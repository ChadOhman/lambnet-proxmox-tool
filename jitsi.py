"""
Jitsi Meet install and upgrade automation.

Installs Jitsi Meet via apt packages with debconf preseeding for non-interactive
setup, or upgrades existing installations via targeted apt upgrade.  Takes a
Proxmox snapshot or vzdump backup of the guest before any changes.
"""

import logging
import re
import time
from datetime import datetime

from models import Guest, Setting
from proxmox_api import ProxmoxClient
from ssh_client import SSHClient

# Shared shell-safety and output helpers from the Mastodon module
from mastodon import _log_cmd_output, _validate_shell_param, _version_gt

logger = logging.getLogger(__name__)

# Jitsi services that must be running for a healthy installation
_JITSI_SERVICES = ["jitsi-videobridge2", "jicofo", "prosody"]

# Packages to upgrade during a targeted apt upgrade
_JITSI_APT_PACKAGES = [
    "jitsi-meet",
    "jitsi-videobridge2",
    "jicofo",
    "jitsi-meet-web",
    "jitsi-meet-prosody",
    "jitsi-meet-web-config",
]

# Hostname validation: FQDN pattern (letters, digits, hyphens, dots)
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

# Email validation: basic pattern for Let's Encrypt email
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


# ---------------------------------------------------------------------------
# Version check (via apt on the target guest)
# ---------------------------------------------------------------------------

def check_jitsi_release():
    """Check the Jitsi apt repository for the latest available version.

    Unlike other apps that query GitHub, Jitsi versions come from the apt
    repo on the target guest.  Requires the guest to be configured and
    reachable via SSH.

    Returns (update_available, latest_version, release_url).
    """
    from models import Credential

    config = _get_jitsi_config()
    guest_id = config.get("guest_id", "")
    if not guest_id:
        logger.debug("Jitsi guest not configured, skipping release check")
        return False, "", ""

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        return False, "", ""
    if not guest:
        return False, "", ""

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    stdout = None
    has_usable_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")

    # Try SSH first
    if has_usable_ip and credential:
        try:
            with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                ssh.execute_sudo("apt-get update -qq 2>/dev/null", timeout=120)
                stdout, stderr, code = ssh.execute_sudo(
                    "apt-cache policy jitsi-meet 2>/dev/null", timeout=15
                )
                if code != 0:
                    stdout = None
        except Exception as e:
            logger.debug("SSH failed for Jitsi release check: %s", e)

    # Fall back to guest agent
    if stdout is None and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq", timeout=120)
                stdout, err = client.exec_guest_agent(
                    node, guest.vmid, "apt-cache policy jitsi-meet", timeout=15
                )
                if err:
                    logger.debug("Guest agent apt-cache failed: %s", err)
                    stdout = None
        except Exception as e:
            logger.debug("Guest agent failed for Jitsi release check: %s", e)

    if not stdout:
        logger.error("Failed to check Jitsi releases: no reachable connection to guest %s", guest.name)
        return False, "", ""

    try:
        # Parse "Candidate: X.Y.Z-N" from output
        candidate = ""
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Candidate:"):
                candidate = line.split(":", 1)[1].strip()
                break

        if not candidate or candidate == "(none)":
            return False, "", ""

        # Strip Debian revision suffix (e.g., "2.0.9457-1" -> "2.0.9457")
        latest = re.sub(r'-\d+$', '', candidate)

        Setting.set("jitsi_latest_version", latest)

        current = Setting.get("jitsi_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("jitsi_update_available", "true" if update_available else "false")

        return update_available, latest, ""

    except Exception as e:
        logger.error("Failed to parse Jitsi version: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Proxmox protection helpers
# ---------------------------------------------------------------------------

def _snapshot_jitsi_guest(guest):
    """Create a Proxmox snapshot of a guest before Jitsi install/upgrade.

    Polls until the snapshot task completes (up to 5 minutes).
    Returns (success, message).
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapname = f"pre-jitsi-{timestamp}"
    description = f"Auto-snapshot before Jitsi install/upgrade at {timestamp}"

    ok, upid = client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)
    if not ok:
        return False, f"Failed to start snapshot: {upid}"

    # Poll until snapshot completes
    deadline = time.time() + 300  # 5 minutes
    while time.time() < deadline:
        time.sleep(2)
        try:
            status = client.get_task_status(node, upid)
            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status == "OK":
                    return True, f"Snapshot {snapname} of '{guest.name}' completed"
                return False, f"Snapshot task failed: {exit_status}"
        except Exception as e:
            logger.debug("Error polling snapshot task for %s: %s", guest.name, e)

    return False, "Snapshot timed out after 5 minutes"


def _backup_jitsi_guest(guest, storage, mode="snapshot"):
    """Create a vzdump backup of a guest before Jitsi install/upgrade. Polls until complete.

    mode: "snapshot" (live, no downtime), "suspend" (brief pause), "stop" (shut down).
    Returns (success, message).
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    notes = f"pre-jitsi-{timestamp}"

    ok, upid = client.create_backup(node, guest.vmid, storage, mode=mode, notes=notes)
    if not ok:
        return False, f"Failed to start backup: {upid}"

    timeout = 1800  # 30 minutes
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(5)
        try:
            status = client.get_task_status(node, upid)
            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status == "OK":
                    return True, f"Backup of '{guest.name}' to '{storage}' completed"
                return False, f"Backup task failed: {exit_status}"
        except Exception as e:
            logger.debug("Error polling backup task for %s: %s", guest.name, e)

    return False, f"Backup of '{guest.name}' timed out after {timeout // 60} minutes"


# ---------------------------------------------------------------------------
# Internal config helper
# ---------------------------------------------------------------------------

def _get_jitsi_config():
    """Read all Jitsi-related settings."""
    return {
        "guest_id": Setting.get("jitsi_guest_id", ""),
        "hostname": Setting.get("jitsi_hostname", ""),
        "cert_type": Setting.get("jitsi_cert_type", "self-signed"),
        "letsencrypt_email": Setting.get("jitsi_letsencrypt_email", ""),
        "url": Setting.get("jitsi_url", ""),
        "current_version": Setting.get("jitsi_current_version", ""),
        "latest_version": Setting.get("jitsi_latest_version", ""),
        "protection_type": Setting.get("jitsi_protection_type", "snapshot"),
        "backup_storage": Setting.get("jitsi_backup_storage", ""),
        "backup_mode": Setting.get("jitsi_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("jitsi_auto_upgrade", "false") == "true",
        "installed": Setting.get("jitsi_installed", "false") == "true",
    }


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_jitsi_version(guest):
    """Detect the installed Jitsi Meet version via SSH.

    Reads the version from dpkg package info.

    Returns (version_string, None) on success, or (None, error_message) on failure.
    """
    from models import Credential

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the Jitsi guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Read version from dpkg
            stdout, stderr, code = ssh.execute_sudo(
                "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
            )
            if code == 0 and stdout and stdout.strip():
                # Parse "Version: 2.0.9457-1" -> "2.0.9457"
                version_line = stdout.strip().splitlines()[0]
                version = version_line.replace("Version:", "").strip()
                # Strip Debian revision suffix
                version = re.sub(r'-\d+$', '', version)
                if version:
                    return version, None

            return None, "jitsi-meet package not found or version could not be determined"

    except Exception as e:
        logger.warning("Could not detect Jitsi version: %s", e)
        return None, str(e)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_jitsi_preflight(log_callback=None):
    """Run read-only pre-flight checks before Jitsi install or upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity,
    and Jitsi-specific prerequisites.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []
    checks_passed = 0
    checks_total = 0
    checks_failed = 0

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    def check(label, passed, fail_msg=None):
        nonlocal checks_passed, checks_total, checks_failed
        checks_total += 1
        if passed:
            checks_passed += 1
            log(f"  [PASS] {label}")
        else:
            checks_failed += 1
            msg = f"  [FAIL] {label}"
            if fail_msg:
                msg += f" — {fail_msg}"
            log(msg)

    log("=== Jitsi Meet Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    guest_id = config.get("guest_id", "")
    if guest_id:
        check("Jitsi guest configured", True)
    else:
        check("Jitsi guest configured", False, "not set in settings")
        config_ok = False

    hostname = config.get("hostname", "")
    if hostname:
        check("Hostname configured", True)
        if _HOSTNAME_RE.match(hostname):
            check("Hostname format valid", True)
        else:
            check("Hostname format valid", False, f"'{hostname}' is not a valid FQDN")
            config_ok = False
    else:
        check("Hostname configured", False, "not set in settings")
        config_ok = False

    cert_type = config.get("cert_type", "self-signed")
    if cert_type in ("letsencrypt", "self-signed", "custom"):
        check(f"Certificate type valid ({cert_type})", True)
    else:
        check("Certificate type valid", False, f"unknown type: {cert_type}")
        config_ok = False

    if cert_type == "letsencrypt":
        email = config.get("letsencrypt_email", "")
        if email:
            if _EMAIL_RE.match(email):
                check("Let's Encrypt email configured", True)
            else:
                check("Let's Encrypt email configured", False, f"'{email}' is not a valid email")
                config_ok = False
        else:
            check("Let's Encrypt email configured", False,
                  "Let's Encrypt selected but no email provided")
            config_ok = False

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")
    if protection_type == "backup":
        if backup_storage:
            check("Backup storage configured", True)
        else:
            check("Backup storage configured", False,
                  "backup protection selected but no storage configured")
            config_ok = False

    try:
        _validate_shell_param(hostname, "Hostname")
        if cert_type == "letsencrypt":
            _validate_shell_param(config.get("letsencrypt_email", ""), "Email")
        check("Shell-safe config values", True)
    except ValueError as e:
        check("Shell-safe config values", False, str(e))
        config_ok = False

    if not config_ok:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
        return False, "\n".join(log_lines)

    # ── B. Proxmox guest status ───────────────────────────────────────────────
    log("")
    log("--- B. Proxmox guests ---")

    app_guest = Guest.query.get(int(config["guest_id"]))
    check("Jitsi guest in database", app_guest is not None,
          f"guest ID {config['guest_id']} not found")

    if not app_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
        return False, "\n".join(log_lines)

    if app_guest.proxmox_host:
        try:
            client = ProxmoxClient(app_guest.proxmox_host)
            node = client.find_guest_node(app_guest.vmid)
            if not node:
                check(f"{app_guest.name} found on Proxmox", False, "not found on any PVE node")
            else:
                check(f"{app_guest.name} found on Proxmox", True)
                status = client.get_guest_status(node, app_guest.vmid, app_guest.guest_type)
                check(f"{app_guest.name} running", status == "running",
                      f"current status: {status}")
                if protection_type == "snapshot":
                    supports_snap = client.guest_supports_snapshot(
                        node, app_guest.vmid, app_guest.guest_type
                    )
                    check(f"{app_guest.name} supports snapshots", supports_snap,
                          "storage does not support snapshots — switch to Backup protection")
        except Exception as e:
            check(f"{app_guest.name} Proxmox reachable", False, str(e))
    else:
        log(f"  [WARN] {app_guest.name} has no Proxmox host configured — skipping Proxmox checks")

    # ── C. SSH checks on guest ────────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {app_guest.name} ---")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for Jitsi guest or as default")
    elif not app_guest.ip_address:
        check("SSH credential available", True)
        check("Jitsi guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Jitsi guest IP configured", True)
        try:
            with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                installed = config.get("installed", False)

                if installed:
                    # Upgrade pre-flight: verify jitsi-meet is installed
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jitsi-meet 2>/dev/null | grep '^Status:.*installed'",
                        timeout=10
                    )
                    check("jitsi-meet package installed",
                          code == 0 and "installed" in (stdout or ""),
                          "jitsi-meet package not found")

                    # Check apt repos configured
                    stdout, stderr, code = ssh.execute_sudo(
                        "test -f /etc/apt/sources.list.d/jitsi-stable.list && echo ok",
                        timeout=10
                    )
                    check("Jitsi apt repository configured",
                          code == 0 and "ok" in (stdout or ""),
                          "/etc/apt/sources.list.d/jitsi-stable.list not found")

                    # Check services status
                    for svc in _JITSI_SERVICES:
                        stdout, stderr, code = ssh.execute_sudo(
                            f"systemctl is-active {svc} 2>/dev/null", timeout=10
                        )
                        svc_status = (stdout or "").strip()
                        if svc_status == "active":
                            log(f"  [INFO] {svc} is active")
                        elif svc_status:
                            log(f"  [WARN] {svc} status: {svc_status}")
                        else:
                            log(f"  [WARN] Could not determine {svc} status")

                    # Current version (informational)
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
                    )
                    if code == 0 and stdout and stdout.strip():
                        log(f"  [INFO] {stdout.strip()}")

                else:
                    # Install pre-flight: verify jitsi-meet NOT already installed
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jitsi-meet 2>/dev/null | grep '^Status:.*installed'",
                        timeout=10
                    )
                    if code == 0 and "installed" in (stdout or ""):
                        check("Jitsi not yet installed", False,
                              "jitsi-meet is already installed — use upgrade instead")
                    else:
                        check("Jitsi not yet installed", True)

                    # Check hostname resolves (informational)
                    stdout, stderr, code = ssh.execute_sudo(
                        f"host {hostname} 2>/dev/null || dig +short {hostname} 2>/dev/null",
                        timeout=10
                    )
                    if code == 0 and stdout and stdout.strip():
                        log(f"  [INFO] Hostname {hostname} resolves")
                    else:
                        log(f"  [WARN] Hostname {hostname} may not resolve — "
                            "ensure DNS is configured before install")

                    # Check if OS is Debian/Ubuntu
                    stdout, stderr, code = ssh.execute_sudo(
                        "lsb_release -si 2>/dev/null", timeout=10
                    )
                    distro = (stdout or "").strip()
                    if distro in ("Debian", "Ubuntu"):
                        check(f"OS is {distro}", True)
                    elif distro:
                        check("OS is Debian/Ubuntu", False,
                              f"detected {distro} — Jitsi requires Debian or Ubuntu")
                    else:
                        log("  [WARN] Could not determine OS distribution")

        except Exception as e:
            check("SSH connection established", False, str(e))

    all_pass = checks_failed == 0
    log("")
    if all_pass:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — all clear ===")
    else:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
    return all_pass, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Protection helper (shared by install and upgrade)
# ---------------------------------------------------------------------------

def _run_protection(config, app_guest, log, skip_protection=False):
    """Run snapshot or backup protection on the Jitsi guest.

    Returns True on success, False on failure.
    """
    if skip_protection:
        log("=== Step 1: Skipping snapshot/backup (requested by super-admin) ===")
        return True

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")

    if protection_type == "backup" and not backup_storage:
        log("ERROR: Backup protection selected but no backup storage is configured")
        return False

    if protection_type == "backup":
        backup_mode = config.get("backup_mode", "snapshot")
        log(f"=== Step 1: Creating vzdump backup to storage '{backup_storage}' "
            f"(mode: {backup_mode}) ===")
        log("(This may take several minutes — please be patient)")
        ok, msg = _backup_jitsi_guest(app_guest, backup_storage, mode=backup_mode)
        log(f"Backup {app_guest.name}: {msg}")
        if not ok:
            return False
    else:
        log("=== Step 1: Creating Proxmox snapshot ===")
        ok, msg = _snapshot_jitsi_guest(app_guest)
        log(f"Snapshot {app_guest.name}: {msg}")
        if not ok:
            return False

    log("")
    return True


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def run_jitsi_install(log_callback=None):
    """Install Jitsi Meet on the configured guest via apt.

    Steps:
    1. Snapshot or backup the guest.
    2. Add Jitsi apt repository.
    3. Update apt cache.
    4. Preseed debconf with hostname and certificate choice.
    5. Install jitsi-meet package (non-interactive).
    6. If Let's Encrypt: run certificate setup script.
    7. Configure UFW firewall (if active).
    8. Verify all Jitsi services are running.
    9. Detect and persist the installed version.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Jitsi guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jitsi guest not found"

    hostname = config["hostname"]
    cert_type = config["cert_type"]
    letsencrypt_email = config.get("letsencrypt_email", "")

    if not hostname:
        return False, "Jitsi hostname not configured"

    try:
        _validate_shell_param(hostname, "Hostname")
        if cert_type == "letsencrypt" and letsencrypt_email:
            _validate_shell_param(letsencrypt_email, "Email")
    except ValueError as e:
        return False, str(e)

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jitsi guest has no IP address"

    log("=== Jitsi Meet Installation ===")
    log(f"Guest: {app_guest.name} ({app_guest.ip_address})")
    log(f"Hostname: {hostname}")
    log(f"Certificate: {cert_type}")
    log("")

    # Step 1: Protection
    if not _run_protection(config, app_guest, log):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Note: We do NOT add the Prosody community repo (packages.prosody.im).
            # Ubuntu Noble ships Prosody 0.12.x which satisfies Jitsi's dependency
            # and works with Lua 5.1.  The community repo's Prosody 13.x is built
            # against Lua 5.1 but no longer supports it, causing startup failures.
            # Remove it if a previous attempt added it.
            ssh.execute_sudo(
                "rm -f /etc/apt/sources.list.d/prosody.list "
                "/etc/apt/keyrings/prosody-keyring.gpg 2>/dev/null",
                timeout=10
            )

            # Step 2: Add Jitsi apt repository
            log("=== Step 2: Adding Jitsi apt repository ===")

            stdout, stderr, code = ssh.execute_sudo(
                "curl -fsSL https://download.jitsi.org/jitsi-key.gpg.key "
                "| gpg --dearmor -o /etc/apt/keyrings/jitsi-keyring.gpg --yes 2>&1",
                timeout=30
            )
            if code != 0:
                log(f"WARNING: Could not add Jitsi keyring (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
            else:
                log("Jitsi keyring added")

            stdout, stderr, code = ssh.execute_sudo(
                'echo "deb [signed-by=/etc/apt/keyrings/jitsi-keyring.gpg] '
                'https://download.jitsi.org stable/" '
                "> /etc/apt/sources.list.d/jitsi-stable.list",
                timeout=10
            )
            if code != 0:
                log(f"WARNING: Could not add Jitsi repository (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
            else:
                log("Jitsi repository added")
            log("")

            # Step 3: Update apt cache
            log("=== Step 3: Updating apt cache ===")
            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=120
            )
            if code != 0:
                log(f"ERROR: apt-get update failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            log("apt cache updated")
            log("")

            # Step 4: Preseed debconf
            log("=== Step 4: Preseeding debconf ===")

            # Preseed hostname
            stdout, stderr, code = ssh.execute_sudo(
                f'echo "jitsi-videobridge2 jitsi-videobridge/jvb-hostname string {hostname}" '
                "| debconf-set-selections",
                timeout=10
            )
            if code != 0:
                log(f"ERROR: Failed to preseed hostname (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)

            # Preseed certificate choice
            # The debconf value uses "Generate a new self-signed certificate" for
            # both self-signed and letsencrypt (LE cert is set up post-install).
            if cert_type == "custom":
                cert_preseed = "I want to use my own certificate"
            else:
                cert_preseed = (
                    "Generate a new self-signed certificate "
                    "(oportunity to obtain a Let's Encrypt certificate later)"
                )

            stdout, stderr, code = ssh.execute_sudo(
                'echo "jitsi-meet-web-config jitsi-meet/cert-choice select '
                f'{cert_preseed}" | debconf-set-selections',
                timeout=10
            )

            if code != 0:
                log(f"WARNING: debconf preseed for certificate may have failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
            else:
                log(f"debconf preseeded: hostname={hostname}, cert={cert_type}")
            log("")

            # Step 5: Install jitsi-meet
            log("=== Step 5: Installing jitsi-meet package ===")
            log("(This may take several minutes...)")
            # Force-purge any broken/incompatible Prosody from a previous failed
            # install (e.g. 13.x from the community repo with Lua 5.1 issues).
            # --force-remove-reinstreq handles packages stuck in a broken dpkg state.
            ssh.execute_sudo(
                "dpkg --force-remove-reinstreq --purge prosody 2>&1 || true",
                timeout=60
            )
            ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get -f install -y 2>&1 || true",
                timeout=120
            )
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y jitsi-meet 2>&1",
                timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
            if code != 0:
                log(f"ERROR: jitsi-meet installation failed (exit {code})")
                return False, "\n".join(log_lines)
            log("jitsi-meet package installed successfully")
            log("")

            # Step 6: Let's Encrypt certificate (if requested)
            if cert_type == "letsencrypt":
                log("=== Step 6: Setting up Let's Encrypt certificate ===")
                if letsencrypt_email:
                    le_cmd = (
                        f"echo '{letsencrypt_email}' | "
                        "/usr/share/jitsi-meet/scripts/install-letsencrypt-cert.sh 2>&1"
                    )
                else:
                    le_cmd = "/usr/share/jitsi-meet/scripts/install-letsencrypt-cert.sh 2>&1"

                stdout, stderr, code = ssh.execute_sudo(le_cmd, timeout=120)
                _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
                if code != 0:
                    log(f"WARNING: Let's Encrypt setup returned exit code {code}")
                    log("You may need to run the certificate script manually")
                else:
                    log("Let's Encrypt certificate installed successfully")
                log("")
            else:
                log("=== Step 6: Skipping Let's Encrypt (not selected) ===")
                log("")

            # Step 7: Configure UFW firewall
            log("=== Step 7: Configuring firewall ===")
            stdout, stderr, code = ssh.execute_sudo(
                "ufw status 2>/dev/null | head -1", timeout=10
            )
            ufw_active = code == 0 and "active" in (stdout or "").lower()

            if ufw_active:
                for rule in ["80/tcp", "443/tcp", "10000/udp", "5349/tcp"]:
                    stdout, stderr, code = ssh.execute_sudo(
                        f"ufw allow {rule} 2>&1", timeout=10
                    )
                    if code == 0:
                        log(f"  UFW: allowed {rule}")
                    else:
                        log(f"  WARNING: Could not add UFW rule for {rule}")
            else:
                log("  UFW not active — skipping firewall configuration")
                log("  Ensure ports 80/tcp, 443/tcp, 10000/udp, 5349/tcp are open")
            log("")

            # Step 8: Verify services
            log("=== Step 8: Verifying Jitsi services ===")
            all_active = True
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                svc_status = (stdout or "").strip()
                if svc_status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  {svc}: {svc_status or 'unknown'}")
                    # Try to start it
                    ssh.execute_sudo(f"systemctl start {svc} 2>&1", timeout=30)
                    stdout2, _, code2 = ssh.execute_sudo(
                        f"systemctl is-active {svc} 2>/dev/null", timeout=10
                    )
                    if code2 == 0 and (stdout2 or "").strip() == "active":
                        log(f"  {svc}: started successfully")
                    else:
                        log(f"  WARNING: {svc} is not active")
                        all_active = False

            if not all_active:
                log("WARNING: Not all services are active — Jitsi may not be fully functional")
            log("")

            # Step 9: Detect and persist version
            log("=== Step 9: Detecting installed version ===")
            stdout, stderr, code = ssh.execute_sudo(
                "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
            )
            if code == 0 and stdout and stdout.strip():
                version_line = stdout.strip().splitlines()[0]
                version = version_line.replace("Version:", "").strip()
                version = re.sub(r'-\d+$', '', version)
                if version:
                    Setting.set("jitsi_current_version", version)
                    Setting.set("jitsi_installed", "true")
                    Setting.set("jitsi_url", f"https://{hostname}")
                    from models import db
                    db.session.commit()
                    log(f"Jitsi Meet v{version} installed successfully")
                else:
                    log("WARNING: Could not parse version from dpkg output")
            else:
                log("WARNING: Could not detect installed version")

            log("")
            log("=== Jitsi Meet installation complete ===")
            return True, "\n".join(log_lines)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def run_jitsi_upgrade(log_callback=None, skip_protection=False):
    """Upgrade Jitsi Meet via targeted apt upgrade.

    Steps:
    1. Snapshot or backup the guest.
    2. Update apt cache.
    3. Upgrade Jitsi packages.
    4. Restart Jitsi services.
    5. Verify services are active.
    6. Detect and persist new version.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Jitsi guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jitsi guest not found"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jitsi guest has no IP address"

    log("=== Jitsi Meet Upgrade ===")
    log(f"Guest: {app_guest.name} ({app_guest.ip_address})")
    log("")

    # Step 1: Protection
    if not _run_protection(config, app_guest, log, skip_protection=skip_protection):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Step 2: Update apt cache
            log("=== Step 2: Updating apt cache ===")
            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=120
            )
            if code != 0:
                log(f"ERROR: apt-get update failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            log("apt cache updated")
            log("")

            # Step 3: Upgrade Jitsi packages
            log("=== Step 3: Upgrading Jitsi packages ===")
            log("(This may take several minutes...)")
            packages = " ".join(_JITSI_APT_PACKAGES)
            stdout, stderr, code = ssh.execute_sudo(
                f"DEBIAN_FRONTEND=noninteractive apt-get upgrade -y {packages} 2>&1",
                timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
            if code != 0:
                log(f"ERROR: Jitsi upgrade failed (exit {code})")
                return False, "\n".join(log_lines)
            log("Jitsi packages upgraded successfully")
            log("")

            # Step 4: Restart services
            log("=== Step 4: Restarting Jitsi services ===")
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {svc} 2>&1", timeout=30
                )
                if code != 0:
                    log(f"  WARNING: {svc} restart returned exit code {code}")
                else:
                    log(f"  {svc} restarted")
            log("")

            # Step 5: Verify services
            log("=== Step 5: Verifying Jitsi services ===")
            # Give services a moment to stabilize
            time.sleep(3)
            all_active = True
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                svc_status = (stdout or "").strip()
                if svc_status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  {svc}: {svc_status or 'unknown'}")
                    all_active = False

            if not all_active:
                log("WARNING: Not all services are active after upgrade")
            log("")

            # Step 6: Detect and persist new version
            log("=== Step 6: Detecting new version ===")
            stdout, stderr, code = ssh.execute_sudo(
                "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
            )
            if code == 0 and stdout and stdout.strip():
                version_line = stdout.strip().splitlines()[0]
                version = version_line.replace("Version:", "").strip()
                version = re.sub(r'-\d+$', '', version)
                if version:
                    Setting.set("jitsi_current_version", version)
                    from models import db
                    db.session.commit()
                    log(f"Jitsi Meet is now at v{version}")
                else:
                    log("WARNING: Could not parse version from dpkg output")
            else:
                log("WARNING: Could not detect installed version after upgrade")

            log("")
            ok = all_active
            if ok:
                log("=== Jitsi Meet upgrade complete ===")
            else:
                log("=== Jitsi Meet upgrade finished with warnings ===")
            return ok, "\n".join(log_lines)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)
