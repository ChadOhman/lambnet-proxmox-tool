"""
Ghost CMS upgrade automation.

Checks the npm registry for new Ghost releases, takes a Proxmox snapshot or
vzdump backup of the app guest, then runs 'ghost update' via SSH.
"""

import json
import logging
import os.path as _osp
import re
import time
from datetime import datetime
from urllib.request import Request, urlopen

from models import Guest, Setting
from proxmox_api import ProxmoxClient
from ssh_client import SSHClient

# Shared shell-safety and output helpers from the Mastodon module
from mastodon import _log_cmd_output, _validate_shell_param, _version_gt

logger = logging.getLogger(__name__)

_GHOST_NPM_URL = "https://registry.npmjs.org/ghost/latest"
_GHOST_RELEASE_BASE = "https://github.com/TryGhost/Ghost/releases/tag/v{version}"


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_ghost_release():
    """Check npm registry for the latest Ghost release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        req = Request(_GHOST_NPM_URL, headers={"User-Agent": "lambnet-proxmox-tool"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        latest = data.get("version", "")
        if not latest:
            return False, "", ""

        release_url = _GHOST_RELEASE_BASE.format(version=latest)

        Setting.set("ghost_latest_version", latest)
        Setting.set("ghost_latest_release_url", release_url)

        current = Setting.get("ghost_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("ghost_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check Ghost releases: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Proxmox protection helpers (Ghost-specific snapshot/backup names)
# ---------------------------------------------------------------------------

def _snapshot_ghost_guest(guest):
    """Create a Proxmox snapshot of a guest before Ghost upgrade.

    Returns (success, message).
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapname = f"pre-ghost-{timestamp}"
    description = f"Auto-snapshot before Ghost upgrade at {timestamp}"

    return client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)


def _backup_ghost_guest(guest, storage, mode="snapshot"):
    """Create a vzdump backup of a guest before Ghost upgrade. Polls until complete.

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
    notes = f"pre-ghost-{timestamp}"

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

def _get_ghost_config():
    """Read all Ghost-related settings."""
    return {
        "guest_id": Setting.get("ghost_guest_id", ""),
        "user": Setting.get("ghost_user", "ghost_user"),
        "ghost_dir": Setting.get("ghost_dir", "/opt/ghost"),
        "current_version": Setting.get("ghost_current_version", ""),
        "latest_version": Setting.get("ghost_latest_version", ""),
        "protection_type": Setting.get("ghost_protection_type", "snapshot"),
        "backup_storage": Setting.get("ghost_backup_storage", ""),
        "backup_mode": Setting.get("ghost_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("ghost_auto_upgrade", "false") == "true",
    }


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_ghost_version(guest, ghost_dir, user="ghost"):
    """Detect the installed Ghost version via SSH.

    Commands run as *user* (via su -) so that Node.js installed under that
    user's profile (nvm, n, system package) is on PATH.

    Returns (version_string, None) on success, or (None, error_message) on failure.
    """
    from models import Credential

    try:
        _validate_shell_param(ghost_dir, "Ghost dir")
        _validate_shell_param(user, "Ghost user")
    except ValueError as e:
        return None, str(e)

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the Ghost guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Pre-check: verify the configured directory exists.
            # If it doesn't, scan for .ghost-cli files to help the user find the right path.
            stdout, stderr, code = ssh.execute_sudo(
                f"test -d {ghost_dir} && echo ok", timeout=10
            )
            if not (code == 0 and "ok" in (stdout or "")):
                found = ""
                scan_out, _, scan_code = ssh.execute_sudo(
                    "find /var /home /opt /srv -maxdepth 5 -name '.ghost-cli' 2>/dev/null | head -5",
                    timeout=15,
                )
                if scan_code == 0 and scan_out.strip():
                    paths = [
                        _osp.dirname(p.strip())
                        for p in scan_out.strip().splitlines()
                        if p.strip()
                    ]
                    found = f" Found Ghost install(s) at: {', '.join(paths)}"
                return None, f"Directory '{ghost_dir}' does not exist on the guest.{found}"

            # Method 1: read .ghost-cli metadata file — ghost-cli always writes this,
            # no Node.js required.  Contains {"active-version": "5.82.0", ...}
            stdout, stderr, code = ssh.execute_sudo(
                f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
            )
            if code == 0 and stdout.strip():
                m = re.search(r'"active-version"\s*:\s*"([^"]+)"', stdout)
                if m:
                    return m.group(1), None

            ghost_cli_err = (stderr or "").strip()

            # Method 2: ghost version (not --version) run from install dir as ghost user.
            # Outputs "Ghost version: X.Y.Z" among other lines.
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {ghost_dir} && ghost version 2>/dev/null'",
                timeout=20,
            )
            if code == 0 and stdout.strip():
                m = re.search(r'Ghost version:\s*(\S+)', stdout)
                if m:
                    return m.group(1), None

            ghost_ver_err = (stderr or stdout or "").strip()

            # Method 3: read current/package.json via python3 (avoids Node PATH issues)
            py_cmd = (
                f"python3 -c \"import json; "
                f"print(json.load(open('{ghost_dir}/current/package.json'))['version'])\" 2>/dev/null"
            )
            stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    return v, None

            py_err = (stderr or stdout or "").strip()

            errors = "; ".join(filter(None, [
                f".ghost-cli: {ghost_cli_err[:100]}" if ghost_cli_err else None,
                f"ghost version: {ghost_ver_err[:100]}" if ghost_ver_err else None,
                f"package.json: {py_err[:100]}" if py_err else None,
            ]))
            return None, f"All detection methods failed — {errors}" if errors else "All detection methods returned no output"

    except Exception as e:
        logger.warning("Could not detect Ghost version: %s", e)
        return None, str(e)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_ghost_preflight(log_callback=None):
    """Run read-only pre-flight checks before Ghost upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity, Ghost
    installation, Node.js availability, and service status.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_ghost_config()
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

    log("=== Ghost Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    for field, label in [
        ("guest_id", "Ghost guest"),
        ("user", "Ghost user"),
        ("ghost_dir", "Ghost directory"),
    ]:
        val = config.get(field, "")
        if val:
            check(f"{label} configured", True)
        else:
            check(f"{label} configured", False, "not set in settings")
            config_ok = False

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")
    if protection_type == "backup":
        if backup_storage:
            check("Backup storage configured", True)
        else:
            check("Backup storage configured", False, "backup protection selected but no storage configured")
            config_ok = False

    user = config.get("user", "ghost")
    ghost_dir = config.get("ghost_dir", "/var/www/ghost")

    try:
        _validate_shell_param(user, "Ghost user")
        _validate_shell_param(ghost_dir, "Ghost dir")
        check("Shell-safe config values", True)
    except ValueError as e:
        check("Shell-safe config values", False, str(e))
        config_ok = False

    if not config_ok:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
        return False, "\n".join(log_lines)

    # ── B. Proxmox guest status ───────────────────────────────────────────────
    log("")
    log("--- B. Proxmox guest ---")

    ghost_guest = Guest.query.get(int(config["guest_id"]))
    check("Ghost guest in database", ghost_guest is not None,
          f"guest ID {config['guest_id']} not found")

    if not ghost_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
        return False, "\n".join(log_lines)

    if ghost_guest.proxmox_host:
        try:
            client = ProxmoxClient(ghost_guest.proxmox_host)
            node = client.find_guest_node(ghost_guest.vmid)
            if not node:
                check(f"{ghost_guest.name} found on Proxmox", False, "not found on any PVE node")
            else:
                check(f"{ghost_guest.name} found on Proxmox", True)
                status = client.get_guest_status(node, ghost_guest.vmid, ghost_guest.guest_type)
                check(f"{ghost_guest.name} running", status == "running",
                      f"current status: {status}")
                if protection_type == "snapshot":
                    supports_snap = client.guest_supports_snapshot(
                        node, ghost_guest.vmid, ghost_guest.guest_type
                    )
                    check(f"{ghost_guest.name} supports snapshots", supports_snap,
                          "storage does not support snapshots — switch to Backup protection")
        except Exception as e:
            check(f"{ghost_guest.name} Proxmox reachable", False, str(e))
    else:
        log(f"  [WARN] {ghost_guest.name} has no Proxmox host configured — skipping Proxmox checks")

    # ── C. SSH checks ─────────────────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {ghost_guest.name} ---")

    credential = ghost_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for ghost guest or as default")
    elif not ghost_guest.ip_address:
        check("SSH credential available", True)
        check("Ghost guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Ghost guest IP configured", True)
        try:
            with SSHClient.from_credential(ghost_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                # Ghost directory exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"test -d {ghost_dir} && echo ok", timeout=10
                )
                check(f"Ghost directory {ghost_dir} exists",
                      code == 0 and "ok" in (stdout or ""),
                      "directory not found")

                # Ghost CLI available (try PATH first, then node_modules/.bin)
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -c 'which ghost 2>/dev/null && echo ok || "
                    f"(test -x {ghost_dir}/node_modules/.bin/ghost && echo ok)'",
                    timeout=10,
                )
                ghost_cli_ok = code == 0 and "ok" in (stdout or "")
                check("Ghost CLI available", ghost_cli_ok,
                      f"ghost command not found — check Ghost CLI installation in {ghost_dir}")

                # Node.js version (informational)
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -c 'node --version 2>/dev/null'", timeout=10
                )
                if code == 0 and stdout.strip():
                    m = re.search(r'v?(\d+\.\d+\.\d+)', stdout.strip())
                    node_ver = m.group(1) if m else stdout.strip()
                    log(f"  [INFO] Node.js {node_ver} installed")
                else:
                    log("  [WARN] Could not determine Node.js version")

                # Current Ghost version (informational) — read .ghost-cli metadata
                stdout, stderr, code = ssh.execute_sudo(
                    f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
                )
                if code == 0 and stdout.strip():
                    m = re.search(r'"active-version"\s*:\s*"([^"]+)"', stdout)
                    if m:
                        log(f"  [INFO] Ghost current version: {m.group(1)}")
                    else:
                        log("  [WARN] .ghost-cli exists but active-version not found")
                else:
                    log(f"  [WARN] Could not read {ghost_dir}/.ghost-cli"
                        + (f" — {(stderr or '').strip()}" if stderr else ""))

                # File permissions (informational) — ghost-cli rejects files
                # outside versions/ that have wrong modes.
                stdout, stderr, code = ssh.execute_sudo(
                    f"find {ghost_dir} ! -path '*/versions/*' -type f ! -perm 664 "
                    f"2>/dev/null | head -5",
                    timeout=20,
                )
                bad_files = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
                if bad_files:
                    log(f"  [WARN] {len(bad_files)}+ file(s) with non-664 permissions "
                        f"(will be fixed during upgrade)")
                else:
                    log("  [INFO] File permissions look correct")

                # Service status (informational)
                dir_basename = _osp.basename(ghost_dir.rstrip("/"))
                service_name = f"ghost_{dir_basename}"
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {service_name} 2>/dev/null", timeout=10
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log(f"  [INFO] Ghost service ({service_name}) is active")
                elif service_status:
                    log(f"  [WARN] Ghost service ({service_name}) status: {service_status}")
                else:
                    log("  [WARN] Could not determine Ghost service status")

        except Exception as e:
            check("SSH connection established", False, str(e))

    all_pass = checks_failed == 0
    log("")
    if all_pass:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — all clear ===")
    else:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
    return all_pass, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def run_ghost_upgrade(log_callback=None, skip_protection=False):
    """Run the Ghost upgrade via SSH using ghost-cli.

    Steps:
    1. Snapshot or backup the guest.
    2. SSH: su - {user} -c 'cd {ghost_dir} && ghost update'
    3. Verify the Ghost service is running.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_ghost_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Ghost guest not configured"

    ghost_guest = Guest.query.get(int(config["guest_id"]))
    if not ghost_guest:
        return False, "Ghost guest not found"

    user = config["user"]
    ghost_dir = config["ghost_dir"]

    try:
        _validate_shell_param(user, "Ghost user")
        _validate_shell_param(ghost_dir, "Ghost dir")
    except ValueError as e:
        return False, str(e)

    credential = ghost_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for Ghost guest"
    if not ghost_guest.ip_address:
        return False, "No IP address configured for Ghost guest"

    # --- Step 1: Protection ---
    if skip_protection:
        log("=== Step 1: Skipping snapshot/backup (requested by super-admin) ===")
    else:
        protection_type = config.get("protection_type", "snapshot")
        backup_storage = config.get("backup_storage", "")

        if protection_type == "backup" and not backup_storage:
            return False, "Backup protection selected but no backup storage is configured"

        if protection_type == "backup":
            backup_mode = config.get("backup_mode", "snapshot")
            log(f"=== Step 1: Creating vzdump backup to storage '{backup_storage}' "
                f"(mode: {backup_mode}) ===")
            log("(This may take several minutes — please be patient)")
            ok, msg = _backup_ghost_guest(ghost_guest, backup_storage, mode=backup_mode)
            log(f"Backup {ghost_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)
        else:
            log(f"=== Step 1: Creating Proxmox snapshot of {ghost_guest.name} ===")
            ok, msg = _snapshot_ghost_guest(ghost_guest)
            log(f"Snapshot {ghost_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)

    log("")

    # --- Step 2: Ghost update via SSH ---
    log("=== Step 2: Running ghost update ===")

    try:
        with SSHClient.from_credential(ghost_guest.ip_address, credential) as ssh:
            # Detect the real service name from .ghost-cli.  ghost-cli names services
            # after the site hostname (e.g. ghost_news-mstdn-ca), not the directory.
            service_name = f"ghost_{_osp.basename(ghost_dir.rstrip('/'))}"  # fallback
            ghost_cli_raw, _, cli_rc = ssh.execute_sudo(
                f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
            )
            if cli_rc == 0 and ghost_cli_raw.strip():
                m_name = re.search(r'"name"\s*:\s*"([^"]+)"', ghost_cli_raw)
                if m_name and re.match(r"^[a-zA-Z0-9_-]+$", m_name.group(1)):
                    service_name = f"ghost_{m_name.group(1)}"
            log(f"Ghost service name: {service_name}")

            # Write/refresh the sudoers entry for ghost_user.  ghost-cli uses
            # 'sudo systemctl ...' to manage the service; without NOPASSWD entries
            # sudo prompts for a password, ghost-cli detects it and calls prompt(),
            # which throws in non-TTY mode.  Always overwrite so the entry stays
            # current if new systemctl sub-commands are required by updated ghost-cli.
            sudoers_path = f"/etc/sudoers.d/ghost-{service_name}"
            sc_out, _, _ = ssh.execute_sudo(
                "command -v systemctl 2>/dev/null || echo /usr/bin/systemctl",
                timeout=5,
            )
            systemctl = (sc_out or "").strip() or "/usr/bin/systemctl"
            sudoers_lines = [
                "# Managed by lambnet-proxmox-tool",
            ] + [
                f"{user} ALL=(root) NOPASSWD: {systemctl} {action} {service_name}"
                for action in ("start", "stop", "restart", "reset-failed",
                               "is-active", "is-enabled", "enable", "disable")
            ] + [
                f"{user} ALL=(root) NOPASSWD: {systemctl} daemon-reload",
            ]
            write_parts = [
                f"echo '{line}' {'>' if i == 0 else '>>'} {sudoers_path}"
                for i, line in enumerate(sudoers_lines)
            ] + [f"chmod 440 {sudoers_path}"]
            _, w_err, w_code = ssh.execute_sudo(" && ".join(write_parts), timeout=15)
            if w_code == 0:
                log(f"Sudoers entry written: {sudoers_path}")
            else:
                log(f"WARNING: Could not write sudoers: {(w_err or '').strip()}")
            log("")

            # Update ghost-cli itself first so it doesn't try to interactively prompt
            # about running an outdated version (which throws in non-TTY SSH sessions).
            log("Updating ghost-cli to latest version...")
            cli_cmd = "npm install -g ghost-cli@latest 2>&1"
            stdout, stderr, code = ssh.execute_sudo(cli_cmd, timeout=120)
            _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
            if code != 0:
                log("WARNING: ghost-cli update failed — proceeding anyway")
            log("")

            # Fix file/directory permissions before update.  ghost-cli's
            # check-permissions step rejects files with wrong modes (e.g. yarn
            # cache files with executable bits).  Run the same remediation that
            # ghost-cli suggests on failure — but proactively, so the update
            # doesn't abort.
            log("Fixing file permissions...")
            perms_cmds = (
                f"find {ghost_dir} ! -path '*/versions/*' -type f -exec chmod 664 {{}} + "
                f"&& find {ghost_dir} ! -path '*/versions/*' -type d -exec chmod 775 {{}} + "
                f"&& chown -R {user}: {ghost_dir}"
            )
            stdout, stderr, code = ssh.execute_sudo(perms_cmds, timeout=120)
            if code == 0:
                log("File permissions fixed")
            else:
                log(f"WARNING: Permission fix returned exit {code}: "
                    f"{(stderr or stdout or '').strip()[:200]}")
            log("")

            # Run ghost update as the Ghost system user.  su - creates a full login
            # shell so ghost-cli can find Node.js on PATH and interact with systemd.
            # --no-prompt disables interactive confirmations for non-TTY environments.
            update_cmd = f"su - {user} -c 'cd {ghost_dir} && ghost update --no-prompt'"
            log(f"Running: {update_cmd}")
            stdout, stderr, code = ssh.execute_sudo(update_cmd, timeout=600)
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)

            if code != 0:
                log(f"ERROR: ghost update failed (exit {code})")
                return False, "\n".join(log_lines)

            log("ghost update completed successfully")
            log("")

            # --- Step 3: Verify service ---
            log("=== Step 3: Verifying Ghost service ===")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl is-active {service_name} 2>/dev/null", timeout=15
            )
            service_status = (stdout or "").strip()
            if service_status == "active":
                log(f"Ghost service ({service_name}) is active — upgrade successful")
            else:
                log(f"Ghost service ({service_name}) is {service_status or 'unknown'} "
                    f"— attempting to start...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl start {service_name} 2>&1", timeout=30
                )
                if (stdout or "").strip():
                    log((stdout or "").strip())
                # Re-check
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {service_name} 2>/dev/null", timeout=15
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log(f"Ghost service ({service_name}) started successfully.")
                else:
                    log(f"WARNING: Ghost service ({service_name}) is still "
                        f"{service_status or 'unknown'} after start attempt.")
                    # Show recent journal entries to aid diagnosis
                    stdout, _, _ = ssh.execute_sudo(
                        f"journalctl -u {service_name} -n 20 --no-pager 2>/dev/null",
                        timeout=15,
                    )
                    if (stdout or "").strip():
                        log("--- Recent service journal ---")
                        log((stdout or "").strip())

            # Detect and persist new version via .ghost-cli metadata
            stdout, stderr, code = ssh.execute_sudo(
                f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
            )
            if code == 0 and stdout.strip():
                m = re.search(r'"active-version"\s*:\s*"([^"]+)"', stdout)
                if m:
                    Setting.set("ghost_current_version", m.group(1))
                    log(f"Updated Ghost version: {m.group(1)}")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        return False, "\n".join(log_lines)

    log("")
    log("=== Ghost upgrade complete ===")
    return True, "\n".join(log_lines)
