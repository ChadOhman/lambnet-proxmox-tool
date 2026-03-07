"""
Prometheus exporter install and management automation.

Supports installing node_exporter, postgres_exporter, and redis_exporter
on target guests via SSH, and regenerating the Prometheus scrape config.
"""

import json
import logging
import re
import time
import urllib.request

from apps.utils import _log_cmd_output
from clients.ssh_client import SSHClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known exporter registry
# ---------------------------------------------------------------------------

KNOWN_EXPORTERS = {
    "node_exporter": {
        "display_name": "Node Exporter",
        "github_repo": "prometheus/node_exporter",
        "binary_name": "node_exporter",
        "default_port": 9100,
        "systemd_unit": "node_exporter.service",
        "requires_config": False,
        "job_name": "node",
    },
    "postgres_exporter": {
        "display_name": "PostgreSQL Exporter",
        "github_repo": "prometheus-community/postgres_exporter",
        "binary_name": "postgres_exporter",
        "default_port": 9187,
        "systemd_unit": "postgres_exporter.service",
        "requires_config": True,
        "env_vars": ["DATA_SOURCE_NAME"],
        "job_name": "postgres",
    },
    "redis_exporter": {
        "display_name": "Redis Exporter",
        "github_repo": "oliver006/redis_exporter",
        "binary_name": "redis_exporter",
        "default_port": 9121,
        "systemd_unit": "redis_exporter.service",
        "requires_config": True,
        "env_vars": ["REDIS_ADDR"],
        "job_name": "redis",
        "asset_version_prefix": "v",
    },
}


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_exporter_release(exporter_type):
    """Check GitHub for the latest release of an exporter.

    Returns (latest_version, error_string).
    """
    info = KNOWN_EXPORTERS.get(exporter_type)
    if not info:
        return None, f"Unknown exporter type: {exporter_type}"

    try:
        url = f"https://api.github.com/repos/{info['github_repo']}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "lambnet-proxmox-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
        return latest or None, "" if latest else "No version found"
    except Exception as e:
        logger.error("Failed to check %s releases: %s", exporter_type, e)
        return None, str(e)


def detect_exporter_version(guest, exporter_type):
    """Detect the installed exporter version on a guest via SSH.

    Returns (version_string, error_string).
    """
    from models import Credential

    info = KNOWN_EXPORTERS.get(exporter_type)
    if not info:
        return None, f"Unknown exporter type: {exporter_type}"

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured"

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        return None, "Guest has no usable IP address"

    try:
        binary = info["binary_name"]
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(
                f"/usr/local/bin/{binary} --version 2>&1 | head -1", timeout=10
            )
            if code != 0:
                return None, f"{binary} not found or failed to run"
            match = re.search(r"version\s+([\d.]+)", stdout or "")
            if match:
                return match.group(1), ""
            return None, f"Could not parse version from: {(stdout or '')[:100]}"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Systemd unit generation
# ---------------------------------------------------------------------------

def _generate_exporter_systemd_unit(exporter_type, port, env_file=None):
    """Generate a systemd service unit for an exporter."""
    info = KNOWN_EXPORTERS[exporter_type]
    binary = info["binary_name"]
    user = binary  # user matches binary name

    env_line = ""
    if env_file:
        env_line = f"\nEnvironmentFile={env_file}"

    return f"""[Unit]
Description={info['display_name']}
Documentation=https://prometheus.io/docs/instrumenting/exporters/
Wants=network-online.target
After=network-online.target

[Service]
User={user}
Group={user}
Type=simple{env_line}
ExecStart=/usr/local/bin/{binary} \\
  --web.listen-address=:{port}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------------------
# Install / Uninstall
# ---------------------------------------------------------------------------

def run_exporter_install(instance_id, log_callback=None):
    """Install an exporter on the target guest via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, ExporterInstance, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    instance = ExporterInstance.query.get(instance_id)
    if not instance:
        _log("ERROR: Exporter instance not found.")
        return False, log_lines

    info = KNOWN_EXPORTERS.get(instance.exporter_type)
    if not info:
        _log(f"ERROR: Unknown exporter type: {instance.exporter_type}")
        return False, log_lines

    guest = instance.guest
    if not guest:
        _log("ERROR: Guest not found.")
        return False, log_lines

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this guest.")
        return False, log_lines

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        _log("ERROR: Guest has no usable IP address.")
        return False, log_lines

    # Get latest version
    _log(f"Checking latest {info['display_name']} version...")
    latest, err = check_exporter_release(instance.exporter_type)
    if not latest:
        _log(f"ERROR: Could not determine latest version: {err}")
        return False, log_lines

    binary = info["binary_name"]
    _log(f"Installing {info['display_name']} v{latest} on {guest.name} ({guest.ip_address})...")

    instance.status = "installing"
    db.session.commit()

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Determine architecture
            arch_out, _, _ = ssh.execute_sudo("dpkg --print-architecture", timeout=10)
            arch = (arch_out or "amd64").strip()
            dl_arch = "arm64" if arch == "arm64" else "amd64"

            # Create user
            _log(f"Creating {binary} user...")
            stdout, stderr, code = ssh.execute_sudo(
                f"id {binary} >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false {binary}",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Download and extract
            vprefix = info.get("asset_version_prefix", "")
            dl_url = (
                f"https://github.com/{info['github_repo']}/releases/download/v{latest}/"
                f"{binary}-{vprefix}{latest}.linux-{dl_arch}.tar.gz"
            )
            _log(f"Downloading {info['display_name']} v{latest} ({dl_arch})...")
            dl_cmd = (
                f"cd /tmp && "
                f"(curl -sSL -o {binary}.tar.gz '{dl_url}' 2>/dev/null "
                f"|| wget -q -O {binary}.tar.gz '{dl_url}') && "
                f"tar xzf {binary}.tar.gz"
            )
            stdout, stderr, code = ssh.execute_sudo(dl_cmd, timeout=120)
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log(f"ERROR: Failed to download {info['display_name']}.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Install binary
            extract_dir = f"{binary}-{vprefix}{latest}.linux-{dl_arch}"
            _log("Installing binary...")
            stdout, stderr, code = ssh.execute_sudo(
                f"cp /tmp/{extract_dir}/{binary} /usr/local/bin/ && "
                f"chown {binary}:{binary} /usr/local/bin/{binary}",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to install binary.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Write env file if needed
            env_file = None
            if info.get("requires_config") and instance.config:
                env_file = f"/etc/default/{binary}"
                env_lines = "\n".join(f"{k}={v}" for k, v in instance.config.items())
                _log("Writing environment configuration...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"cat > {env_file} << 'ENVEOF'\n{env_lines}\nENVEOF\n"
                    f"chmod 600 {env_file}",
                    timeout=15,
                )
                _log_cmd_output(_log, stdout, stderr, code)

            # Create systemd service
            _log("Creating systemd service...")
            service_content = _generate_exporter_systemd_unit(
                instance.exporter_type, instance.port, env_file
            )
            stdout, stderr, code = ssh.execute_sudo(
                f"cat > /etc/systemd/system/{info['systemd_unit']} << 'SVCEOF'\n{service_content}\nSVCEOF",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create systemd service.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Enable and start
            _log(f"Starting {info['display_name']}...")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl daemon-reload && systemctl enable {info['systemd_unit']} && "
                f"systemctl start {info['systemd_unit']}",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log(f"ERROR: Failed to start {info['display_name']}.")
                instance.status = "failed"
                db.session.commit()
                return False, log_lines

            # Verify
            time.sleep(2)
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl is-active {info['systemd_unit']}", timeout=10
            )
            if code != 0 or (stdout or "").strip() != "active":
                _log(f"WARNING: {info['display_name']} may not be running.")

            # Clean up
            ssh.execute_sudo(f"rm -rf /tmp/{binary}.tar.gz /tmp/{extract_dir}", timeout=15)

            _log(f"{info['display_name']} v{latest} installed successfully.")

            from datetime import datetime, timezone
            instance.status = "installed"
            instance.version = latest
            instance.installed_at = datetime.now(timezone.utc)
            db.session.commit()

            # Regenerate prometheus.yml
            _regenerate_prometheus_config(_log)

            return True, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Exporter install failed for %s", instance.exporter_type)
        instance.status = "failed"
        db.session.commit()
        return False, log_lines


def run_exporter_uninstall(instance_id, log_callback=None):
    """Uninstall an exporter from the target guest via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, ExporterInstance, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    instance = ExporterInstance.query.get(instance_id)
    if not instance:
        _log("ERROR: Exporter instance not found.")
        return False, log_lines

    info = KNOWN_EXPORTERS.get(instance.exporter_type)
    if not info:
        _log(f"ERROR: Unknown exporter type: {instance.exporter_type}")
        return False, log_lines

    guest = instance.guest
    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured.")
        return False, log_lines

    binary = info["binary_name"]
    _log(f"Uninstalling {info['display_name']} from {guest.name}...")

    instance.status = "uninstalling"
    db.session.commit()

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Stop and disable
            _log("Stopping service...")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl stop {info['systemd_unit']} 2>/dev/null; "
                f"systemctl disable {info['systemd_unit']} 2>/dev/null",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Remove files
            _log("Removing files...")
            stdout, stderr, code = ssh.execute_sudo(
                f"rm -f /usr/local/bin/{binary} "
                f"/etc/systemd/system/{info['systemd_unit']} "
                f"/etc/default/{binary} && "
                f"systemctl daemon-reload",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            _log(f"{info['display_name']} uninstalled successfully.")

            instance.status = "removed"
            db.session.commit()

            # Regenerate prometheus.yml
            _regenerate_prometheus_config(_log)

            return True, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Exporter uninstall failed for %s", instance.exporter_type)
        instance.status = "failed"
        db.session.commit()
        return False, log_lines


# ---------------------------------------------------------------------------
# Prometheus config regeneration
# ---------------------------------------------------------------------------

def _regenerate_prometheus_config(_log=None):
    """Regenerate prometheus.yml with all installed exporter targets and push to Prometheus guest."""
    from models import Credential, ExporterInstance, Guest, Setting
    from apps.prometheus_app import _generate_prometheus_yml

    _log = _log or (lambda msg: None)

    prom_guest_id = Setting.get("prometheus_guest_id", "")
    if not prom_guest_id:
        _log("Skipping prometheus.yml regeneration: no Prometheus guest configured.")
        return

    try:
        prom_guest = Guest.query.get(int(prom_guest_id))
    except (TypeError, ValueError):
        _log("ERROR: Invalid Prometheus guest ID.")
        return

    if not prom_guest:
        _log("ERROR: Prometheus guest not found.")
        return

    # Build extra scrape configs from installed exporters
    installed = (
        ExporterInstance.query
        .filter(ExporterInstance.status == "installed")  # noqa: E712
        .join(Guest)
        .all()
    )

    # Group by exporter type
    by_type = {}
    for exp in installed:
        ip = exp.guest.ip_address
        if not ip or ip.lower() in ("dhcp", "dhcp6", "auto"):
            continue
        by_type.setdefault(exp.exporter_type, []).append(f"{ip}:{exp.port}")

    extra_configs = ""
    for etype, targets in sorted(by_type.items()):
        info = KNOWN_EXPORTERS.get(etype, {})
        job_name = info.get("job_name", etype)
        targets_str = ", ".join(f'"{t}"' for t in sorted(targets))
        extra_configs += f"""

  - job_name: "{job_name}"
    static_configs:
      - targets: [{targets_str}]"""

    # Generate full config
    lambnet_url = Setting.get("prometheus_lambnet_metrics_url", "")
    auth_token = Setting.get("prometheus_auth_token", "")
    yml = _generate_prometheus_yml(lambnet_url, auth_token, extra_configs)

    # Push to Prometheus guest
    credential = prom_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential for Prometheus guest.")
        return

    try:
        with SSHClient.from_credential(prom_guest.ip_address, credential) as ssh:
            _log("Updating prometheus.yml with exporter targets...")
            stdout, stderr, code = ssh.execute_sudo(
                f"cat > /etc/prometheus/prometheus.yml << 'PROMEOF'\n{yml}\nPROMEOF",
                timeout=15,
            )
            if code != 0:
                _log(f"ERROR: Failed to write prometheus.yml: {(stderr or '')[:200]}")
                return

            _log("Reloading Prometheus configuration...")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl reload prometheus", timeout=15
            )
            if code != 0:
                _log(f"WARNING: Prometheus reload may have failed: {(stderr or '')[:200]}")
            else:
                _log("Prometheus configuration updated successfully.")
    except Exception as e:
        _log(f"ERROR: Failed to update Prometheus config: {e}")
