"""
Mastodon (glitch-soc) upgrade automation.

Checks the mastodon/mastodon GitHub repo for new releases, takes Proxmox
snapshots of the app and database guests, then runs the full glitch-soc
upgrade procedure via SSH including git stash/pop, PGBouncer-to-direct-DB
swap for migrations, and service restarts.
"""

import json
import logging
import re
import time
from datetime import datetime, timezone
from urllib.request import urlopen, Request

from models import Setting, Guest
from ssh_client import SSHClient
from proxmox_api import ProxmoxClient

logger = logging.getLogger(__name__)

# Shell-safe value pattern: alphanumeric, hyphens, underscores, dots, forward slashes, colons
_SHELL_SAFE_RE = re.compile(r'^[\w.\-/:~]+$')


def _validate_shell_param(value, label):
    """Raise ValueError if a config value contains shell-unsafe characters."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _SHELL_SAFE_RE.match(value):
        raise ValueError(f"{label} contains unsafe characters: {value!r}")

DEFAULT_MASTODON_REPO = "mastodon/mastodon"


def check_mastodon_release():
    """Check GitHub for the latest Mastodon release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        repo = Setting.get("mastodon_repo", DEFAULT_MASTODON_REPO) or DEFAULT_MASTODON_REPO
        releases_url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = Request(releases_url, headers={"User-Agent": "MCAT"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        latest = data.get("tag_name", "").lstrip("v")
        release_url = data.get("html_url", "")

        if not latest:
            return False, "", ""

        Setting.set("mastodon_latest_version", latest)
        Setting.set("mastodon_latest_release_url", release_url)

        current = Setting.get("mastodon_current_version", "")
        update_available = bool(current and latest != current)

        return update_available, latest, release_url
    except Exception as e:
        logger.error(f"Failed to check Mastodon releases: {e}")
        return False, "", ""


def snapshot_guest(guest):
    """Create a Proxmox snapshot of a guest before upgrade.

    Returns (success, message).
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapname = f"pre-mastodon-{timestamp}"
    description = f"Auto-snapshot before Mastodon upgrade at {timestamp}"

    return client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)


def backup_guest(guest, storage):
    """Create a vzdump backup of a guest before upgrade. Polls until the task completes.

    Returns (success, message).
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    notes = f"pre-mastodon-{timestamp}"

    ok, upid = client.create_backup(node, guest.vmid, storage, notes=notes)
    if not ok:
        return False, f"Failed to start backup: {upid}"

    # Poll until the vzdump task completes (can take several minutes for large guests)
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
            logger.debug(f"Error polling backup task for {guest.name}: {e}")

    return False, f"Backup of '{guest.name}' timed out after {timeout // 60} minutes"


def _get_mastodon_config():
    """Read all Mastodon-related settings."""
    return {
        "guest_id": Setting.get("mastodon_guest_id", ""),
        "db_guest_id": Setting.get("mastodon_db_guest_id", ""),
        "user": Setting.get("mastodon_user", "mastodon"),
        "app_dir": Setting.get("mastodon_app_dir", "/home/mastodon/live"),
        "pgbouncer_host": Setting.get("mastodon_pgbouncer_host", ""),
        "pgbouncer_port": Setting.get("mastodon_pgbouncer_port", ""),
        "direct_db_host": Setting.get("mastodon_direct_db_host", ""),
        "direct_db_port": Setting.get("mastodon_direct_db_port", "5432"),
        "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false") == "true",
        "current_version": Setting.get("mastodon_current_version", ""),
        "latest_version": Setting.get("mastodon_latest_version", ""),
        "protection_type": Setting.get("mastodon_protection_type", "snapshot"),
        "backup_storage": Setting.get("mastodon_backup_storage", ""),
    }


def _swap_env_db(ssh, app_dir, new_host, new_port):
    """Swap DB_HOST and DB_PORT in .env.production via sed."""
    _validate_shell_param(app_dir, "app_dir")
    _validate_shell_param(new_host, "DB host")
    if not re.match(r'^\d+$', str(new_port)):
        return False, f"Invalid DB port: {new_port}"

    env_file = f"{app_dir}/.env.production"
    cmds = [
        f"sed -i 's/^DB_HOST=.*/DB_HOST={new_host}/' {env_file}",
        f"sed -i 's/^DB_PORT=.*/DB_PORT={new_port}/' {env_file}",
    ]
    for cmd in cmds:
        stdout, stderr, code = ssh.execute_sudo(cmd, timeout=10)
        if code != 0:
            return False, f"Failed to update .env.production: {stderr}"
    return True, "DB config swapped"


def run_mastodon_upgrade():
    """Run the full Mastodon upgrade procedure.

    Returns (success, log_output).
    """
    from models import db, Credential

    config = _get_mastodon_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Mastodon app guest not configured"
    if not config["db_guest_id"]:
        return False, "PostgreSQL guest not configured"
    if not config["pgbouncer_host"] or not config["direct_db_host"]:
        return False, "PGBouncer and direct DB host/port must be configured"

    mastodon_guest = Guest.query.get(int(config["guest_id"]))
    db_guest = Guest.query.get(int(config["db_guest_id"]))

    if not mastodon_guest:
        return False, "Mastodon app guest not found"
    if not db_guest:
        return False, "PostgreSQL guest not found"

    user = config["user"]
    app_dir = config["app_dir"]

    # Validate shell-interpolated values to prevent command injection
    try:
        _validate_shell_param(user, "Mastodon user")
        _validate_shell_param(app_dir, "Mastodon app_dir")
    except ValueError as e:
        return False, str(e)

    # --- Step 1: Protection (snapshot or backup) ---
    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")

    if protection_type == "backup" and backup_storage:
        log(f"=== Step 1: Creating vzdump backups to storage '{backup_storage}' ===")
        log("(This may take several minutes — please be patient)")

        ok, msg = backup_guest(mastodon_guest, backup_storage)
        log(f"Backup {mastodon_guest.name}: {msg}")
        if not ok:
            return False, "\n".join(log_lines)

        ok, msg = backup_guest(db_guest, backup_storage)
        log(f"Backup {db_guest.name}: {msg}")
        if not ok:
            return False, "\n".join(log_lines)
    else:
        log("=== Step 1: Creating Proxmox snapshots ===")

        ok, msg = snapshot_guest(mastodon_guest)
        log(f"Snapshot {mastodon_guest.name}: {msg}")
        if not ok:
            return False, "\n".join(log_lines)

        ok, msg = snapshot_guest(db_guest)
        log(f"Snapshot {db_guest.name}: {msg}")
        if not ok:
            return False, "\n".join(log_lines)

    # --- Step 2: SSH upgrade sequence ---
    log("=== Step 2: Connecting to Mastodon guest via SSH ===")

    credential = mastodon_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for Mastodon guest"

    env_swapped = False

    try:
        with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:

            # 2a. git stash
            log("--- git stash ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash'", timeout=30
            )
            log(stdout or stderr or "(no output)")

            # 2b. Swap .env.production to direct DB
            log("--- Swapping .env.production to direct DB ---")
            ok, msg = _swap_env_db(ssh, app_dir, config["direct_db_host"], config["direct_db_port"])
            log(msg)
            if not ok:
                return False, "\n".join(log_lines)
            env_swapped = True

            # 2c. git pull
            log("--- git pull ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git pull'", timeout=120
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: git pull failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2d. git stash pop
            log("--- git stash pop ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash pop'", timeout=30
            )
            log(stdout or stderr or "(no output)")
            # stash pop may fail if no stash exists or conflict - not fatal
            if code != 0:
                log("WARNING: git stash pop returned non-zero (may be no stash to pop)")

            # 2e. bundle install
            log("--- bundle install ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && bundle install'", timeout=600
            )
            log(stdout[-2000:] if len(stdout) > 2000 else stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: bundle install failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2f. yarn install
            log("--- yarn install ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && yarn install --frozen-lockfile'", timeout=600
            )
            log(stdout[-2000:] if len(stdout) > 2000 else stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: yarn install failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2g. Pre-deployment migrations
            log("--- Pre-deployment database migrations ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && RAILS_ENV=production SKIP_POST_DEPLOYMENT_MIGRATIONS=true bundle exec rails db:migrate'",
                timeout=600,
            )
            log(stdout[-2000:] if len(stdout) > 2000 else stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: pre-deployment migrations failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2h. Asset precompilation
            log("--- Asset precompilation ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && RAILS_ENV=production bundle exec rails assets:precompile'",
                timeout=900,
            )
            log(stdout[-2000:] if len(stdout) > 2000 else stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: asset precompilation failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2i. Restart all mastodon services
            log("--- Restarting mastodon services ---")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl restart mastodon-*", timeout=60
            )
            log(stdout or stderr or "(no output)")

            # 2k. Clear cache
            log("--- Clearing cache ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && RAILS_ENV=production bin/tootctl cache clear'",
                timeout=120,
            )
            log(stdout or stderr or "(no output)")

            # 2l. Post-deployment migrations
            log("--- Post-deployment database migrations ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && RAILS_ENV=production bundle exec rails db:migrate'",
                timeout=600,
            )
            log(stdout[-2000:] if len(stdout) > 2000 else stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: post-deployment migrations failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2m. Restore .env.production to PGBouncer
            log("--- Restoring .env.production to PGBouncer ---")
            ok, msg = _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
            log(msg)
            env_swapped = False

            # 2n. Final service restart
            log("--- Final service restart ---")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl restart mastodon-*", timeout=60
            )
            log(stdout or stderr or "(no output)")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        # Try to restore .env.production if we swapped it
        if env_swapped:
            try:
                with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:
                    _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                    log("Restored .env.production to PGBouncer after failure")
            except Exception:
                log("WARNING: Could not restore .env.production after failure")
        return False, "\n".join(log_lines)

    # Success - update version tracking
    log("=== Upgrade complete! ===")
    latest = config["latest_version"] or config["current_version"]
    now = datetime.now(timezone.utc).isoformat()
    Setting.set("mastodon_current_version", latest)
    Setting.set("mastodon_last_upgrade_at", now)
    Setting.set("mastodon_last_upgrade_status", "success")
    Setting.set("mastodon_last_upgrade_log", "\n".join(log_lines))
    db.session.commit()

    return True, "\n".join(log_lines)
