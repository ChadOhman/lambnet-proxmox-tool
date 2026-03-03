import os
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from models import db, Setting
from credential_store import encrypt
from config import BASE_DIR, DATA_DIR
from audit import log_action

bp = Blueprint("settings", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_manage_settings:
        flash("Super admin access required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_settings_dict():
    return {
        "discord_webhook_url": Setting.get("discord_webhook_url"),
        "discord_enabled": Setting.get("discord_enabled", "false"),
        "discord_notify_updates": Setting.get("discord_notify_updates", "true"),
        "discord_notify_updates_security_only": Setting.get("discord_notify_updates_security_only", "false"),
        "discord_notify_mastodon": Setting.get("discord_notify_mastodon", "true"),
        "discord_notify_ghost": Setting.get("discord_notify_ghost", "true"),
        "discord_notify_app": Setting.get("discord_notify_app", "true"),
        "scan_interval": Setting.get("scan_interval", "6"),
        "scan_enabled": Setting.get("scan_enabled", "true"),
        "discovery_interval": Setting.get("discovery_interval", "4"),
        "discovery_enabled": Setting.get("discovery_enabled", "true"),
        "service_check_interval": Setting.get("service_check_interval", "5"),
        "service_check_enabled": Setting.get("service_check_enabled", "true"),
        "unifi_enabled": Setting.get("unifi_enabled", "false"),
        "unifi_base_url": Setting.get("unifi_base_url", ""),
        "unifi_username": Setting.get("unifi_username", ""),
        "unifi_password": Setting.get("unifi_password", ""),
        "unifi_site": Setting.get("unifi_site", "default"),
        "unifi_is_udm": Setting.get("unifi_is_udm", "true"),
        "unifi_filter_subnet": Setting.get("unifi_filter_subnet", ""),
        "unifi_geoip_enabled": Setting.get("unifi_geoip_enabled", "false"),
        "unifi_geoip_db_path": Setting.get("unifi_geoip_db_path", ""),
        "unifi_api_poll_enabled": Setting.get("unifi_api_poll_enabled", "true"),
        "unifi_api_poll_interval": Setting.get("unifi_api_poll_interval", "5"),
        "unifi_log_retention_days": Setting.get("unifi_log_retention_days", "60"),
        "app_auto_update": Setting.get("app_auto_update", "false"),
        "app_update_branch": Setting.get("app_update_branch", ""),
        "backup_storage": Setting.get("backup_storage", ""),
        "backup_mode": Setting.get("backup_mode", "snapshot"),
        "backup_compress": Setting.get("backup_compress", "zstd"),
    }


def _get_latest_release():
    """Fetch the latest release version from GitHub. Returns version string or None."""
    import urllib.request
    import json
    repo = current_app.config.get("GITHUB_REPO", "")
    if not repo:
        return None
    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("tag_name", "").lstrip("v") or None
    except Exception:
        return None


@bp.route("/")
def index():
    settings = _get_settings_dict()
    latest_release = _get_latest_release()

    # Collect backup-capable storages from all non-PBS Proxmox hosts for the dropdown
    backup_storages = []
    seen = set()
    try:
        from models import ProxmoxHost
        from proxmox_api import ProxmoxClient
        for host in ProxmoxHost.query.filter_by(is_pbs=False).all():
            try:
                client = ProxmoxClient(host)
                nodes = client.api.nodes.get()
                if nodes:
                    storages = client.list_node_storages(nodes[0]['node'], content_type="backup")
                    for st in storages:
                        sid = st.get('storage', '')
                        if sid and sid not in seen:
                            seen.add(sid)
                            backup_storages.append(st)
            except Exception:
                pass
    except Exception:
        pass

    # GeoIP file status for the upload widget
    geoip_db_path = settings.get("unifi_geoip_db_path", "")
    geoip_db_info = None
    if geoip_db_path:
        try:
            stat = os.stat(geoip_db_path)
            geoip_db_info = {"path": geoip_db_path, "size_mb": round(stat.st_size / 1024 / 1024, 1)}
        except OSError:
            geoip_db_info = {"path": geoip_db_path, "size_mb": None}

    return render_template("settings.html", settings=settings, update_available=False, update_version=None, latest_release=latest_release, backup_storages=backup_storages, geoip_db_info=geoip_db_info)


@bp.route("/discord", methods=["POST"])
def save_discord():
    webhook_url = request.form.get("discord_webhook_url", "").strip()
    enabled = "discord_enabled" in request.form
    notify_updates = "discord_notify_updates" in request.form
    notify_security_only = "discord_notify_updates_security_only" in request.form
    notify_mastodon = "discord_notify_mastodon" in request.form
    notify_ghost = "discord_notify_ghost" in request.form
    notify_app = "discord_notify_app" in request.form

    if webhook_url:
        Setting.set("discord_webhook_url", webhook_url)
    Setting.set("discord_enabled", "true" if enabled else "false")
    Setting.set("discord_notify_updates", "true" if notify_updates else "false")
    Setting.set("discord_notify_updates_security_only", "true" if notify_security_only else "false")
    Setting.set("discord_notify_mastodon", "true" if notify_mastodon else "false")
    Setting.set("discord_notify_ghost", "true" if notify_ghost else "false")
    Setting.set("discord_notify_app", "true" if notify_app else "false")

    log_action("settings_discord_save", "settings", resource_name="discord")
    db.session.commit()
    flash("Discord settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/discord/test", methods=["POST"])
def test_discord():
    # Save settings first
    save_discord()

    from notifier import send_test_notification
    ok, message = send_test_notification()
    if ok:
        flash(f"Test notification sent: {message}", "success")
    else:
        flash(f"Test notification failed: {message}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/scan", methods=["POST"])
def save_scan():
    interval = request.form.get("scan_interval", "6").strip()
    enabled = "scan_enabled" in request.form
    discovery_interval = request.form.get("discovery_interval", "4").strip()
    discovery_enabled = "discovery_enabled" in request.form

    service_check_interval = request.form.get("service_check_interval", "5").strip()
    service_check_enabled = "service_check_enabled" in request.form

    Setting.set("scan_interval", interval)
    Setting.set("scan_enabled", "true" if enabled else "false")
    Setting.set("discovery_interval", discovery_interval)
    Setting.set("discovery_enabled", "true" if discovery_enabled else "false")
    Setting.set("service_check_interval", service_check_interval)
    Setting.set("service_check_enabled", "true" if service_check_enabled else "false")

    log_action("settings_scan_save", "settings", resource_name="scan_discovery")
    db.session.commit()

    try:
        from scheduler import reschedule_jobs
        reschedule_jobs(int(interval), int(discovery_interval), int(service_check_interval))
    except Exception:
        pass  # Scheduler not running (e.g. tests or CLI context)

    flash("Scan & discovery settings saved.", "success")
    return redirect(url_for("settings.index"))



@bp.route("/backups", methods=["POST"])
def save_backups():
    backup_storage = request.form.get("backup_storage", "").strip()
    backup_mode = request.form.get("backup_mode", "snapshot").strip()
    backup_compress = request.form.get("backup_compress", "zstd").strip()

    Setting.set("backup_storage", backup_storage)
    Setting.set("backup_mode", backup_mode)
    Setting.set("backup_compress", backup_compress)

    log_action("settings_backups_save", "settings", resource_name="backups")
    db.session.commit()
    flash("Backup settings saved.", "success")
    return redirect(url_for("settings.index"))



@bp.route("/unifi", methods=["POST"])
def save_unifi():
    enabled = "unifi_enabled" in request.form
    base_url = request.form.get("unifi_base_url", "").strip()
    username = request.form.get("unifi_username", "").strip()
    password = request.form.get("unifi_password", "").strip()
    site = request.form.get("unifi_site", "default").strip()
    is_udm = "unifi_is_udm" in request.form
    filter_subnet = request.form.get("unifi_filter_subnet", "").strip()

    Setting.set("unifi_enabled", "true" if enabled else "false")
    Setting.set("unifi_base_url", base_url)
    Setting.set("unifi_username", username)
    if password:
        Setting.set("unifi_password", encrypt(password))
    Setting.set("unifi_site", site or "default")
    Setting.set("unifi_is_udm", "true" if is_udm else "false")
    Setting.set("unifi_filter_subnet", filter_subnet)

    log_action("settings_unifi_save", "settings", resource_name="unifi")
    db.session.commit()
    flash("UniFi settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unifi/test", methods=["POST"])
def test_unifi():
    save_unifi()

    from credential_store import decrypt
    from unifi_client import UniFiClient

    base_url = Setting.get("unifi_base_url", "")
    username = Setting.get("unifi_username", "")
    encrypted_pw = Setting.get("unifi_password", "")
    site = Setting.get("unifi_site", "default")
    is_udm = Setting.get("unifi_is_udm", "true") == "true"

    if not base_url or not username or not encrypted_pw:
        flash("UniFi controller URL, username, and password are required.", "error")
        return redirect(url_for("settings.index"))

    password = decrypt(encrypted_pw)
    client = UniFiClient(base_url, username, password, site=site, is_udm=is_udm)
    ok, msg = client.test_connection()

    if ok:
        flash(f"UniFi connection successful: {msg}", "success")
    else:
        flash(f"UniFi connection failed: {msg}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/unifi-logging", methods=["POST"])
def save_unifi_logging():
    geoip_enabled = "unifi_geoip_enabled" in request.form
    geoip_db_path = request.form.get("unifi_geoip_db_path", "").strip()
    api_poll_enabled = "unifi_api_poll_enabled" in request.form
    api_poll_interval = request.form.get("unifi_api_poll_interval", "5").strip()
    retention_days = request.form.get("unifi_log_retention_days", "60").strip()

    try:
        interval_int = int(api_poll_interval)
        if not (1 <= interval_int <= 1440):
            raise ValueError
    except ValueError:
        flash("Poll interval must be between 1 and 1440 minutes.", "error")
        return redirect(url_for("settings.index"))

    try:
        retention_int = int(retention_days)
        if not (1 <= retention_int <= 365):
            raise ValueError
    except ValueError:
        flash("Retention must be between 1 and 365 days.", "error")
        return redirect(url_for("settings.index"))

    Setting.set("unifi_geoip_enabled", "true" if geoip_enabled else "false")
    Setting.set("unifi_geoip_db_path", geoip_db_path)
    Setting.set("unifi_api_poll_enabled", "true" if api_poll_enabled else "false")
    Setting.set("unifi_api_poll_interval", str(interval_int))
    Setting.set("unifi_log_retention_days", str(retention_int))

    log_action("settings_unifi_logging_save", "settings", resource_name="unifi_logging")
    db.session.commit()
    flash("UniFi log collection settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unifi-logging/upload-geoip", methods=["POST"])
def upload_geoip_db():
    """Accept an uploaded MaxMind GeoLite2-City .mmdb file and save it to DATA_DIR."""
    _MAX_BYTES = 150 * 1024 * 1024  # 150 MB
    _ANCHOR = "#geoip-section"
    is_xhr = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def _err(msg, status=400):
        if is_xhr:
            return jsonify({"ok": False, "message": msg}), status
        flash(msg, "error")
        return redirect(url_for("settings.index") + _ANCHOR)

    if "geoip_db" not in request.files:
        return _err("No file selected.")

    f = request.files["geoip_db"]
    if not f or not f.filename:
        return _err("No file selected.")

    if not f.filename.lower().endswith(".mmdb"):
        return _err("Invalid file type — expected a .mmdb file.")

    dest_path = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")

    # Stream to disk to avoid large in-memory buffers
    bytes_written = 0
    tmp_path = dest_path + ".tmp"
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(tmp_path, "wb") as out:
            while True:
                chunk = f.stream.read(65536)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > _MAX_BYTES:
                    out.close()
                    os.remove(tmp_path)
                    return _err("File too large (max 150 MB).")
                out.write(chunk)
    except OSError as e:
        return _err(f"Could not save file: {e}")

    # Validate: try opening with geoip2 if available
    try:
        import geoip2.database
        reader = geoip2.database.Reader(tmp_path)
        reader.close()
    except ImportError:
        pass  # geoip2 not installed yet — accept the file
    except Exception as e:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return _err(f"File does not appear to be a valid MaxMind database: {e}")

    os.replace(tmp_path, dest_path)

    # Reset the cached reader so the new file is used immediately
    import unifi_geoip
    unifi_geoip.close()

    size_mb = round(bytes_written / 1024 / 1024, 1)
    Setting.set("unifi_geoip_db_path", dest_path)
    log_action("settings_geoip_upload", "settings", resource_name="geoip_db",
               details={"path": dest_path, "size_mb": size_mb})
    db.session.commit()

    msg = f"GeoIP database uploaded ({size_mb} MB). Path set to {dest_path}."
    if is_xhr:
        return jsonify({"ok": True, "message": msg, "path": dest_path, "size_mb": size_mb})
    flash(msg, "success")
    return redirect(url_for("settings.index") + _ANCHOR)


@bp.route("/unifi-logging/verify-geoip")
def verify_geoip_db():
    """Check that the configured GeoIP database is readable and valid."""
    db_path = Setting.get("unifi_geoip_db_path", "")
    if not db_path:
        return jsonify({"ok": False, "message": "No database path configured."})

    if not os.path.exists(db_path):
        size_mb = None
        return jsonify({"ok": False, "message": f"File not found: {db_path}"})

    try:
        size_mb = round(os.stat(db_path).st_size / 1024 / 1024, 1)
    except OSError:
        size_mb = None

    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        meta = reader.metadata()
        db_type = meta.database_type
        # Test lookup on a known public IP (Google DNS)
        test_ip = "8.8.8.8"
        try:
            rec = reader.city(test_ip)
            test_result = f"{rec.city.name or '—'}, {rec.country.iso_code or '—'}"
        except Exception:
            test_result = None
        reader.close()
    except ImportError:
        return jsonify({"ok": True, "message": f"File exists ({size_mb} MB) — geoip2 library not installed, cannot validate contents.", "size_mb": size_mb, "path": db_path})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Invalid database: {e}", "size_mb": size_mb, "path": db_path})

    msg = f"Valid {db_type} — {size_mb} MB"
    if test_result:
        msg += f" — test lookup 8.8.8.8: {test_result}"
    return jsonify({"ok": True, "message": msg, "size_mb": size_mb, "path": db_path})


@bp.route("/app-update-mode", methods=["POST"])
def save_app_update_mode():
    auto_update = "app_auto_update" in request.form
    update_branch = request.form.get("app_update_branch", "").strip()
    Setting.set("app_auto_update", "true" if auto_update else "false")
    Setting.set("app_update_branch", update_branch)
    log_action("settings_update_mode_save", "settings", resource_name="app_update",
               details={"auto_update": auto_update, "branch": update_branch or None})
    db.session.commit()
    flash("Application update settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/check-update", methods=["POST"])
def check_update():
    import urllib.request
    import json

    # Also save the settings from the same form
    auto_update = "app_auto_update" in request.form
    update_branch = request.form.get("app_update_branch", "").strip()
    Setting.set("app_auto_update", "true" if auto_update else "false")
    Setting.set("app_update_branch", update_branch)

    repo = current_app.config.get("GITHUB_REPO", "")
    current_version = current_app.config.get("APP_VERSION", "0.0.0")

    # If a branch is configured, check if it has new commits instead of releases
    if update_branch:
        try:
            url = f"https://api.github.com/repos/{repo}/branches/{update_branch}"
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                full_sha = data.get("commit", {}).get("sha", "")
                sha = full_sha[:7]
                message = data.get("commit", {}).get("commit", {}).get("message", "").split("\n")[0]
                current_commit = current_app.config.get("GIT_COMMIT", "")
                if current_commit and full_sha.startswith(current_commit):
                    flash(f"Already up to date on branch '{update_branch}' ({sha}).", "success")
                    return redirect(url_for("settings.index"))
                settings = _get_settings_dict()
                return render_template(
                    "settings.html", settings=settings,
                    update_available=True,
                    update_version=f"branch '{update_branch}' (latest: {sha} - {message})",
                    latest_release=_get_latest_release(),
                )
        except Exception as e:
            flash(f"Could not check branch '{update_branch}': {e}", "error")
            return redirect(url_for("settings.index"))

    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != current_version:
                settings = _get_settings_dict()
                return render_template("settings.html", settings=settings, update_available=True, update_version=latest, latest_release=latest)
            flash(f"You are running the latest version (v{current_version}).", "success")
    except Exception as e:
        flash(f"Could not check for updates: {e}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/apply-update", methods=["POST"])
def apply_update():
    update_script = os.path.join(BASE_DIR, "update.sh")
    if not os.path.exists(update_script):
        flash("Update script not found.", "error")
        return redirect(url_for("settings.index"))

    try:
        import re as _re
        update_branch = Setting.get("app_update_branch", "")
        cmd = ["bash", update_script]
        if update_branch:
            if not _re.match(r'^[A-Za-z0-9._\-/]+$', update_branch) or update_branch.startswith("-"):
                flash("Invalid branch name.", "error")
                return redirect(url_for("settings.index"))
            cmd += ["--branch", update_branch]

        proc = subprocess.Popen(cmd, cwd=BASE_DIR)

        # Write PID marker so we can track the process
        pid_file = os.path.join(DATA_DIR, "update.pid")
        with open(pid_file, "w") as f:
            f.write(str(proc.pid))

        log_action("settings_apply_update", "settings", resource_name="app_update",
                   details={"branch": Setting.get("app_update_branch") or None})
        db.session.commit()

    except Exception as e:
        flash(f"Update failed to start: {e}", "error")
        return redirect(url_for("settings.index"))

    return redirect(url_for("settings.update_progress"))


@bp.route("/update-progress")
def update_progress():
    return render_template("update_progress.html")


@bp.route("/update-status")
def update_status():
    log_file = os.path.join(DATA_DIR, "update.log")
    pid_file = os.path.join(DATA_DIR, "update.pid")

    # Read log contents
    log_text = ""
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                log_text = f.read()
        except Exception:
            log_text = ""

    # Check if process is still running
    running = False
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # signal 0 = check if process exists
            running = True
        except (ProcessLookupError, ValueError, PermissionError):
            running = False

    return jsonify({
        "log": log_text,
        "running": running,
        "line_count": log_text.count("\n"),
    })
