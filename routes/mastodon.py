import logging
import time as _time
import threading as _threading
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from models import db, Setting, Guest
from audit import log_action

# ---------------------------------------------------------------------------
# In-memory stats cache — avoids holding an HTTP connection open for 15-20 s
# while SSH calls run (which disrupts the SSE collab stream on the same
# single gevent worker).  The stats() route fires a detached background
# greenlet and returns {"loading": true} immediately; clients poll until
# the background job populates the cache.
# ---------------------------------------------------------------------------
_stats_cache = {"result": None, "ts": 0.0, "loading": False}
_STATS_TTL = 60  # seconds before a cached result is considered stale

# ---------------------------------------------------------------------------
# In-memory upgrade job state — tracks the currently-running upgrade so the
# frontend can poll for real-time log output.
# ---------------------------------------------------------------------------
_upgrade_job = {"running": False, "success": None, "log": []}

logger = logging.getLogger(__name__)

bp = Blueprint("mastodon", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_mastodon_settings():
    return {
        "guest_id": Setting.get("mastodon_guest_id", ""),
        "db_guest_id": Setting.get("mastodon_db_guest_id", ""),
        "user": Setting.get("mastodon_user", "mastodon"),
        "app_dir": Setting.get("mastodon_app_dir", "/home/mastodon/live"),
        "repo": Setting.get("mastodon_repo", "mastodon/mastodon"),
        "branch": Setting.get("mastodon_branch", ""),
        "pgbouncer_host": Setting.get("mastodon_pgbouncer_host", ""),
        "pgbouncer_port": Setting.get("mastodon_pgbouncer_port", ""),
        "direct_db_host": Setting.get("mastodon_direct_db_host", ""),
        "direct_db_port": Setting.get("mastodon_direct_db_port", "5432"),
        "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false"),
        "current_version": Setting.get("mastodon_current_version", ""),
        "pg_version": Setting.get("mastodon_pg_version", ""),
        "latest_version": Setting.get("mastodon_latest_version", ""),
        "latest_release_url": Setting.get("mastodon_latest_release_url", ""),
        "last_upgrade_at": Setting.get("mastodon_last_upgrade_at", ""),
        "last_upgrade_status": Setting.get("mastodon_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("mastodon_last_upgrade_log", ""),
        "protection_type": Setting.get("mastodon_protection_type", "snapshot"),
        "backup_storage": Setting.get("mastodon_backup_storage", ""),
        "backup_mode": Setting.get("mastodon_backup_mode", "snapshot"),
        "guest_id_2": Setting.get("mastodon_guest_id_2", ""),
    }


@bp.route("/")
def overview():
    settings = _get_mastodon_settings()
    guest_id = settings.get("guest_id", "")
    db_guest_id = settings.get("db_guest_id", "")

    mastodon_services = []
    from models import GuestService
    try:
        if guest_id:
            mastodon_services += GuestService.query.filter_by(guest_id=int(guest_id)).all()
        if db_guest_id:
            mastodon_services += GuestService.query.filter_by(guest_id=int(db_guest_id)).all()
    except (TypeError, ValueError):
        logger.warning("Mastodon guest_id setting is not a valid integer")

    return render_template(
        "mastodon_overview.html",
        settings=settings,
        mastodon_services=mastodon_services,
    )


@bp.route("/upgrade")
def upgrade_page():
    settings = _get_mastodon_settings()
    guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()

    # Fetch backup-capable storages from the Mastodon guest's Proxmox host
    backup_storages = []
    guest_id = settings.get("guest_id", "")
    if guest_id:
        mastodon_guest = Guest.query.get(int(guest_id))
        if mastodon_guest and mastodon_guest.proxmox_host and not mastodon_guest.proxmox_host.is_pbs:
            try:
                from proxmox_api import ProxmoxClient
                client = ProxmoxClient(mastodon_guest.proxmox_host)
                node = client.find_guest_node(mastodon_guest.vmid)
                if node:
                    backup_storages = client.list_node_storages(node, content_type="backup")
            except Exception as e:
                logger.warning(f"Could not fetch backup storages: {e}")

    return render_template("mastodon.html", settings=settings, guests=guests, backup_storages=backup_storages)


@bp.route("/stats")
def stats():
    settings = _get_mastodon_settings()
    guest_id = settings.get("guest_id", "")
    db_guest_id = settings.get("db_guest_id", "")

    if not guest_id or not db_guest_id:
        return jsonify({"error": "Mastodon guests not configured"}), 400

    force = request.args.get("force") == "1"
    now = _time.time()

    # Return cached result if it is still fresh
    if not force and _stats_cache["result"] and (now - _stats_cache["ts"]) < _STATS_TTL:
        return jsonify(_stats_cache["result"])

    # Background collection already in progress — tell the client to poll
    if _stats_cache["loading"]:
        return jsonify({"loading": True})

    # Kick off a detached background greenlet (or thread) so this HTTP request
    # returns in milliseconds without holding a WSGI connection open.
    _stats_cache["loading"] = True
    if force:
        _stats_cache["result"] = None

    from flask import current_app
    _app = current_app._get_current_object()

    def _bg():
        try:
            from scanner import get_mastodon_overview_stats
            with _app.app_context():
                from models import Guest as _G
                mg = _G.query.get(int(guest_id))
                dg = _G.query.get(int(db_guest_id))
                data = get_mastodon_overview_stats(
                    mg, dg,
                    app_dir=settings.get("app_dir", "/home/mastodon/live"),
                    user=settings.get("user", "mastodon"),
                )
            data["current_version"] = settings.get("current_version", "")
            data["latest_version"] = settings.get("latest_version", "")
            data["pg_version"] = settings.get("pg_version", "")
            _stats_cache["result"] = data
            _stats_cache["ts"] = _time.time()
        except Exception as exc:
            logger.error("Mastodon stats background fetch failed: %s", exc)
        finally:
            _stats_cache["loading"] = False

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        import threading as _threading
        _threading.Thread(target=_bg, daemon=True).start()

    return jsonify({"loading": True})


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("mastodon_guest_id", request.form.get("mastodon_guest_id", "").strip())
    Setting.set("mastodon_guest_id_2", request.form.get("mastodon_guest_id_2", "").strip())
    Setting.set("mastodon_db_guest_id", request.form.get("mastodon_db_guest_id", "").strip())
    Setting.set("mastodon_user", request.form.get("mastodon_user", "mastodon").strip())
    Setting.set("mastodon_app_dir", request.form.get("mastodon_app_dir", "/home/mastodon/live").strip())
    Setting.set("mastodon_repo", request.form.get("mastodon_repo", "mastodon/mastodon").strip())
    Setting.set("mastodon_branch", request.form.get("mastodon_branch", "").strip())
    Setting.set("mastodon_pgbouncer_host", request.form.get("mastodon_pgbouncer_host", "").strip())
    Setting.set("mastodon_pgbouncer_port", request.form.get("mastodon_pgbouncer_port", "").strip())
    Setting.set("mastodon_direct_db_host", request.form.get("mastodon_direct_db_host", "").strip())
    Setting.set("mastodon_direct_db_port", request.form.get("mastodon_direct_db_port", "5432").strip())
    Setting.set("mastodon_auto_upgrade", "true" if "mastodon_auto_upgrade" in request.form else "false")
    Setting.set("mastodon_current_version", request.form.get("mastodon_current_version", "").strip())
    protection_type = request.form.get("mastodon_protection_type", "snapshot")
    Setting.set("mastodon_protection_type", protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("mastodon_backup_storage", request.form.get("mastodon_backup_storage", "").strip())
    backup_mode = request.form.get("mastodon_backup_mode", "snapshot")
    Setting.set("mastodon_backup_mode", backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("mastodon_config_save", "settings", resource_name="mastodon")
    db.session.commit()
    flash("Mastodon settings saved.", "success")
    return redirect(url_for("mastodon.upgrade_page"))


@bp.route("/check", methods=["POST"])
def check():
    from mastodon import check_mastodon_release

    update_available, latest, release_url = check_mastodon_release()
    current = Setting.get("mastodon_current_version", "")

    if not latest:
        flash("Could not fetch latest Mastodon release from GitHub.", "error")
    elif update_available:
        flash(f"Mastodon update available: v{current} -> v{latest}", "warning")
    elif current:
        flash(f"Mastodon is up to date (v{current}).", "success")
    else:
        flash(f"Latest Mastodon release: v{latest}. Set your current version to enable update detection.", "info")

    return redirect(url_for("mastodon.upgrade_page"))


@bp.route("/upgrade/status")
def upgrade_status():
    return jsonify({
        "running": _upgrade_job["running"],
        "success": _upgrade_job["success"],
        "log": _upgrade_job["log"],
    })


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from mastodon import run_mastodon_upgrade
    from flask import current_app

    if _upgrade_job["running"]:
        flash("An upgrade is already in progress.", "warning")
        return redirect(url_for("mastodon.upgrade_page"))

    _upgrade_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_mastodon_upgrade(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("mastodon_last_upgrade_at", now)
            Setting.set("mastodon_last_upgrade_status", "success" if ok else "error")
            Setting.set("mastodon_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("mastodon_upgrade", "settings", resource_name="mastodon",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("mastodon.upgrade_page"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from scanner import _execute_command
    from mastodon import _validate_shell_param

    guest_id = Setting.get("mastodon_guest_id", "")
    db_guest_id = Setting.get("mastodon_db_guest_id", "")
    user = Setting.get("mastodon_user", "mastodon")
    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")

    try:
        _validate_shell_param(user, "Mastodon user")
        _validate_shell_param(app_dir, "Mastodon app_dir")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("mastodon.upgrade_page"))

    detected = []

    # Detect Mastodon version
    if guest_id:
        mastodon_guest = Guest.query.get(int(guest_id))
        if mastodon_guest:
            stdout, error = _execute_command(
                mastodon_guest,
                f"su - {user} -c 'cat {app_dir}/VERSION 2>/dev/null || cd {app_dir} && git describe --tags 2>/dev/null'",
                timeout=15,
                sudo=True,
            )
            if stdout and not error:
                version = stdout.strip().lstrip("v")
                if version:
                    Setting.set("mastodon_current_version", version)
                    detected.append(f"Mastodon: v{version}")
            elif error:
                logger.warning(f"Mastodon version detection failed: {error}")
                flash(f"Could not detect Mastodon version: {error}", "warning")
        else:
            flash("Mastodon app guest not found.", "error")
    else:
        flash("Mastodon app guest not configured.", "warning")

    # Detect PostgreSQL version
    if db_guest_id:
        db_guest = Guest.query.get(int(db_guest_id))
        if db_guest:
            stdout, error = _execute_command(
                db_guest,
                "psql --version 2>/dev/null || postgres --version 2>/dev/null",
                timeout=15,
            )
            if stdout and not error:
                import re
                match = re.search(r"(\d+[\.\d]*)", stdout.strip())
                if match:
                    pg_version = match.group(1)
                    Setting.set("mastodon_pg_version", pg_version)
                    detected.append(f"PostgreSQL: {pg_version}")
            elif error:
                logger.warning(f"PostgreSQL version detection failed: {error}")
                flash(f"Could not detect PostgreSQL version: {error}", "warning")
        else:
            flash("PostgreSQL guest not found.", "error")
    else:
        flash("PostgreSQL guest not configured.", "warning")

    if detected:
        flash(f"Detected: {', '.join(detected)}", "success")

    return redirect(url_for("mastodon.upgrade_page"))
