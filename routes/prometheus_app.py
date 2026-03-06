"""
Prometheus application management blueprint.

Provides settings, install, upgrade, and connection test routes following the
same pattern as routes/jitsi.py.
"""

import logging
import threading as _threading
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import db, Setting, Guest
from auth.audit import log_action


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


_install_job = {"running": False, "success": None, "log": []}
_upgrade_job = {"running": False, "success": None, "log": []}

logger = logging.getLogger(__name__)

bp = Blueprint("prometheus_app", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_settings():
    return {
        "guest_id": Setting.get("prometheus_guest_id", ""),
        "url": Setting.get("prometheus_url", ""),
        "auth_token": Setting.get("prometheus_auth_token", ""),
        "enabled": Setting.get("prometheus_enabled", "false") == "true",
        "auto_upgrade": Setting.get("prometheus_auto_upgrade", "false"),
        "current_version": Setting.get("prometheus_current_version", ""),
        "latest_version": Setting.get("prometheus_latest_version", ""),
        "update_available": Setting.get("prometheus_update_available", "") == "true",
        "installed": Setting.get("prometheus_installed", "") == "true",
        "retention_days": Setting.get("prometheus_retention_days", "90"),
        "protection_type": Setting.get("prometheus_protection_type", "snapshot"),
        "backup_storage": Setting.get("prometheus_backup_storage", ""),
        "backup_mode": Setting.get("prometheus_backup_mode", "snapshot"),
        "lambnet_metrics_url": Setting.get("prometheus_lambnet_metrics_url", ""),
        "last_install_at": _parse_iso(Setting.get("prometheus_last_install_at", "")),
        "last_install_status": Setting.get("prometheus_last_install_status", ""),
        "last_install_log": Setting.get("prometheus_last_install_log", ""),
        "last_upgrade_at": _parse_iso(Setting.get("prometheus_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("prometheus_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("prometheus_last_upgrade_log", ""),
    }


@bp.route("/manage")
def manage():
    settings = _get_settings()
    guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()

    backup_storages = []
    snapshots_supported = True

    guest_id = settings.get("guest_id", "")
    if guest_id:
        try:
            g = Guest.query.get(int(guest_id))
            if g and g.proxmox_host and not g.proxmox_host.is_pbs:
                from clients.proxmox_api import ProxmoxClient
                client = ProxmoxClient(g.proxmox_host)
                node = client.find_guest_node(g.vmid)
                if node:
                    backup_storages = client.list_node_storages(node, content_type="backup")
                    if not client.guest_supports_snapshot(node, g.vmid, g.guest_type):
                        snapshots_supported = False
        except Exception as e:
            logger.warning("Could not check snapshot/backup support: %s", e)

    return render_template(
        "prometheus.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
    )


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("prometheus_guest_id", request.form.get("prometheus_guest_id", "").strip())
    Setting.set("prometheus_url", request.form.get("prometheus_url", "").strip())
    Setting.set("prometheus_auth_token", request.form.get("prometheus_auth_token", "").strip())
    Setting.set("prometheus_enabled",
                "true" if "prometheus_enabled" in request.form else "false")
    Setting.set("prometheus_auto_upgrade",
                "true" if "prometheus_auto_upgrade" in request.form else "false")
    Setting.set("prometheus_lambnet_metrics_url",
                request.form.get("prometheus_lambnet_metrics_url", "").strip())

    retention = request.form.get("prometheus_retention_days", "90").strip()
    try:
        retention = str(max(1, int(retention)))
    except (ValueError, TypeError):
        retention = "90"
    Setting.set("prometheus_retention_days", retention)

    protection_type = request.form.get("prometheus_protection_type", "snapshot")
    Setting.set("prometheus_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("prometheus_backup_storage",
                request.form.get("prometheus_backup_storage", "").strip())
    backup_mode = request.form.get("prometheus_backup_mode", "snapshot")
    Setting.set("prometheus_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("prometheus_config_save", "settings", resource_name="prometheus")
    db.session.commit()
    flash("Prometheus settings saved.", "success")
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.prometheus_app import check_prometheus_release

    update_available, latest, release_url = check_prometheus_release()
    current = Setting.get("prometheus_current_version", "")

    if not latest:
        flash("Could not fetch latest Prometheus version.", "error")
    elif update_available:
        flash(f"Prometheus update available: v{current} \u2192 v{latest}", "warning")
    elif current:
        flash(f"Prometheus is up to date (v{current}).", "success")
    else:
        flash(f"Latest Prometheus version: v{latest}. Set your current version to enable update detection.", "info")

    db.session.commit()
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/test-connection", methods=["POST"])
def test_connection():
    prom_url = Setting.get("prometheus_url", "")
    if not prom_url:
        return jsonify({"ok": False, "error": "Prometheus URL is not configured"})

    try:
        from clients.prometheus_query import PrometheusQueryClient
        client = PrometheusQueryClient(base_url=prom_url)
        ok = client.check_connection()
        if ok:
            return jsonify({"ok": True, "message": "Connection successful"})
        return jsonify({"ok": False, "error": "Prometheus is not reachable"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.prometheus_app import detect_prometheus_version

    guest_id = Setting.get("prometheus_guest_id", "")
    if not guest_id:
        flash("Prometheus guest is not configured.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid guest ID.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if not guest:
        flash("Guest not found.", "error")
        return redirect(url_for("prometheus_app.manage"))

    version, error = detect_prometheus_version(guest)
    if version:
        Setting.set("prometheus_current_version", version)
        if Setting.get("prometheus_installed") != "true":
            Setting.set("prometheus_installed", "true")
        db.session.commit()
        flash(f"Detected Prometheus version: {version}", "success")
    else:
        if Setting.get("prometheus_installed") == "true":
            Setting.set("prometheus_installed", "false")
            Setting.set("prometheus_current_version", "")
            db.session.commit()
            flash(f"Prometheus not found on guest: {error}. Marked as not installed.", "warning")
        else:
            flash(f"Could not detect Prometheus version: {error}", "warning")

    return redirect(url_for("prometheus_app.manage"))


@bp.route("/install/status")
def install_status():
    return jsonify({
        "running": _install_job["running"],
        "success": _install_job["success"],
        "log": _install_job["log"],
    })


@bp.route("/upgrade/status")
def upgrade_status():
    return jsonify({
        "running": _upgrade_job["running"],
        "success": _upgrade_job["success"],
        "log": _upgrade_job["log"],
    })


@bp.route("/install", methods=["POST"])
def install():
    from apps.prometheus_app import run_prometheus_install
    from flask import current_app

    if _install_job["running"] or _upgrade_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _install_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _install_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_prometheus_install(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _install_job["running"] = False
        _install_job["success"] = ok
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("prometheus_last_install_at", now)
            Setting.set("prometheus_last_install_status", "success" if ok else "error")
            Setting.set("prometheus_last_install_log", "\n".join(_install_job["log"]))
            if ok:
                Setting.set("prometheus_installed", "true")
            log_action("prometheus_install", "settings", resource_name="prometheus",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("prometheus_app.manage"))


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from apps.prometheus_app import run_prometheus_upgrade
    from flask import current_app

    if _install_job["running"] or _upgrade_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _upgrade_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_prometheus_upgrade(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("prometheus_last_upgrade_at", now)
            Setting.set("prometheus_last_upgrade_status", "success" if ok else "error")
            Setting.set("prometheus_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("prometheus_upgrade", "settings", resource_name="prometheus",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("prometheus_app.manage"))
