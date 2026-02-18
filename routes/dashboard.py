from flask import Blueprint, render_template, current_app
from flask_login import login_required, current_user
from models import db, ProxmoxHost, Guest, UpdatePackage, ScanResult, Setting

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    if current_user.is_admin:
        total_guests = Guest.query.filter_by(enabled=True).count()
        guests_with_updates = (
            Guest.query.filter_by(enabled=True)
            .filter(Guest.status == "updates-available")
            .all()
        )
    else:
        accessible = current_user.accessible_guests()
        total_guests = len(accessible)
        guests_with_updates = [g for g in accessible if g.status == "updates-available"]

    total_hosts = ProxmoxHost.query.count()
    total_updates = UpdatePackage.query.filter_by(status="pending").count()
    security_updates = UpdatePackage.query.filter_by(status="pending", severity="critical").count()

    stats = {
        "total_hosts": total_hosts,
        "total_guests": total_guests,
        "total_updates": total_updates,
        "security_updates": security_updates,
    }

    recent_scans = (
        ScanResult.query.order_by(ScanResult.scanned_at.desc())
        .limit(20)
        .all()
    )

    # Check for app update availability (for admins)
    app_update_available = None
    if current_user.is_admin:
        latest_version = Setting.get("latest_app_version")
        current_version = current_app.config.get("APP_VERSION", "unknown")
        is_stale = current_app.config.get("APP_VERSION_STALE", False)
        if latest_version and latest_version != current_version:
            app_update_available = latest_version
        elif is_stale and latest_version:
            app_update_available = latest_version

    return render_template(
        "dashboard.html",
        stats=stats,
        guests_with_updates=guests_with_updates,
        recent_scans=recent_scans,
        app_update_available=app_update_available,
    )
