from flask import Blueprint, render_template, request, session, current_app
from flask_login import login_required, current_user
from collections import Counter
from models import db, ProxmoxHost, Guest, GuestService, UpdatePackage, ScanResult, Setting, Tag

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    # Tag filter (shared with guests/terminal pages via session)
    tag_filter = request.args.get("tag", None)
    user_tag_names = [t.name for t in current_user.allowed_tags]

    if tag_filter is not None:
        session["guest_tag_filter"] = tag_filter
    elif "guest_tag_filter" in session:
        tag_filter = session["guest_tag_filter"]
    elif user_tag_names:
        tag_filter = "__my_tags__"
    else:
        tag_filter = ""

    # Build base guest query with access control
    if current_user.is_admin:
        base_query = Guest.query.filter_by(enabled=True)
    else:
        user_tag_ids = [t.id for t in current_user.allowed_tags]
        if not user_tag_ids:
            base_query = Guest.query.filter(False)
        else:
            base_query = Guest.query.filter_by(enabled=True).filter(
                Guest.tags.any(Tag.id.in_(user_tag_ids))
            )

    # Apply tag filter
    if tag_filter == "__my_tags__":
        base_query = base_query.filter(Guest.tags.any(Tag.name.in_(user_tag_names)))
    elif tag_filter:
        base_query = base_query.filter(Guest.tags.any(Tag.name == tag_filter))

    filtered_guests = base_query.all()
    filtered_guest_ids = [g.id for g in filtered_guests]

    total_guests = len(filtered_guests)
    guests_with_updates = [g for g in filtered_guests if g.status == "updates-available"]

    total_hosts = ProxmoxHost.query.count()

    if filtered_guest_ids:
        total_updates = UpdatePackage.query.filter(
            UpdatePackage.status == "pending",
            UpdatePackage.guest_id.in_(filtered_guest_ids),
        ).count()
        security_updates = UpdatePackage.query.filter(
            UpdatePackage.status == "pending",
            UpdatePackage.severity == "critical",
            UpdatePackage.guest_id.in_(filtered_guest_ids),
        ).count()
        recent_scans = (
            ScanResult.query.filter(ScanResult.guest_id.in_(filtered_guest_ids))
            .order_by(ScanResult.scanned_at.desc())
            .limit(20)
            .all()
        )
    else:
        total_updates = 0
        security_updates = 0
        recent_scans = []

    reboot_required = [g for g in filtered_guests if g.reboot_required]

    # Power state breakdown
    power_states = Counter(g.power_state for g in filtered_guests)

    # Guest type breakdown
    guest_types = Counter(g.guest_type for g in filtered_guests)

    # Update status breakdown
    status_counts = Counter(g.status for g in filtered_guests)
    guests_never_scanned = sum(1 for g in filtered_guests if g.last_scan is None)

    # Auto-update coverage
    auto_update_enabled = sum(1 for g in filtered_guests if g.auto_update)

    # Service health
    total_services = 0
    services_running = 0
    services_failed = 0
    if filtered_guest_ids:
        svc_statuses = db.session.query(GuestService.status, db.func.count()).filter(
            GuestService.guest_id.in_(filtered_guest_ids)
        ).group_by(GuestService.status).all()
        for svc_status, count in svc_statuses:
            total_services += count
            if svc_status == "running":
                services_running += count
            elif svc_status == "failed":
                services_failed += count

    stats = {
        "total_hosts": total_hosts,
        "total_guests": total_guests,
        "total_updates": total_updates,
        "security_updates": security_updates,
        "reboot_required": len(reboot_required),
        "guests_running": power_states.get("running", 0),
        "guests_stopped": power_states.get("stopped", 0),
        "vms": guest_types.get("vm", 0),
        "containers": guest_types.get("ct", 0),
        "guests_up_to_date": status_counts.get("up-to-date", 0),
        "guests_error": status_counts.get("error", 0),
        "guests_never_scanned": guests_never_scanned,
        "auto_update_enabled": auto_update_enabled,
        "total_services": total_services,
        "services_running": services_running,
        "services_failed": services_failed,
    }

    tags = Tag.query.order_by(Tag.name).all()

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
        guests_needing_reboot=reboot_required,
        recent_scans=recent_scans,
        app_update_available=app_update_available,
        tags=tags,
        current_tag=tag_filter,
        user_tag_names=user_tag_names,
    )
