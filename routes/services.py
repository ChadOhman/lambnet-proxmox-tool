from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import db, Guest, GuestService
from scanner import check_service_statuses, service_action, get_service_logs, get_service_stats

bp = Blueprint("services", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    service_filter = request.args.get("service", "")
    query = GuestService.query.join(Guest).filter(Guest.enabled == True)
    if service_filter:
        query = query.filter(GuestService.service_name == service_filter)
    services = query.order_by(Guest.name, GuestService.service_name).all()

    service_types = sorted(set(s.service_name for s in GuestService.query.all()))
    return render_template("services.html", services=services,
                           service_types=service_types, current_filter=service_filter)


@bp.route("/<int:service_id>/<action>", methods=["POST"])
def control(service_id, action):
    if action not in ("start", "stop", "restart"):
        flash("Invalid action.", "error")
        return redirect(url_for("services.index"))

    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest

    ok, msg = service_action(guest, svc, action)
    if ok:
        flash(f"{action.capitalize()} sent for {svc.service_name} on {guest.name}.", "success")
    else:
        flash(f"Failed to {action} {svc.service_name} on {guest.name}: {msg}", "error")

    referrer = request.referrer
    if referrer and f"/guests/{guest.id}" in referrer:
        return redirect(url_for("guests.detail", guest_id=guest.id))
    return redirect(url_for("services.index"))


@bp.route("/<int:service_id>/logs", methods=["POST"])
def logs(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    log_text = get_service_logs(guest, svc)
    return jsonify({"logs": log_text, "service": svc.service_name, "guest": guest.name})


@bp.route("/refresh", methods=["POST"])
def refresh_all():
    guests = Guest.query.filter(Guest.enabled == True, Guest.services.any()).all()
    checked = 0
    for guest in guests:
        try:
            check_service_statuses(guest)
            checked += 1
        except Exception:
            pass
    flash(f"Service statuses refreshed for {checked} guest(s).", "success")

    referrer = request.referrer
    if referrer and "/guests/" in referrer:
        return redirect(referrer)
    return redirect(url_for("services.index"))


@bp.route("/<int:guest_id>/assign", methods=["POST"])
def assign(guest_id):
    guest = Guest.query.get_or_404(guest_id)
    service_key = request.form.get("service_key", "").strip()

    if service_key not in GuestService.KNOWN_SERVICES:
        flash("Unknown service type.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    existing = GuestService.query.filter_by(guest_id=guest.id, service_name=service_key).first()
    if existing:
        flash(f"{existing.service_name} is already assigned to {guest.name}.", "warning")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    display_name, unit_name, default_port = GuestService.KNOWN_SERVICES[service_key]
    svc = GuestService(
        guest_id=guest.id,
        service_name=service_key,
        unit_name=unit_name,
        port=default_port,
        auto_detected=False,
    )
    db.session.add(svc)
    db.session.commit()

    flash(f"{display_name} assigned to {guest.name}.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:service_id>/remove", methods=["POST"])
def remove(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest_id = svc.guest_id
    name = svc.service_name
    db.session.delete(svc)
    db.session.commit()
    flash(f"Service '{name}' removed.", "warning")

    referrer = request.referrer
    if referrer and f"/guests/{guest_id}" in referrer:
        return redirect(url_for("guests.detail", guest_id=guest_id))
    return redirect(url_for("services.index"))


@bp.route("/<int:service_id>/detail")
def detail(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    stats = get_service_stats(guest, svc)
    log_text = get_service_logs(guest, svc, lines=30)
    return render_template("service_detail.html", service=svc, guest=guest, stats=stats, logs=log_text)


@bp.route("/<int:service_id>/stats")
def stats(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    data = get_service_stats(guest, svc)
    return jsonify(data)
