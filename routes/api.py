from flask import Blueprint, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models import db, Guest
from scanner import scan_guest, scan_all_guests, apply_updates
from notifier import send_update_notification

bp = Blueprint("api", __name__)


@bp.route("/scan/<int:guest_id>", methods=["POST"])
@login_required
def scan_single(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    # Check permission
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to scan this guest.", "error")
        return redirect(url_for("guests.index"))

    result = scan_guest(guest)
    if result.status == "success":
        flash(f"Scan complete for '{guest.name}': {result.total_updates} update(s) found.", "success")
    else:
        flash(f"Scan failed for '{guest.name}': {result.error_message}", "error")

    referrer = request.referrer
    if referrer and f"/guests/{guest_id}" in referrer:
        return redirect(url_for("guests.detail", guest_id=guest_id))
    return redirect(url_for("dashboard.index"))


@bp.route("/scan-all", methods=["POST"])
@login_required
def scan_all():
    if not current_user.is_admin:
        flash("Only admins can scan all guests.", "error")
        return redirect(url_for("dashboard.index"))

    results = scan_all_guests()
    total = len(results)
    errors = sum(1 for r in results if r.status == "error")

    send_update_notification(results)

    if errors:
        flash(f"Scan complete: {total} guest(s) scanned, {errors} error(s).", "warning")
    else:
        flash(f"Scan complete: {total} guest(s) scanned successfully.", "success")

    return redirect(url_for("dashboard.index"))


@bp.route("/apply/<int:guest_id>", methods=["POST"])
@login_required
def apply(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to update this guest.", "error")
        return redirect(url_for("guests.index"))

    # Snapshot gating for non-admin users
    if not current_user.is_admin:
        from routes.guests import guest_requires_snapshot, auto_snapshot_if_needed
        if guest_requires_snapshot(guest):
            ok, msg = auto_snapshot_if_needed(guest)
            if not ok:
                flash(f"Cannot apply updates: snapshot required but failed — {msg}", "error")
                referrer = request.referrer
                if referrer and f"/guests/{guest_id}" in referrer:
                    return redirect(url_for("guests.detail", guest_id=guest_id))
                return redirect(url_for("dashboard.index"))

    ok, output = apply_updates(guest)
    if ok:
        flash(f"Updates applied to '{guest.name}' successfully.", "success")
    else:
        flash(f"Failed to apply updates to '{guest.name}': {output}", "error")

    referrer = request.referrer
    if referrer and f"/guests/{guest_id}" in referrer:
        return redirect(url_for("guests.detail", guest_id=guest_id))
    return redirect(url_for("dashboard.index"))
