from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, Guest, ProxmoxHost, Credential, Tag

bp = Blueprint("guests", __name__)


@bp.route("/")
@login_required
def index():
    if current_user.is_admin:
        guests = Guest.query.order_by(Guest.name).all()
    else:
        guests = current_user.accessible_guests()

    hosts = ProxmoxHost.query.all()
    credentials = Credential.query.all()
    tags = Tag.query.order_by(Tag.name).all()
    return render_template("guests.html", guests=guests, hosts=hosts, credentials=credentials, tags=tags)


@bp.route("/add", methods=["POST"])
@login_required
def add():
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("guests.index"))

    name = request.form.get("name", "").strip()
    guest_type = request.form.get("guest_type", "vm")
    ip_address = request.form.get("ip_address", "").strip()
    connection_method = request.form.get("connection_method", "ssh")

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("guests.index"))

    guest = Guest(
        name=name,
        guest_type=guest_type,
        ip_address=ip_address or None,
        connection_method=connection_method,
    )

    host_id = request.form.get("proxmox_host_id")
    if host_id:
        guest.proxmox_host_id = int(host_id)

    vmid = request.form.get("vmid")
    if vmid:
        guest.vmid = int(vmid)

    cred_id = request.form.get("credential_id")
    if cred_id:
        guest.credential_id = int(cred_id)

    # Assign tags
    tag_ids = request.form.getlist("tag_ids")
    if tag_ids:
        tags = Tag.query.filter(Tag.id.in_([int(t) for t in tag_ids])).all()
        guest.tags = tags

    db.session.add(guest)
    db.session.commit()

    flash(f"Guest '{name}' added.", "success")
    return redirect(url_for("guests.index"))


@bp.route("/<int:guest_id>")
@login_required
def detail(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to view this guest.", "error")
        return redirect(url_for("guests.index"))

    credentials = Credential.query.all()
    tags = Tag.query.order_by(Tag.name).all()
    return render_template("guest_detail.html", guest=guest, credentials=credentials, tags=tags)


@bp.route("/<int:guest_id>/edit", methods=["POST"])
@login_required
def edit(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    guest.ip_address = request.form.get("ip_address", "").strip() or None
    guest.connection_method = request.form.get("connection_method", "ssh")
    guest.auto_update = "auto_update" in request.form

    cred_id = request.form.get("credential_id")
    guest.credential_id = int(cred_id) if cred_id else None

    # Update tags
    tag_ids = request.form.getlist("tag_ids")
    if tag_ids:
        tags = Tag.query.filter(Tag.id.in_([int(t) for t in tag_ids])).all()
        guest.tags = tags
    else:
        guest.tags = []

    db.session.commit()
    flash(f"Guest '{guest.name}' updated.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/delete", methods=["POST"])
@login_required
def delete(guest_id):
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("guests.index"))

    guest = Guest.query.get_or_404(guest_id)
    name = guest.name
    db.session.delete(guest)
    db.session.commit()
    flash(f"Guest '{name}' deleted.", "warning")
    return redirect(url_for("guests.index"))
