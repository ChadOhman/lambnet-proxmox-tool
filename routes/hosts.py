from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, ProxmoxHost, Guest, Tag
from credential_store import encrypt
from proxmox_api import ProxmoxClient

bp = Blueprint("hosts", __name__)


def _admin_required():
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))
    return None


@bp.route("/")
@login_required
def index():
    r = _admin_required()
    if r:
        return r
    hosts = ProxmoxHost.query.all()
    return render_template("hosts.html", hosts=hosts)


@bp.route("/add", methods=["POST"])
@login_required
def add():
    name = request.form.get("name", "").strip()
    hostname = request.form.get("hostname", "").strip()
    port = int(request.form.get("port", 8006))
    auth_type = request.form.get("auth_type", "token")
    username = request.form.get("username", "root@pam").strip()
    verify_ssl = "verify_ssl" in request.form

    if not name or not hostname:
        flash("Name and hostname are required.", "error")
        return redirect(url_for("hosts.index"))

    host = ProxmoxHost(
        name=name,
        hostname=hostname,
        port=port,
        auth_type=auth_type,
        username=username,
        verify_ssl=verify_ssl,
    )

    if auth_type == "token":
        host.api_token_id = request.form.get("api_token_id", "").strip()
        host.api_token_secret = encrypt(request.form.get("api_token_secret", ""))
    else:
        host.encrypted_password = encrypt(request.form.get("password", ""))

    db.session.add(host)
    db.session.commit()

    flash(f"Host '{name}' added successfully.", "success")
    return redirect(url_for("hosts.index"))


@bp.route("/<int:host_id>/test", methods=["POST"])
@login_required
def test_connection(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)
    client = ProxmoxClient(host)
    ok, message = client.test_connection()

    if ok:
        flash(f"Connection to '{host.name}' successful: {message}", "success")
    else:
        flash(f"Connection to '{host.name}' failed: {message}", "error")

    return redirect(url_for("hosts.index"))


@bp.route("/<int:host_id>/discover", methods=["POST"])
@login_required
def discover(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)
    client = ProxmoxClient(host)

    try:
        all_guests = client.get_all_guests()
        added = 0
        for g in all_guests:
            vmid = g.get("vmid")
            existing = Guest.query.filter_by(proxmox_host_id=host.id, vmid=vmid).first()
            if not existing:
                ip = client.get_guest_ip(g["node"], vmid, g["type"])
                guest = Guest(
                    proxmox_host_id=host.id,
                    vmid=vmid,
                    name=g.get("name", f"guest-{vmid}"),
                    guest_type=g["type"],
                    ip_address=ip,
                    connection_method="auto",
                )
                db.session.add(guest)
                added += 1

                # Sync Proxmox tags if available
                proxmox_tags = g.get("tags", "")
                if proxmox_tags:
                    for tag_name in proxmox_tags.split(";"):
                        tag_name = tag_name.strip()
                        if tag_name:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            guest.tags.append(tag)
            else:
                # Update tags for existing guests
                proxmox_tags = g.get("tags", "")
                if proxmox_tags:
                    existing.tags.clear()
                    for tag_name in proxmox_tags.split(";"):
                        tag_name = tag_name.strip()
                        if tag_name:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            existing.tags.append(tag)

        db.session.commit()
        flash(f"Discovered {len(all_guests)} guests on '{host.name}' ({added} new). Tags synced.", "success")
    except Exception as e:
        flash(f"Discovery failed for '{host.name}': {e}", "error")

    return redirect(url_for("hosts.index"))


@bp.route("/<int:host_id>/delete", methods=["POST"])
@login_required
def delete(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)
    name = host.name
    db.session.delete(host)
    db.session.commit()
    flash(f"Host '{name}' deleted.", "warning")
    return redirect(url_for("hosts.index"))
