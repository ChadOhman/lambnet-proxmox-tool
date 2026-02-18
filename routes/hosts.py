import re
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, ProxmoxHost, Guest, Tag
from credential_store import encrypt
from proxmox_api import ProxmoxClient

bp = Blueprint("hosts", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_manage_hosts:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    hosts = ProxmoxHost.query.all()
    return render_template("hosts.html", hosts=hosts)


@bp.route("/add", methods=["POST"])
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
def discover(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)
    client = ProxmoxClient(host)

    try:
        # Discover guests only on this host's node (not the entire cluster)
        node_name = client.get_local_node_name()
        if node_name:
            node_guests = client.get_node_guests(node_name)
        else:
            # Fallback: if we can't determine the local node, get all guests
            node_guests = client.get_all_guests()
            node_name = "cluster"

        # Fetch replication info (VMID -> target node)
        repl_map = client.get_replication_map()

        # Clean up duplicates: remove guests on THIS host whose VMID
        # is not actually present on this node (leftover from cluster-wide discovery)
        node_vmids = {g.get("vmid") for g in node_guests}
        stale = Guest.query.filter(
            Guest.proxmox_host_id == host.id,
            Guest.vmid.isnot(None),
            ~Guest.vmid.in_(node_vmids),
        ).all()
        removed = 0
        for s in stale:
            db.session.delete(s)
            removed += 1

        added = 0
        updated = 0
        skipped = 0
        for g in node_guests:
            vmid = g.get("vmid")
            status = g.get("status", "")

            # Check if this guest already exists on THIS host
            existing = Guest.query.filter_by(proxmox_host_id=host.id, vmid=vmid).first()

            # Check if this VMID already exists on ANOTHER host (replication)
            if not existing:
                other = Guest.query.filter(Guest.vmid == vmid, Guest.proxmox_host_id != host.id).first()
                if other:
                    # Replicated guest — only claim it if it's running here
                    if status != "running":
                        skipped += 1
                        continue
                    # It's running on this node — move ownership from the other host
                    existing = other
                    existing.proxmox_host_id = host.id

            # Parse tags - Proxmox uses semicolons (PVE 8+) or commas (older)
            proxmox_tags = g.get("tags", "")
            tag_names = [t.strip() for t in re.split(r"[;,]", proxmox_tags) if t.strip()] if proxmox_tags else []

            # Only fetch IP for running guests (skip stopped ones for speed)
            ip = None
            if status == "running":
                ip = client.get_guest_ip(g["node"], vmid, g["type"])

            repl_target = repl_map.get(vmid)

            if not existing:
                guest = Guest(
                    proxmox_host_id=host.id,
                    vmid=vmid,
                    name=g.get("name", f"guest-{vmid}"),
                    guest_type=g["type"],
                    ip_address=ip,
                    connection_method="auto",
                    replication_target=repl_target,
                )
                db.session.add(guest)
                added += 1

                for tag_name in tag_names:
                    tag = Tag.query.filter_by(name=tag_name).first()
                    if not tag:
                        tag = Tag(name=tag_name)
                        db.session.add(tag)
                    guest.tags.append(tag)
            else:
                # Update IP, name, replication, and tags for existing guests
                if ip:
                    existing.ip_address = ip
                existing.name = g.get("name", existing.name)
                existing.replication_target = repl_target
                existing.tags.clear()
                for tag_name in tag_names:
                    tag = Tag.query.filter_by(name=tag_name).first()
                    if not tag:
                        tag = Tag(name=tag_name)
                        db.session.add(tag)
                    existing.tags.append(tag)
                updated += 1

        db.session.commit()
        if len(node_guests) == 0:
            flash(
                f"No guests found on node '{node_name}' for host '{host.name}'. "
                "Check that VMs/CTs exist and that the API token has VM.Audit permission.",
                "warning",
            )
        else:
            msg = f"Discovered {len(node_guests)} guests on '{host.name}' node '{node_name}' ({added} new, {updated} updated)"
            if skipped:
                msg += f", {skipped} replicas skipped"
            if removed:
                msg += f", {removed} stale removed"
            flash(msg + ".", "success")
    except Exception as e:
        flash(f"Discovery failed for '{host.name}': {e}", "error")

    return redirect(url_for("hosts.index"))


@bp.route("/<int:host_id>/delete", methods=["POST"])
def delete(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)
    name = host.name
    db.session.delete(host)
    db.session.commit()
    flash(f"Host '{name}' deleted.", "warning")
    return redirect(url_for("hosts.index"))
