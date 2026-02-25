import logging
import re
import threading as _threading
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models import db, ProxmoxHost, Guest, Tag, AuditLog, Credential
from credential_store import encrypt
from proxmox_api import ProxmoxClient
from audit import log_action

# In-memory state for SSH-based apt apply jobs
_apply_jobs = {}   # host_id -> {"log": [], "running": bool, "success": bool|None, "cancelled": bool}
_apply_lock = _threading.Lock()

logger = logging.getLogger(__name__)

bp = Blueprint("hosts", __name__)


@bp.before_request
@login_required
def _require_login():
    # Read-only routes require can_view_hosts (or can_manage_hosts)
    # Discover routes require super_admin
    # Update management read routes require can_view_hosts
    # Update management write routes require can_manage_hosts
    read_only_endpoints = {
        "hosts.index", "hosts.detail",
        "hosts.get_updates", "hosts.task_status", "hosts.task_log",
        "hosts.apply_progress", "hosts.apply_status",
    }
    discover_endpoints = {"hosts.discover", "hosts.discover_all"}
    if request.endpoint in read_only_endpoints:
        if not current_user.can_view_hosts and not current_user.can_manage_hosts:
            flash("Access denied.", "error")
            return redirect(url_for("dashboard.index"))
    elif request.endpoint in discover_endpoints:
        if not current_user.is_super_admin:
            flash("Super admin access required.", "error")
            return redirect(url_for("hosts.index"))
    else:
        if not current_user.can_manage_hosts:
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    hosts = ProxmoxHost.query.all()
    return render_template("hosts.html", hosts=hosts)


@bp.route("/<int:host_id>")
def detail(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)

    node_status = None
    node_name = None
    error = None

    if host.is_pbs:
        from pbs_client import PBSClient
        datastores = []
        try:
            client = PBSClient(host)
            node_status = client.get_node_status()
            node_name = client.get_node_name()
            datastores = client.get_all_datastores_with_status()
        except Exception as e:
            error = str(e)

        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        pbs_recent_logs = (AuditLog.query
                           .filter(AuditLog.resource_type == "host",
                                   AuditLog.resource_id == host.id,
                                   AuditLog.timestamp >= cutoff)
                           .order_by(AuditLog.timestamp.desc())
                           .limit(25).all())
        credentials = Credential.query.order_by(Credential.name).all()
        return render_template(
            "host_detail.html",
            host=host,
            node_name=node_name,
            node_status=node_status,
            node_storage=[],
            guests=[],
            datastores=datastores,
            error=error,
            recent_logs=pbs_recent_logs,
            credentials=credentials,
        )

    # PVE host
    node_storage = []
    try:
        client = ProxmoxClient(host)
        node_name = client.get_local_node_name()
        if node_name:
            node_status = client.get_node_status(node_name)
            node_storage = client.get_node_storage(node_name)
        else:
            error = "Could not determine node name."
    except Exception as e:
        error = str(e)

    # Filter guests by user's tag-based access
    all_host_guests = Guest.query.filter_by(proxmox_host_id=host.id, enabled=True).order_by(Guest.name).all()
    guests = [g for g in all_host_guests if current_user.can_access_guest(g)]

    # Recent audit activity for this host (last 7 days)
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent_logs = (AuditLog.query
                   .filter(AuditLog.resource_type == "host",
                           AuditLog.resource_id == host.id,
                           AuditLog.timestamp >= cutoff)
                   .order_by(AuditLog.timestamp.desc())
                   .limit(25).all())

    credentials = Credential.query.order_by(Credential.name).all()
    return render_template(
        "host_detail.html",
        host=host,
        node_name=node_name,
        node_status=node_status,
        node_storage=node_storage,
        guests=guests,
        datastores=[],
        error=error,
        recent_logs=recent_logs,
        credentials=credentials,
    )


@bp.route("/add", methods=["POST"])
def add():
    name = request.form.get("name", "").strip()
    hostname = request.form.get("hostname", "").strip()
    host_type = request.form.get("host_type", "pve")
    if host_type not in ("pve", "pbs"):
        host_type = "pve"
    default_port = 8007 if host_type == "pbs" else 8006
    try:
        port = int(request.form.get("port", default_port))
    except (TypeError, ValueError):
        flash("Invalid port number.", "error")
        return redirect(url_for("hosts.index"))
    auth_type = request.form.get("auth_type", "token")
    default_user = "root@pbs" if host_type == "pbs" else "root@pam"
    username = request.form.get("username", default_user).strip()
    verify_ssl = "verify_ssl" in request.form

    if not name or not hostname:
        flash("Name and hostname are required.", "error")
        return redirect(url_for("hosts.index"))

    host = ProxmoxHost(
        name=name,
        hostname=hostname,
        port=port,
        host_type=host_type,
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
    db.session.flush()
    log_action("host_add", "host", resource_id=host.id, resource_name=host.name)
    db.session.commit()

    flash(f"Host '{name}' added successfully.", "success")
    return redirect(url_for("hosts.index"))


@bp.route("/<int:host_id>/test", methods=["POST"])
def test_connection(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)

    if host.is_pbs:
        from pbs_client import PBSClient
        client = PBSClient(host)
    else:
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

    if host.is_pbs:
        flash(f"'{host.name}' is a Proxmox Backup Server — guest discovery is not applicable.", "warning")
        return redirect(url_for("hosts.index"))

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
                # Safety: don't store invalid IP values
                if ip and ip.lower() in ("dhcp", "dhcp6", "auto"):
                    ip = None

            repl_target = repl_map.get(vmid)
            mac = client.get_guest_mac(g["node"], vmid, g["type"])

            # Normalize power state from Proxmox status
            power_state = status if status in ("running", "stopped", "paused") else "unknown"

            if not existing:
                guest = Guest(
                    proxmox_host_id=host.id,
                    vmid=vmid,
                    name=g.get("name", f"guest-{vmid}"),
                    guest_type=g["type"],
                    ip_address=ip,
                    connection_method="auto",
                    replication_target=repl_target,
                    mac_address=mac,
                    power_state=power_state,
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
                # Update IP, name, replication, MAC, power state, and tags
                if ip:
                    existing.ip_address = ip
                existing.name = g.get("name", existing.name)
                existing.replication_target = repl_target
                existing.power_state = power_state
                if mac:
                    existing.mac_address = mac
                existing.tags.clear()
                for tag_name in tag_names:
                    tag = Tag.query.filter_by(name=tag_name).first()
                    if not tag:
                        tag = Tag(name=tag_name)
                        db.session.add(tag)
                    existing.tags.append(tag)
                updated += 1

        log_action("host_discover", "host", resource_id=host.id, resource_name=host.name,
                   details={"added": added, "updated": updated, "removed": removed})
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


@bp.route("/discover-all", methods=["POST"])
def discover_all():
    hosts = ProxmoxHost.query.all()
    if not hosts:
        flash("No hosts configured.", "warning")
        return redirect(url_for("hosts.index"))

    for host in hosts:
        if host.is_pbs:
            continue  # PBS hosts have no VMs/CTs to discover
        try:
            client = ProxmoxClient(host)
            node_name = client.get_local_node_name()
            if node_name:
                node_guests = client.get_node_guests(node_name)
            else:
                node_guests = client.get_all_guests()
                node_name = "cluster"

            repl_map = client.get_replication_map()

            node_vmids = {g.get("vmid") for g in node_guests}
            stale = Guest.query.filter(
                Guest.proxmox_host_id == host.id,
                Guest.vmid.isnot(None),
                ~Guest.vmid.in_(node_vmids),
            ).all()
            for s in stale:
                db.session.delete(s)

            added = 0
            updated = 0
            for g in node_guests:
                vmid = g.get("vmid")
                status = g.get("status", "")

                existing = Guest.query.filter_by(proxmox_host_id=host.id, vmid=vmid).first()

                if not existing:
                    other = Guest.query.filter(Guest.vmid == vmid, Guest.proxmox_host_id != host.id).first()
                    if other:
                        if status != "running":
                            continue
                        existing = other
                        existing.proxmox_host_id = host.id

                proxmox_tags = g.get("tags", "")
                tag_names = [t.strip() for t in re.split(r"[;,]", proxmox_tags) if t.strip()] if proxmox_tags else []

                ip = None
                if status == "running":
                    ip = client.get_guest_ip(g["node"], vmid, g["type"])
                    if ip and ip.lower() in ("dhcp", "dhcp6", "auto"):
                        ip = None

                repl_target = repl_map.get(vmid)
                mac = client.get_guest_mac(g["node"], vmid, g["type"])
                power_state = status if status in ("running", "stopped", "paused") else "unknown"

                if not existing:
                    guest = Guest(
                        proxmox_host_id=host.id,
                        vmid=vmid,
                        name=g.get("name", f"guest-{vmid}"),
                        guest_type=g["type"],
                        ip_address=ip,
                        connection_method="auto",
                        replication_target=repl_target,
                        mac_address=mac,
                        power_state=power_state,
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
                    if ip:
                        existing.ip_address = ip
                    existing.name = g.get("name", existing.name)
                    existing.replication_target = repl_target
                    existing.power_state = power_state
                    if mac:
                        existing.mac_address = mac
                    existing.tags.clear()
                    for tag_name in tag_names:
                        tag = Tag.query.filter_by(name=tag_name).first()
                        if not tag:
                            tag = Tag(name=tag_name)
                            db.session.add(tag)
                        existing.tags.append(tag)
                    updated += 1

            log_action("host_discover", "host", resource_id=host.id, resource_name=host.name,
                       details={"added": added, "updated": updated})
            db.session.commit()
            flash(f"'{host.name}': {len(node_guests)} guests ({added} new, {updated} updated).", "success")
        except Exception as e:
            flash(f"Discovery failed for '{host.name}': {e}", "error")

    log_action("host_discover_all", "system", resource_name="all hosts")
    db.session.commit()
    return redirect(url_for("hosts.index"))


@bp.route("/<int:host_id>/delete", methods=["POST"])
def delete(host_id):
    host = ProxmoxHost.query.get_or_404(host_id)
    name = host.name
    log_action("host_delete", "host", resource_id=host.id, resource_name=name)
    db.session.delete(host)
    db.session.commit()
    flash(f"Host '{name}' deleted.", "warning")
    return redirect(url_for("hosts.index"))


# ---------------------------------------------------------------------------
# Update management
# ---------------------------------------------------------------------------

def _get_client_and_node(host):
    """Return (client, node_name) for PVE or PBS host."""
    if host.is_pbs:
        from pbs_client import PBSClient
        client = PBSClient(host)
        return client, client.get_node_name()
    else:
        client = ProxmoxClient(host)
        node_name = client.get_local_node_name()
        return client, node_name


@bp.route("/<int:host_id>/updates")
def get_updates(host_id):
    """JSON: list of pending apt packages for this host."""
    host = ProxmoxHost.query.get_or_404(host_id)
    try:
        client, node_name = _get_client_and_node(host)
        if host.is_pbs:
            updates = client.get_apt_updates()
        else:
            updates = client.get_apt_updates(node_name) if node_name else []
        return jsonify({"updates": updates, "count": len(updates), "node": node_name})
    except Exception:
        logger.exception("Error fetching updates for host %s", host_id)
        return jsonify({"error": "Failed to fetch updates.", "updates": [], "count": 0}), 500


@bp.route("/<int:host_id>/updates/refresh", methods=["POST"])
def refresh_updates(host_id):
    """Trigger apt-get update via API. Returns UPID + node_name for task polling."""
    host = ProxmoxHost.query.get_or_404(host_id)
    try:
        client, node_name = _get_client_and_node(host)
        if host.is_pbs:
            upid = client.refresh_apt_cache()
        else:
            if not node_name:
                return jsonify({"error": "Could not determine node name"}), 500
            upid = client.refresh_apt_cache(node_name)
        log_action("host_refresh_updates", "host", resource_id=host.id, resource_name=host.name)
        db.session.commit()
        return jsonify({"upid": upid, "node": node_name})
    except Exception:
        logger.exception("Error refreshing apt cache for host %s", host_id)
        return jsonify({"error": "Failed to refresh apt cache."}), 500


@bp.route("/<int:host_id>/task/<path:upid>/status")
def task_status(host_id, upid):
    """JSON: poll a Proxmox task status by UPID."""
    host = ProxmoxHost.query.get_or_404(host_id)
    try:
        client, node_name = _get_client_and_node(host)
        if host.is_pbs:
            status = client.get_task_status(upid)
        else:
            status = client.get_task_status(node_name, upid)
        return jsonify(status or {})
    except Exception:
        logger.exception("Error fetching task status for host %s upid %s", host_id, upid)
        return jsonify({"error": "Failed to fetch task status."}), 500


@bp.route("/<int:host_id>/task/<path:upid>/log")
def task_log(host_id, upid):
    """JSON: get log lines for a Proxmox task."""
    host = ProxmoxHost.query.get_or_404(host_id)
    try:
        start = max(0, int(request.args.get("start", 0)))
        limit = min(1000, max(1, int(request.args.get("limit", 500))))
    except (ValueError, TypeError):
        start, limit = 0, 500
    try:
        client, node_name = _get_client_and_node(host)
        if host.is_pbs:
            lines = client.get_task_log(upid, start=start, limit=limit)
        else:
            lines = client.get_task_log(node_name, upid, start=start, limit=limit)
        return jsonify({"lines": lines or []})
    except Exception:
        logger.exception("Error fetching task log for host %s upid %s", host_id, upid)
        return jsonify({"error": "Failed to fetch task log."}), 500


def _run_apply(host_id, hostname, credential_model, app_ctx):
    """Background thread: SSH to host and run apt-get dist-upgrade."""
    from ssh_client import SSHClient

    def _append(chunk):
        with _apply_lock:
            job = _apply_jobs.get(host_id)
            if job:
                job["log"].append(chunk)

    def _stop_fn():
        with _apply_lock:
            job = _apply_jobs.get(host_id)
            return bool(job and job.get("cancelled"))

    with app_ctx.app_context():
        try:
            client = SSHClient.from_credential(hostname, credential_model)
            cmd = "DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade 2>&1"
            exit_code = client.execute_streaming(cmd, _append, timeout=1800, stop_fn=_stop_fn)
            success = exit_code == 0
        except Exception as e:
            _append(f"\n[Error: {e}]\n")
            success = False
        finally:
            try:
                client.close()
            except Exception:
                pass

        with _apply_lock:
            job = _apply_jobs.get(host_id)
            if job:
                job["running"] = False
                job["success"] = success


@bp.route("/<int:host_id>/updates/apply", methods=["POST"])
def apply_updates(host_id):
    """Start SSH-based apt upgrade job and redirect to progress page."""
    host = ProxmoxHost.query.get_or_404(host_id)

    if not host.ssh_credential:
        flash("No SSH credential configured for this host. Set one below to enable applying updates.", "error")
        return redirect(url_for("hosts.detail", host_id=host_id))

    with _apply_lock:
        existing = _apply_jobs.get(host_id)
        if existing and existing.get("running"):
            flash("An update job is already running for this host.", "warning")
            return redirect(url_for("hosts.apply_progress", host_id=host_id))
        _apply_jobs[host_id] = {"log": [], "running": True, "success": None, "cancelled": False}

    from flask import current_app
    t = _threading.Thread(
        target=_run_apply,
        args=(host_id, host.hostname, host.ssh_credential, current_app._get_current_object()),
        daemon=True,
    )
    t.start()

    log_action("host_apply_updates", "host", resource_id=host.id, resource_name=host.name)
    db.session.commit()
    return redirect(url_for("hosts.apply_progress", host_id=host_id))


@bp.route("/<int:host_id>/updates/apply/progress")
def apply_progress(host_id):
    """Render the SSH update progress page."""
    host = ProxmoxHost.query.get_or_404(host_id)
    return render_template("host_update_progress.html", host=host)


@bp.route("/<int:host_id>/updates/apply/status")
def apply_status(host_id):
    """JSON: current state of the SSH apply job."""
    with _apply_lock:
        job = _apply_jobs.get(host_id, {})
        return jsonify({
            "running": job.get("running", False),
            "success": job.get("success"),
            "cancelled": job.get("cancelled", False),
            "log": job.get("log", []),
        })


@bp.route("/<int:host_id>/updates/apply/cancel", methods=["POST"])
def apply_cancel(host_id):
    """Signal the running SSH apply job to stop."""
    with _apply_lock:
        job = _apply_jobs.get(host_id)
        if job and job.get("running"):
            job["cancelled"] = True
            return jsonify({"ok": True})
    return jsonify({"ok": False, "message": "No running job found."})


@bp.route("/<int:host_id>/ssh-credential", methods=["POST"])
def set_ssh_credential(host_id):
    """Save (or clear) the SSH credential linked to this host."""
    host = ProxmoxHost.query.get_or_404(host_id)
    credential_id = request.form.get("credential_id", "").strip()
    if credential_id:
        cred = Credential.query.get(int(credential_id))
        if not cred:
            flash("Credential not found.", "error")
            return redirect(url_for("hosts.detail", host_id=host_id))
        host.ssh_credential_id = cred.id
        log_action("host_set_ssh_credential", "host", resource_id=host.id, resource_name=host.name,
                   details={"credential": cred.name})
    else:
        host.ssh_credential_id = None
        log_action("host_clear_ssh_credential", "host", resource_id=host.id, resource_name=host.name)
    db.session.commit()
    flash("SSH credential updated.", "success")
    return redirect(url_for("hosts.detail", host_id=host_id))
