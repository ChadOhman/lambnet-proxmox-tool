import time
import threading
import logging
from datetime import datetime, timezone
from flask import Blueprint, redirect, url_for, flash, request, render_template, jsonify
from flask_login import login_required, current_user
from models import db, Guest, ProxmoxHost, Tag
from scanner import scan_guest, scan_all_guests
from notifier import send_update_notification
from audit import log_action

logger = logging.getLogger(__name__)

bp = Blueprint("api", __name__)

# In-memory store for running update jobs keyed by guest_id
_update_jobs = {}
_jobs_lock = threading.Lock()


class UpdateJob:
    """Tracks a background guest update."""

    def __init__(self, guest_id, guest_name):
        self.guest_id = guest_id
        self.guest_name = guest_name
        self.log = ""
        self.running = True
        self.success = None  # None=in progress, True=success, False=failed
        self.started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()

    def append(self, text):
        with self._lock:
            self.log += text

    def finish(self, success):
        with self._lock:
            self.running = False
            self.success = success

    def to_dict(self):
        with self._lock:
            return {
                "guest_id": self.guest_id,
                "guest_name": self.guest_name,
                "log": self.log,
                "running": self.running,
                "success": self.success,
                "started_at": self.started_at.isoformat(),
            }


def _run_update_background(app, guest_id, dist_upgrade=False):
    """Run apt upgrade in a background thread with streaming output."""
    from ssh_client import SSHClient
    from proxmox_api import ProxmoxClient

    with app.app_context():
        job = _update_jobs.get(guest_id)
        if not job:
            return

        guest = Guest.query.get(guest_id)
        if not guest:
            job.append("[Error] Guest not found.\n")
            job.finish(False)
            return

        cmd = (
            "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"
            if dist_upgrade
            else "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
        )

        try:
            # SSH path
            if guest.connection_method in ("ssh", "auto") and guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto"):
                credential = guest.credential
                if not credential:
                    from models import Credential
                    credential = Credential.query.filter_by(is_default=True).first()

                if credential:
                    job.append(f"Connecting to {guest.name} ({guest.ip_address}) via SSH...\n")
                    try:
                        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                            job.append("$ apt-get update\n")
                            update_code = ssh.execute_sudo_streaming(
                                "apt-get update", job.append, timeout=120
                            )
                            if update_code != 0:
                                job.append(f"\napt-get update exited with code {update_code}.\n")

                            job.append(f"\n$ {cmd}\n")
                            exit_code = ssh.execute_sudo_streaming(cmd, job.append, timeout=600)

                            if exit_code == 0:
                                job.append("\n\nUpdates applied successfully.\n")
                                now = datetime.now(timezone.utc)
                                for pkg in guest.pending_updates():
                                    pkg.status = "applied"
                                    pkg.applied_at = now
                                guest.status = "up-to-date"
                                db.session.commit()
                                job.finish(True)
                                return
                            else:
                                job.append(f"\n\napt exited with code {exit_code}.\n")
                                job.finish(False)
                                return
                    except Exception as e:
                        if guest.connection_method == "ssh":
                            job.append(f"\n[SSH Error] {e}\n")
                            job.finish(False)
                            return
                        job.append("SSH failed, trying guest agent...\n")

            # Guest agent path (non-streaming fallback)
            if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
                job.append(f"Connecting to {guest.name} via QEMU guest agent...\n")
                try:
                    client = ProxmoxClient(guest.proxmox_host)
                    all_guests = client.get_all_guests()
                    node = None
                    for g in all_guests:
                        if g.get("vmid") == guest.vmid:
                            node = g.get("node")
                            break

                    if node:
                        job.append("$ apt-get update\n")
                        update_out, update_err = client.exec_guest_agent(node, guest.vmid, "apt-get update")
                        if update_out:
                            job.append(update_out)
                        if update_err:
                            job.append(f"\n{update_err}\n")
                        job.append(f"\n$ {cmd}\n")
                        stdout, err = client.exec_guest_agent(node, guest.vmid, cmd)
                        if err is None:
                            if stdout:
                                job.append(stdout)
                            job.append("\n\nUpdates applied successfully.\n")
                            now = datetime.now(timezone.utc)
                            for pkg in guest.pending_updates():
                                pkg.status = "applied"
                                pkg.applied_at = now
                            guest.status = "up-to-date"
                            db.session.commit()
                            job.finish(True)
                            return
                        else:
                            job.append(f"\n[Agent Error] {err}\n")
                            job.finish(False)
                            return
                    else:
                        job.append(f"[Error] Could not find VM {guest.vmid} on any node.\n")
                        job.finish(False)
                        return
                except Exception as e:
                    job.append(f"\n[Agent Error] {e}\n")
                    job.finish(False)
                    return

            job.append("[Error] No viable connection method available.\n")
            job.finish(False)

        except Exception as e:
            logger.error(f"Background update error for guest {guest_id}: {e}", exc_info=True)
            job.append(f"\n[Unexpected Error] {e}\n")
            job.finish(False)


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
        log_action("guest_scan", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"updates_found": result.total_updates})
        db.session.commit()
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
    if not current_user.can_manage_guests:
        flash("Only admins can scan all guests.", "error")
        return redirect(url_for("dashboard.index"))

    results = scan_all_guests()
    total = len(results)
    errors = sum(1 for r in results if r.status == "error")

    send_update_notification(results)

    log_action("guest_scan_all", "system", resource_name="all guests",
               details={"total": total, "errors": errors})
    db.session.commit()

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

    # Check if an update is already running for this guest
    with _jobs_lock:
        existing = _update_jobs.get(guest_id)
        if existing and existing.running:
            flash(f"Updates are already being applied to '{guest.name}'.", "warning")
            return redirect(url_for("api.update_progress", guest_id=guest_id))

    dist_upgrade = request.form.get("dist_upgrade") == "1"

    log_action("guest_update", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"dist_upgrade": dist_upgrade})
    db.session.commit()

    # Create the job and start the background thread
    from flask import current_app
    app = current_app._get_current_object()

    job = UpdateJob(guest_id, guest.name)
    with _jobs_lock:
        _update_jobs[guest_id] = job

    thread = threading.Thread(
        target=_run_update_background,
        args=(app, guest_id, dist_upgrade),
        daemon=True,
    )
    thread.start()

    return redirect(url_for("api.update_progress", guest_id=guest_id))


@bp.route("/apply/<int:guest_id>/progress")
@login_required
def update_progress(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to view this guest.", "error")
        return redirect(url_for("guests.index"))

    job = _update_jobs.get(guest_id)
    if not job:
        flash("No update in progress for this guest.", "info")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    return render_template("guest_update_progress.html", guest=guest, job=job)


@bp.route("/apply/<int:guest_id>/status")
@login_required
def update_status(guest_id):
    job = _update_jobs.get(guest_id)
    if not job:
        return jsonify({"running": False, "log": "", "success": None})
    return jsonify(job.to_dict())


# ---------------------------------------------------------------------------
# Proxmox task tracking (backups, snapshots, rollbacks)
# ---------------------------------------------------------------------------

_proxmox_jobs = {}  # keyed by f"{job_type}:{guest_id}"
_proxmox_jobs_lock = threading.Lock()

JOB_TYPE_LABELS = {
    "backup": "Creating Backup",
    "snapshot": "Creating Snapshot",
    "snapshot_delete": "Deleting Snapshot",
    "rollback": "Rolling Back",
}


class ProxmoxJob:
    """Tracks a background Proxmox task (backup, snapshot, etc.)."""

    def __init__(self, guest_id, guest_name, job_type, upid, node, host_model):
        self.guest_id = guest_id
        self.guest_name = guest_name
        self.job_type = job_type
        self.upid = upid
        self.node = node
        self.host_model = host_model
        self.log = ""
        self.running = True
        self.success = None
        self.started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()
        self._last_log_line = 0

    @property
    def label(self):
        return JOB_TYPE_LABELS.get(self.job_type, self.job_type)

    def append(self, text):
        with self._lock:
            self.log += text

    def finish(self, success):
        with self._lock:
            self.running = False
            self.success = success

    def to_dict(self):
        with self._lock:
            return {
                "guest_id": self.guest_id,
                "guest_name": self.guest_name,
                "job_type": self.job_type,
                "label": self.label,
                "log": self.log,
                "running": self.running,
                "success": self.success,
                "started_at": self.started_at.isoformat(),
            }


def _poll_proxmox_task(app, job_key):
    """Poll Proxmox task status and accumulate log output."""
    from proxmox_api import ProxmoxClient

    with app.app_context():
        job = _proxmox_jobs.get(job_key)
        if not job:
            return

        try:
            client = ProxmoxClient(job.host_model)

            while True:
                time.sleep(2)

                try:
                    log_lines = client.get_task_log(job.node, job.upid, start=job._last_log_line)
                    for line in log_lines:
                        text = line.get("t", "")
                        if text:
                            job.append(text + "\n")
                        line_num = line.get("n", 0)
                        if line_num >= job._last_log_line:
                            job._last_log_line = line_num + 1
                except Exception as e:
                    logger.debug(f"Error fetching task log: {e}")

                try:
                    status = client.get_task_status(job.node, job.upid)
                    if status.get("status") == "stopped":
                        exit_status = status.get("exitstatus", "")
                        if exit_status == "OK":
                            job.finish(True)
                        else:
                            job.append(f"\nTask failed: {exit_status}\n")
                            job.finish(False)
                        return
                except Exception as e:
                    logger.debug(f"Error fetching task status: {e}")

        except Exception as e:
            logger.error(f"Proxmox task polling error for {job_key}: {e}", exc_info=True)
            job.append(f"\n[Error] {e}\n")
            job.finish(False)


def start_proxmox_job(guest, job_type, upid, node):
    """Create a ProxmoxJob, start the polling thread, and return the job key."""
    from flask import current_app
    app = current_app._get_current_object()

    job_key = f"{job_type}:{guest.id}"

    job = ProxmoxJob(guest.id, guest.name, job_type, upid, node, guest.proxmox_host)
    with _proxmox_jobs_lock:
        _proxmox_jobs[job_key] = job

    thread = threading.Thread(
        target=_poll_proxmox_task,
        args=(app, job_key),
        daemon=True,
    )
    thread.start()

    return job_key


@bp.route("/task/<int:guest_id>/<job_type>/progress")
@login_required
def task_progress(guest_id, job_type):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.can_manage_guests and not current_user.can_access_guest(guest):
        flash("You don't have permission to view this guest.", "error")
        return redirect(url_for("guests.index"))

    job_key = f"{job_type}:{guest_id}"
    job = _proxmox_jobs.get(job_key)
    if not job:
        flash("No task in progress for this guest.", "info")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    return render_template("proxmox_task_progress.html", guest=guest, job=job)


@bp.route("/task/<int:guest_id>/<job_type>/status")
@login_required
def task_status(guest_id, job_type):
    job_key = f"{job_type}:{guest_id}"
    job = _proxmox_jobs.get(job_key)
    if not job:
        return jsonify({"running": False, "log": "", "success": None})
    return jsonify(job.to_dict())


# ---------------------------------------------------------------------------
# RRD performance data
# ---------------------------------------------------------------------------

@bp.route("/guests/<int:guest_id>/rrd")
@login_required
def guest_rrd(guest_id):
    """Return RRD performance data as JSON for Chart.js."""
    from proxmox_api import ProxmoxClient

    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        return jsonify({"error": "Permission denied"}), 403

    if not guest.proxmox_host or not guest.vmid:
        return jsonify({"error": "Guest has no Proxmox host configured"}), 400

    timeframe = request.args.get("timeframe", "day")
    if timeframe not in ("hour", "day", "week", "month", "year"):
        timeframe = "day"

    try:
        client = ProxmoxClient(guest.proxmox_host)
        node = client.find_guest_node(guest.vmid)
        if not node:
            return jsonify({"error": "Guest not found on any node"}), 404

        raw = client.get_rrd_data(node, guest.vmid, guest.guest_type, timeframe=timeframe)
    except Exception as e:
        logger.error(f"RRD fetch error for guest {guest_id}: {e}")
        return jsonify({"error": str(e)}), 500

    if not raw:
        return jsonify({"labels": [], "cpu": [], "mem_percent": [], "mem_used_mb": [],
                        "mem_total_mb": 0, "netin": [], "netout": [], "net_unit": "KB/s"})

    labels = []
    cpu = []
    mem_percent = []
    mem_used_mb = []
    netin = []
    netout = []
    mem_total_mb = 0

    for point in raw:
        ts = point.get("time")
        if ts is None:
            continue

        labels.append(datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M"))

        # CPU: fraction (0.0–N where N = num cores) → percentage of allocated cores
        cpu_val = point.get("cpu")
        maxcpu = point.get("maxcpu", 1) or 1
        if cpu_val is not None:
            cpu.append(round(cpu_val / maxcpu * 100, 2))
        else:
            cpu.append(None)

        # Memory: bytes → percentage + MB
        mem_val = point.get("mem")
        maxmem = point.get("maxmem", 1) or 1
        if mem_val is not None:
            mem_used_mb.append(round(mem_val / 1048576, 1))
            mem_percent.append(round(mem_val / maxmem * 100, 2))
        else:
            mem_used_mb.append(None)
            mem_percent.append(None)
        mem_total_mb = round(maxmem / 1048576, 1)

        # Network: bytes/sec
        ni = point.get("netin")
        no = point.get("netout")
        netin.append(round(ni, 2) if ni is not None else None)
        netout.append(round(no, 2) if no is not None else None)

    # Pick a sensible unit for network values
    max_net = max((v for v in netin + netout if v is not None), default=0)
    if max_net > 1_000_000:
        net_unit = "Mbps"
        divisor = 125_000  # bytes/sec → Mbps
    elif max_net > 1_000:
        net_unit = "KB/s"
        divisor = 1024
    else:
        net_unit = "B/s"
        divisor = 1

    if divisor != 1:
        netin = [round(v / divisor, 2) if v is not None else None for v in netin]
        netout = [round(v / divisor, 2) if v is not None else None for v in netout]

    return jsonify({
        "labels": labels,
        "cpu": cpu,
        "mem_percent": mem_percent,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "netin": netin,
        "netout": netout,
        "net_unit": net_unit,
    })


@bp.route("/hosts/<int:host_id>/rrd")
@login_required
def host_rrd(host_id):
    """Return node-level RRD performance data as JSON for Chart.js."""
    from proxmox_api import ProxmoxClient

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    host = ProxmoxHost.query.get_or_404(host_id)

    timeframe = request.args.get("timeframe", "day")
    if timeframe not in ("hour", "day", "week", "month", "year"):
        timeframe = "day"

    try:
        client = ProxmoxClient(host)
        node_name = client.get_local_node_name()
        if not node_name:
            return jsonify({"error": "Could not determine node name"}), 404

        raw = client.get_node_rrd_data(node_name, timeframe=timeframe)
    except Exception as e:
        logger.error(f"RRD fetch error for host {host_id}: {e}")
        return jsonify({"error": str(e)}), 500

    if not raw:
        return jsonify({"labels": [], "cpu": [], "mem_percent": [], "mem_used_mb": [],
                        "mem_total_mb": 0, "netin": [], "netout": [], "net_unit": "KB/s",
                        "iowait": [], "rootfs_percent": []})

    labels = []
    cpu = []
    iowait = []
    mem_percent = []
    mem_used_mb = []
    netin = []
    netout = []
    rootfs_percent = []
    mem_total_mb = 0

    for point in raw:
        ts = point.get("time")
        if ts is None:
            continue

        labels.append(datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M"))

        # CPU: fraction (0.0–1.0) → percentage
        cpu_val = point.get("cpu")
        if cpu_val is not None:
            cpu.append(round(cpu_val * 100, 2))
        else:
            cpu.append(None)

        # IO wait: fraction → percentage
        iow = point.get("iowait")
        if iow is not None:
            iowait.append(round(iow * 100, 2))
        else:
            iowait.append(None)

        # Memory: bytes → percentage + MB
        mem_val = point.get("memused")
        maxmem = point.get("memtotal", 1) or 1
        if mem_val is not None:
            mem_used_mb.append(round(mem_val / 1048576, 1))
            mem_percent.append(round(mem_val / maxmem * 100, 2))
        else:
            mem_used_mb.append(None)
            mem_percent.append(None)
        mem_total_mb = round(maxmem / 1048576, 1)

        # Root filesystem usage
        rootfs_used = point.get("rootused")
        rootfs_total = point.get("roottotal", 1) or 1
        if rootfs_used is not None:
            rootfs_percent.append(round(rootfs_used / rootfs_total * 100, 2))
        else:
            rootfs_percent.append(None)

        # Network: bytes/sec
        ni = point.get("netin")
        no = point.get("netout")
        netin.append(round(ni, 2) if ni is not None else None)
        netout.append(round(no, 2) if no is not None else None)

    # Pick a sensible unit for network values
    max_net = max((v for v in netin + netout if v is not None), default=0)
    if max_net > 1_000_000:
        net_unit = "Mbps"
        divisor = 125_000
    elif max_net > 1_000:
        net_unit = "KB/s"
        divisor = 1024
    else:
        net_unit = "B/s"
        divisor = 1

    if divisor != 1:
        netin = [round(v / divisor, 2) if v is not None else None for v in netin]
        netout = [round(v / divisor, 2) if v is not None else None for v in netout]

    return jsonify({
        "labels": labels,
        "cpu": cpu,
        "iowait": iowait,
        "mem_percent": mem_percent,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "netin": netin,
        "netout": netout,
        "net_unit": net_unit,
        "rootfs_percent": rootfs_percent,
    })


@bp.route("/dashboard/host-stats")
@login_required
def dashboard_host_stats():
    """Return aggregated live stats from all Proxmox hosts for the dashboard."""
    from proxmox_api import ProxmoxClient

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    hosts = ProxmoxHost.query.all()
    if not hosts:
        return jsonify({"hosts": []})

    results = []
    for host in hosts:
        entry = {"id": host.id, "name": host.name, "online": False, "is_pbs": host.is_pbs}
        try:
            if host.is_pbs:
                from pbs_client import PBSClient
                status = PBSClient(host).get_node_status()
            else:
                client = ProxmoxClient(host)
                node_name = client.get_local_node_name()
                if not node_name:
                    results.append(entry)
                    continue
                status = client.get_node_status(node_name)

            if not status:
                results.append(entry)
                continue

            entry["online"] = True
            entry["cpu_usage"] = status["cpu_usage"]
            entry["cpu_threads"] = status["cpu_threads"]
            entry["memory_used"] = status["memory_used"]
            entry["memory_total"] = status["memory_total"]
            entry["swap_used"] = status["swap_used"]
            entry["swap_total"] = status["swap_total"]
            entry["rootfs_used"] = status["rootfs_used"]
            entry["rootfs_total"] = status["rootfs_total"]
            entry["uptime"] = status["uptime"]
            entry["loadavg"] = status["loadavg"]
        except Exception as e:
            logger.error(f"Dashboard host stats error for {host.name}: {e}")

        results.append(entry)

    # Compute aggregates across all online hosts
    online = [h for h in results if h.get("online")]
    agg = {}
    if online:
        agg["total_cpu_threads"] = sum(h.get("cpu_threads", 0) for h in online)
        agg["avg_cpu"] = round(sum(h.get("cpu_usage", 0) for h in online) / len(online), 1)
        agg["max_cpu"] = max(h.get("cpu_usage", 0) for h in online)
        agg["total_memory_used"] = sum(h.get("memory_used", 0) for h in online)
        agg["total_memory"] = sum(h.get("memory_total", 0) for h in online)
        agg["total_swap_used"] = sum(h.get("swap_used", 0) for h in online)
        agg["total_swap"] = sum(h.get("swap_total", 0) for h in online)
        agg["total_rootfs_used"] = sum(h.get("rootfs_used", 0) for h in online)
        agg["total_rootfs"] = sum(h.get("rootfs_total", 0) for h in online)
        agg["hosts_online"] = len(online)
        agg["hosts_offline"] = len(results) - len(online)

    return jsonify({"hosts": results, "aggregate": agg})


@bp.route("/dashboard/guest-stats")
@login_required
def dashboard_guest_stats():
    """Return live CPU/memory/disk usage for all running guests across all Proxmox hosts."""
    from proxmox_api import ProxmoxClient

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    tag_filter = request.args.get("tag", "")

    hosts = ProxmoxHost.query.all()
    if not hosts:
        return jsonify({"guests": []})

    # Build lookup: (host_id, vmid) -> db guest (for links).
    # Apply the active tag filter so the panel matches the dashboard view.
    guest_query = Guest.query.filter_by(enabled=True)
    if tag_filter == "__my_tags__":
        user_tag_names = [t.name for t in current_user.allowed_tags]
        if user_tag_names:
            guest_query = guest_query.filter(Guest.tags.any(Tag.name.in_(user_tag_names)))
    elif tag_filter:
        guest_query = guest_query.filter(Guest.tags.any(Tag.name == tag_filter))

    db_lookup = {}
    for g in guest_query.all():
        if g.proxmox_host_id and g.vmid:
            db_lookup[(g.proxmox_host_id, g.vmid)] = g

    results = []
    for host in hosts:
        if host.is_pbs:
            continue  # PBS has no VMs/CTs to report
        try:
            client = ProxmoxClient(host)
            raw_guests = client.get_all_guests()
        except Exception as e:
            logger.error(f"Dashboard guest stats error for {host.name}: {e}")
            continue

        for g in raw_guests:
            if g.get("status") != "running":
                continue

            vmid = g.get("vmid")
            db_guest = db_lookup.get((host.id, vmid))
            # When a tag filter is active, skip guests not in the filtered set.
            if tag_filter and db_guest is None:
                continue
            mem_used = g.get("mem", 0)
            mem_total = g.get("maxmem", 0) or 1
            disk_used = g.get("disk", 0)
            disk_total = g.get("maxdisk", 0) or 1
            cpu_pct = round(g.get("cpu", 0) * 100, 1)
            mem_pct = round(mem_used / mem_total * 100, 1)
            disk_pct = round(disk_used / disk_total * 100, 1)

            results.append({
                "vmid": vmid,
                "name": g.get("name", f"VMID {vmid}"),
                "type": g.get("type", "vm"),
                "node": g.get("node", ""),
                "host_name": host.name,
                "cpu_pct": cpu_pct,
                "mem_used": mem_used,
                "mem_total": mem_total,
                "mem_pct": mem_pct,
                "disk_used": disk_used,
                "disk_total": disk_total,
                "disk_pct": disk_pct,
                "uptime": g.get("uptime", 0),
                "guest_id": db_guest.id if db_guest else None,
            })

    results.sort(key=lambda x: x["cpu_pct"], reverse=True)
    return jsonify({"guests": results})


@bp.route("/hosts/<int:host_id>/guest-stats")
@login_required
def host_guest_stats(host_id):
    """Return live CPU/memory/disk keyed by VMID for all guests on one PVE host."""
    from proxmox_api import ProxmoxClient

    host = ProxmoxHost.query.get_or_404(host_id)

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    if host.is_pbs:
        return jsonify({"error": "Not a PVE host"}), 400

    try:
        client = ProxmoxClient(host)
        node_name = client.get_local_node_name()
        raw = client.get_node_guests(node_name) if node_name else client.get_all_guests()
    except Exception as e:
        logger.error(f"Host guest stats error for host {host_id}: {e}")
        return jsonify({"error": str(e)}), 500

    stats = {}
    for g in raw:
        vmid = g.get("vmid")
        if vmid is None:
            continue
        mem_used = g.get("mem", 0)
        mem_total = g.get("maxmem", 0) or 1
        disk_used = g.get("disk", 0)
        disk_total = g.get("maxdisk", 0) or 1
        stats[vmid] = {
            "status": g.get("status", ""),
            "cpu_pct": round(g.get("cpu", 0) * 100, 1),
            "mem_used": mem_used,
            "mem_total": mem_total,
            "mem_pct": round(mem_used / mem_total * 100, 1),
            "disk_used": disk_used,
            "disk_total": disk_total,
            "disk_pct": round(disk_used / disk_total * 100, 1) if disk_used > 0 else 0,
        }

    return jsonify({"stats": stats})


@bp.route("/guests/<int:guest_id>/unifi-stats")
@login_required
def guest_unifi_stats(guest_id):
    """Return fresh UniFi stats for a guest as JSON (used for live polling)."""
    guest = Guest.query.get_or_404(guest_id)
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        return jsonify({"error": "forbidden"}), 403

    if not guest.mac_address:
        return jsonify({"error": "no_mac"}), 404

    from models import Setting
    if Setting.get("unifi_enabled", "false") != "true":
        return jsonify({"error": "unifi_disabled"}), 404

    try:
        from routes.unifi import _get_unifi_client
        client = _get_unifi_client()
        if not client:
            return jsonify({"error": "not_configured"}), 404

        stats = client.get_client_by_mac(guest.mac_address)
        if not stats:
            return jsonify({"error": "not_found"}), 404

        Setting.set("unifi_last_polled", datetime.now(timezone.utc).isoformat())
        return jsonify({"stats": stats})
    except Exception as e:
        logger.error(f"UniFi stats fetch failed for guest {guest_id}: {e}")
        return jsonify({"error": "fetch_failed"}), 500
