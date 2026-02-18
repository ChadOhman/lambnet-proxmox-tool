import threading
import logging
from datetime import datetime, timezone
from flask import Blueprint, redirect, url_for, flash, request, render_template, jsonify
from flask_login import login_required, current_user
from models import db, Guest, UpdatePackage
from scanner import scan_guest, scan_all_guests
from notifier import send_update_notification

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
                        job.append(f"SSH failed, trying guest agent...\n")

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
