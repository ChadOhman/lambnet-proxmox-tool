import json
import logging
import queue
import re
import shlex
import threading
from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, stream_with_context
from sqlalchemy import func
from flask_login import login_required, current_user
from auth.audit import log_action
from models import db, AuditLog, Guest, Tag, GuestService, ServiceMetricSnapshot
from core.scanner import (check_service_statuses, service_action, get_service_logs, get_service_stats,
                     sidekiq_clear_dead, sidekiq_retry_dead,
                     sidekiq_clear_retry, sidekiq_retry_retry,
                     sidekiq_list_jobs, sidekiq_delete_job, sidekiq_retry_job,
                     lt_list_installed, lt_list_available, lt_install_package, lt_update_all_packages,
                     lt_update_packages_stream)

logger = logging.getLogger(__name__)

# Allowlist for PostgreSQL database names: letters, digits, underscores only (max 63 chars).
# Prevents command injection in shell commands that embed the database name.
_PG_DB_NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,63}$')

bp = Blueprint("services", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_view_services:
        flash("You don't have permission to view services.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    service_filter = request.args.get("service", "")
    query = GuestService.query.join(Guest).filter(Guest.enabled == True)

    # Filter by user's tag-based access (non-admin users only see services
    # on guests they have tag access to)
    if not current_user.is_admin:
        user_tag_ids = [t.id for t in current_user.allowed_tags]
        if user_tag_ids:
            query = query.filter(Guest.tags.any(Tag.id.in_(user_tag_ids)))
        else:
            query = query.filter(False)  # no tags = no access

    if service_filter:
        query = query.filter(GuestService.service_name == service_filter)
    services = query.order_by(Guest.name, GuestService.service_name).all()

    service_types = sorted(set(s.service_name for s in GuestService.query.all()))
    return render_template("services.html", services=services,
                           service_types=service_types, current_filter=service_filter)


@bp.route("/<int:service_id>/<action>", methods=["POST"])
def control(service_id, action):
    if not current_user.can_edit_services:
        flash("You don't have permission to control services.", "error")
        return redirect(url_for("services.index"))
    if action not in ("start", "stop", "restart"):
        flash("Invalid action.", "error")
        return redirect(url_for("services.index"))

    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest

    ok, msg = service_action(guest, svc, action)
    if ok:
        log_action("service_control", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "action": action})
        db.session.commit()
        flash(f"{action.capitalize()} sent for {svc.service_name} on {guest.name}.", "success")
    else:
        flash(f"Failed to {action} {svc.service_name} on {guest.name}: {msg}", "error")

    referrer = request.referrer
    if referrer and f"/guests/{guest.id}" in referrer:
        from urllib.parse import urlparse
        parsed = urlparse(referrer)
        if not parsed.netloc or parsed.netloc == request.host:
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
    if not current_user.can_edit_services:
        flash("You don't have permission to refresh service statuses.", "error")
        return redirect(url_for("services.index"))
    guests = Guest.query.filter(Guest.enabled == True, Guest.services.any()).all()
    checked = 0
    for guest in guests:
        try:
            check_service_statuses(guest)
            checked += 1
        except Exception as e:
            logger.warning(f"Service status check failed for {guest.name}: {e}")
    flash(f"Service statuses refreshed for {checked} guest(s).", "success")

    referrer = request.referrer
    if referrer and "/guests/" in referrer:
        from urllib.parse import urlparse
        parsed = urlparse(referrer)
        # Only redirect to same-host paths to prevent open redirect
        if not parsed.netloc or parsed.netloc == request.host:
            return redirect(parsed.path)
    return redirect(url_for("services.index"))


@bp.route("/<int:guest_id>/assign", methods=["POST"])
def assign(guest_id):
    if not current_user.can_edit_services:
        flash("You don't have permission to assign services.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))
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
    log_action("service_assign", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": service_key})
    db.session.commit()

    flash(f"{display_name} assigned to {guest.name}.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:service_id>/remove", methods=["POST"])
def remove(service_id):
    if not current_user.can_edit_services:
        flash("You don't have permission to remove services.", "error")
        return redirect(url_for("services.index"))
    svc = GuestService.query.get_or_404(service_id)
    guest_id = svc.guest_id
    name = svc.service_name
    log_action("service_remove", "guest", resource_id=guest_id, resource_name=svc.guest.name,
               details={"service": name})
    db.session.delete(svc)
    db.session.commit()
    flash(f"Service '{name}' removed.", "warning")

    referrer = request.referrer
    if referrer and f"/guests/{guest_id}" in referrer:
        from urllib.parse import urlparse
        parsed = urlparse(referrer)
        if not parsed.netloc or parsed.netloc == request.host:
            return redirect(url_for("guests.detail", guest_id=guest_id))
    return redirect(url_for("services.index"))


@bp.route("/<int:service_id>/detail")
def detail(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    stats = get_service_stats(guest, svc)
    log_text = get_service_logs(guest, svc, lines=30)
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent_logs = (AuditLog.query
                   .filter(AuditLog.resource_type == "guest",
                           AuditLog.resource_id == guest.id,
                           AuditLog.timestamp >= cutoff,
                           func.json_extract(AuditLog.details, "$.service") == svc.service_name)
                   .order_by(AuditLog.timestamp.desc())
                   .limit(25).all())
    return render_template("service_detail.html", service=svc, guest=guest, stats=stats, logs=log_text,
                           recent_logs=recent_logs)


@bp.route("/<int:service_id>/sidekiq/clear-dead", methods=["POST"])
def sidekiq_clear_dead_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_clear_dead(guest, svc)
    if ok:
        log_action("sidekiq_clear_dead", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/retry-dead", methods=["POST"])
def sidekiq_retry_dead_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_retry_dead(guest, svc)
    if ok:
        log_action("sidekiq_retry_dead", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/clear-retry", methods=["POST"])
def sidekiq_clear_retry_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_clear_retry(guest, svc)
    if ok:
        log_action("sidekiq_clear_retry", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/retry-retry", methods=["POST"])
def sidekiq_retry_retry_queue(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_retry_retry(guest, svc)
    if ok:
        log_action("sidekiq_retry_retry", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "result": msg})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/<queue_type>/jobs")
def sidekiq_jobs(service_id, queue_type):
    if queue_type not in ("dead", "retry", "schedule"):
        return jsonify({"error": "Invalid queue type"}), 400
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"error": "Not a Sidekiq service"}), 400
    guest = svc.guest
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = min(100, max(1, int(request.args.get("limit", 25))))
    except (ValueError, TypeError):
        offset, limit = 0, 25
    jobs, total, err = sidekiq_list_jobs(guest, svc, queue_type, offset=offset, limit=limit)
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"jobs": jobs, "total": total, "offset": offset, "limit": limit})


@bp.route("/<int:service_id>/sidekiq/<queue_type>/jobs/<jid>/delete", methods=["POST"])
def sidekiq_delete_job_route(service_id, queue_type, jid):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    if queue_type not in ("dead", "retry", "schedule"):
        return jsonify({"ok": False, "message": "Invalid queue type"}), 400
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_delete_job(guest, svc, queue_type, jid)
    if ok:
        log_action("sidekiq_delete_job", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "queue_type": queue_type, "jid": jid})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/sidekiq/<queue_type>/jobs/<jid>/retry", methods=["POST"])
def sidekiq_retry_job_route(service_id, queue_type, jid):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    if queue_type not in ("dead", "retry", "schedule"):
        return jsonify({"ok": False, "message": "Invalid queue type"}), 400
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "sidekiq":
        return jsonify({"ok": False, "message": "Not a Sidekiq service"}), 400
    guest = svc.guest
    ok, msg = sidekiq_retry_job(guest, svc, queue_type, jid)
    if ok:
        log_action("sidekiq_retry_job", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "queue_type": queue_type, "jid": jid})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/pg/kill-query/<int:pid>", methods=["POST"])
def pg_kill_query(service_id, pid):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "postgresql":
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    guest = svc.guest
    from core.scanner import _execute_command
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -t -A -c \"SELECT pg_terminate_backend({pid})\" 2>&1",
        timeout=10,
        sudo=True,
    )
    if error:
        return jsonify({"ok": False, "message": f"SSH error: {error[:200]}"})
    result = (stdout or "").strip()
    if result == "t":
        log_action("pg_kill_query", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "pid": pid})
        db.session.commit()
        return jsonify({"ok": True, "message": f"Backend {pid} terminated."})
    if result == "f":
        return jsonify({"ok": False, "message": f"Backend {pid} not found (already finished?)."})
    return jsonify({"ok": False, "message": f"Unexpected result: {(result or error or '')[:100]}"})


def _safe_int(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _safe_float(v):
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _pg_guard(service_id):
    """Return (svc, guest) or raise 404. Also checks service type."""
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "postgresql":
        return None, None
    return svc, svc.guest


@bp.route("/<int:service_id>/pg/vacuum", methods=["POST"])
def pg_vacuum(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    data = request.get_json(silent=True) or {}
    database = (data.get("database") or "").strip()
    analyze = bool(data.get("analyze", False))
    verbose = bool(data.get("verbose", False))
    if not database:
        return jsonify({"ok": False, "message": "database is required"}), 400
    if not _PG_DB_NAME_RE.match(database):
        return jsonify({"ok": False, "message": "Invalid database name."}), 400
    from core.scanner import _execute_command
    options = ["VERBOSE"] if verbose else []
    if analyze:
        options.append("ANALYZE")
    verb = "VACUUM " + " ".join(options) if options else "VACUUM"
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -d {database} -c \"{verb}\" 2>&1",
        timeout=120,
        sudo=True,
    )
    if error:
        return jsonify({"ok": False, "message": f"SSH error: {error[:300]}"})
    log_action("pg_vacuum", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name, "database": database, "analyze": analyze, "verbose": verbose})
    db.session.commit()
    output = (stdout or "").strip() or f"{verb} completed."
    return jsonify({"ok": True, "message": output})


@bp.route("/<int:service_id>/pg/explain", methods=["POST"])
def pg_explain(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"ok": False, "message": "Not a PostgreSQL service"}), 400
    data = request.get_json(silent=True) or {}
    database = (data.get("database") or "").strip()
    query = (data.get("query") or "").strip()
    if not database or not query:
        return jsonify({"ok": False, "message": "database and query are required"}), 400
    if not _PG_DB_NAME_RE.match(database):
        return jsonify({"ok": False, "message": "Invalid database name."}), 400
    from core.scanner import _execute_command
    import uuid
    tmpfile = f"/tmp/.pg_explain_{uuid.uuid4().hex[:12]}.sql"  # nosec B108 — remote SSH path, not a local temp file
    # Use shlex.quote() to safely shell-quote the SQL content; single quotes in the shell
    # prevent all metacharacter expansion (backticks, $(), semicolons, etc.).
    safe_content = shlex.quote(f"EXPLAIN {query}")
    _, write_err = _execute_command(
        guest,
        f"printf %s {safe_content} > {tmpfile}",
        timeout=10,
    )
    if write_err:
        return jsonify({"ok": False, "message": f"Could not write temp file: {write_err[:200]}"})
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -d {database} -f {tmpfile} 2>&1; rm -f {tmpfile}",
        timeout=60,
        sudo=True,
    )
    if error:
        _execute_command(guest, f"rm -f {tmpfile}", timeout=5)
        return jsonify({"ok": False, "message": f"SSH error: {error[:300]}"})
    log_action("pg_explain", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"service": svc.service_name, "database": database})
    db.session.commit()
    return jsonify({"ok": True, "plan": (stdout or "").strip()})


@bp.route("/<int:service_id>/pg/roles")
def pg_roles(service_id):
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a PostgreSQL service"}), 400
    from core.scanner import _execute_command
    stdout, error = _execute_command(
        guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit "
        "FROM pg_roles ORDER BY rolname"
        "\" 2>/dev/null",
        timeout=10,
        sudo=True,
    )
    if error:
        return jsonify({"error": error[:200]}), 500
    roles = []
    for line in (stdout or "").strip().split("\n"):
        parts = line.strip().split("|")
        if len(parts) == 7:
            roles.append({
                "name": parts[0],
                "superuser": parts[1] == "t",
                "create_role": parts[2] == "t",
                "create_db": parts[3] == "t",
                "can_login": parts[4] == "t",
                "replication": parts[5] == "t",
                "conn_limit": parts[6],
            })
    return jsonify({"roles": roles})


@bp.route("/<int:service_id>/pg/settings")
def pg_settings(service_id):
    svc, guest = _pg_guard(service_id)
    if svc is None:
        return jsonify({"error": "Not a PostgreSQL service"}), 400
    from core.scanner import _execute_command
    # Fetch a curated set of important settings
    names = (
        "max_connections,shared_buffers,work_mem,maintenance_work_mem,"
        "effective_cache_size,wal_level,max_wal_size,checkpoint_completion_target,"
        "log_min_duration_statement,autovacuum,autovacuum_vacuum_scale_factor,"
        "autovacuum_analyze_scale_factor,random_page_cost,effective_io_concurrency,"
        "max_worker_processes,max_parallel_workers"
    )
    stdout, error = _execute_command(
        guest,
        f"sudo -u postgres psql -t -A -c \""  # noqa: S608 — query built from hardcoded literals only, no user input
        f"SELECT name, setting, unit, short_desc FROM pg_settings "
        f"WHERE name = ANY(ARRAY[{','.join(repr(n) for n in names.split(','))}]) "
        f"ORDER BY name"
        f"\" 2>/dev/null",
        timeout=10,
        sudo=True,
    )
    if error:
        return jsonify({"error": error[:200]}), 500
    settings = []
    for line in (stdout or "").strip().split("\n"):
        parts = line.strip().split("|", 3)
        if len(parts) == 4:
            settings.append({
                "name": parts[0],
                "setting": parts[1],
                "unit": parts[2],
                "description": parts[3],
            })
    return jsonify({"settings": settings})


@bp.route("/<int:service_id>/pg/metrics-history")
def pg_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "postgresql":
        return jsonify({"error": "Not a PostgreSQL service"}), 400

    # Try Prometheus first if enabled
    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient
            prom = PrometheusQueryClient()
            pg_metrics = [
                "lambnet_pg_connections_total",
                "lambnet_pg_cache_hit_ratio",
                "lambnet_pg_connections_active",
                "lambnet_pg_lock_waits",
                "lambnet_pg_commits_total",
                "lambnet_pg_rollbacks_total",
            ]
            data = prom.get_service_metrics_history(svc.id, pg_metrics, timeframe)
            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for PG metrics history, falling back to SQLite")

    # Fall back to SQLite
    limit = min(int(request.args.get("limit", 144)), 288)  # default 12h at 5-min
    rows = (
        ServiceMetricSnapshot.query
        .filter_by(service_id=svc.id)
        .order_by(ServiceMetricSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        try:
            d = json.loads(row.data or "{}")
        except (json.JSONDecodeError, TypeError):
            d = {}
        d["captured_at"] = row.captured_at.isoformat()
        result.append(d)
    return jsonify({"snapshots": result})


@bp.route("/<int:service_id>/stats")
def stats(service_id):
    svc = GuestService.query.get_or_404(service_id)
    guest = svc.guest
    data = get_service_stats(guest, svc)

    # Persist a metric snapshot for PostgreSQL services
    if svc.service_name == "postgresql" and data.get("type") == "postgresql":
        try:
            snapshot_data = {
                "total_connections": _safe_int(data.get("total_connections")),
                "cache_hit_ratio": _safe_float(str(data.get("cache_hit_ratio", "")).rstrip("%")),
                "active_queries": _safe_int(data.get("active_queries")),
                "lock_waits": data.get("lock_waits", 0),
                "total_commits": _safe_int(data.get("total_commits")),
                "total_rollbacks": _safe_int(data.get("total_rollbacks")),
            }
            snap = ServiceMetricSnapshot(
                service_id=svc.id,
                captured_at=datetime.now(timezone.utc),
                data=json.dumps(snapshot_data),
            )
            db.session.add(snap)
            # Prune: keep most recent 288 rows per service (≈24h at 5-min intervals)
            old_ids = (
                db.session.query(ServiceMetricSnapshot.id)
                .filter_by(service_id=svc.id)
                .order_by(ServiceMetricSnapshot.captured_at.desc())
                .offset(288)
                .all()
            )
            if old_ids:
                ServiceMetricSnapshot.query.filter(
                    ServiceMetricSnapshot.id.in_([r[0] for r in old_ids])
                ).delete(synchronize_session=False)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to save PostgreSQL metric snapshot for service %s", svc.id)

    # Persist a metric snapshot for JVB services
    if svc.service_name == "jitsi-videobridge2" and not data.get("rest_api_disabled"):
        try:
            snapshot_data = {
                "conferences": data.get("conferences", 0),
                "participants": data.get("participants", 0),
                "stress_level": data.get("stress_level", 0),
                "bit_rate_download": data.get("bit_rate_download", 0),
            }
            snap = ServiceMetricSnapshot(
                service_id=svc.id,
                captured_at=datetime.now(timezone.utc),
                data=json.dumps(snapshot_data),
            )
            db.session.add(snap)
            old_ids = (
                db.session.query(ServiceMetricSnapshot.id)
                .filter_by(service_id=svc.id)
                .order_by(ServiceMetricSnapshot.captured_at.desc())
                .offset(288)
                .all()
            )
            if old_ids:
                ServiceMetricSnapshot.query.filter(
                    ServiceMetricSnapshot.id.in_([r[0] for r in old_ids])
                ).delete(synchronize_session=False)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to save JVB metric snapshot for service %s", svc.id)

    # Feed Prometheus exporter with service-specific metrics
    _update_prometheus_service_stats(svc, guest, data)

    return jsonify(data)


def _update_prometheus_service_stats(svc, guest, data):
    """Push service stats to the Prometheus exporter."""
    try:
        if svc.service_name == "postgresql" and data.get("type") == "postgresql":
            from clients.prometheus_exporter import update_pg_metrics
            update_pg_metrics(svc.id, guest.name, data)
        elif svc.service_name == "redis" and data.get("type") == "redis":
            from clients.prometheus_exporter import update_redis_metrics
            update_redis_metrics(svc.id, guest.name, data)
        elif svc.service_name == "elasticsearch" and data.get("type") == "elasticsearch":
            from clients.prometheus_exporter import update_es_metrics
            update_es_metrics(svc.id, guest.name, data)
        elif svc.service_name == "jitsi-videobridge2" and not data.get("rest_api_disabled"):
            from clients.prometheus_exporter import update_jitsi_metrics
            update_jitsi_metrics(svc.id, guest.name, data)
        elif svc.service_name == "prometheus" and not data.get("prom_api_disabled"):
            from clients.prometheus_exporter import update_prometheus_metrics
            update_prometheus_metrics(svc.id, guest.name, data)
    except Exception:
        logger.debug("Failed to update Prometheus metrics for service %s", svc.id, exc_info=True)


@bp.route("/<int:service_id>/jvb/metrics-history")
def jvb_metrics_history(service_id):
    from models import Setting

    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "jitsi-videobridge2":
        return jsonify({"error": "Not a Jitsi Videobridge service"}), 400

    # Try Prometheus first if enabled
    timeframe = request.args.get("timeframe", "day")
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient
            prom = PrometheusQueryClient()
            jvb_metrics = [
                "lambnet_jitsi_conferences",
                "lambnet_jitsi_participants",
                "lambnet_jitsi_stress_level",
                "lambnet_jitsi_bitrate_download_bps",
            ]
            data = prom.get_service_metrics_history(svc.id, jvb_metrics, timeframe)
            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for JVB metrics history, falling back to SQLite")

    # Fall back to SQLite
    limit = min(int(request.args.get("limit", 144)), 288)
    rows = (
        ServiceMetricSnapshot.query
        .filter_by(service_id=svc.id)
        .order_by(ServiceMetricSnapshot.captured_at.asc())
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        try:
            d = json.loads(row.data or "{}")
        except (json.JSONDecodeError, TypeError):
            d = {}
        d["captured_at"] = row.captured_at.isoformat()
        result.append(d)
    return jsonify({"snapshots": result})


@bp.route("/<int:service_id>/libretranslate/packages")
def lt_packages(service_id):
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"error": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    pkg_type = request.args.get("type", "installed")
    if pkg_type == "available":
        packages, err = lt_list_available(guest, svc)
    else:
        packages, err = lt_list_installed(guest, svc)
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"packages": packages, "type": pkg_type})


@bp.route("/<int:service_id>/libretranslate/install", methods=["POST"])
def lt_install(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"ok": False, "message": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    data = request.get_json(silent=True) or {}
    from_code = data.get("from_code", "")
    to_code = data.get("to_code", "")
    ok, msg = lt_install_package(guest, svc, from_code, to_code)
    if ok:
        log_action("lt_install_package", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "from": from_code, "to": to_code})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg})


@bp.route("/<int:service_id>/libretranslate/update", methods=["POST"])
def lt_update(service_id):
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"ok": False, "message": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    ok, msg, count = lt_update_all_packages(guest, svc)
    if ok:
        log_action("lt_update_packages", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"service": svc.service_name, "updated": count})
        db.session.commit()
    return jsonify({"ok": ok, "message": msg, "count": count})


@bp.route("/<int:service_id>/libretranslate/update-stream", methods=["POST"])
def lt_update_stream(service_id):
    from flask import current_app
    if not current_user.can_edit_services:
        return jsonify({"ok": False, "message": "Permission denied."}), 403
    svc = GuestService.query.get_or_404(service_id)
    if svc.service_name != "libretranslate":
        return jsonify({"ok": False, "message": "Not a LibreTranslate service"}), 400
    guest = svc.guest
    guest_id = guest.id
    guest_name = guest.name
    svc_name = svc.service_name
    svc_id = svc.id

    msg_queue = queue.Queue()
    app = current_app._get_current_object()

    def run():
        # Push a fresh app context so the background thread gets its own
        # SQLAlchemy session and can safely reload the SQLAlchemy objects.
        try:
            with app.app_context():
                fresh_guest = Guest.query.get(guest_id)
                fresh_svc = GuestService.query.get(svc_id)
                if fresh_guest and fresh_svc:
                    lt_update_packages_stream(fresh_guest, fresh_svc, msg_queue.put)
                else:
                    msg_queue.put(json.dumps({"type": "result", "ok": False,
                                             "updated": 0, "message": "Service not found"}))
        except Exception as exc:
            msg_queue.put(json.dumps({"type": "result", "ok": False,
                                     "updated": 0, "message": str(exc)}))
        finally:
            msg_queue.put(None)  # sentinel — always sent so generator never blocks forever

    threading.Thread(target=run, daemon=True).start()

    def generate():
        result = None
        while True:
            item = msg_queue.get()
            if item is None:
                break
            yield f"data: {item}\n\n"
            try:
                data = json.loads(item)
                if data.get("type") == "result":
                    result = data
            except Exception:
                pass
        if result and result.get("ok"):
            log_action("lt_update_packages", "guest", resource_id=guest_id, resource_name=guest_name,
                       details={"service": svc_name, "updated": result.get("updated", 0)})
            db.session.commit()

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
