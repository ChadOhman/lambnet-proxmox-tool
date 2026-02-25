import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from sqlalchemy import or_
from models import db, Setting, UnifiLogEntry
from credential_store import decrypt
from audit import log_action

logger = logging.getLogger(__name__)

bp = Blueprint("unifi", __name__)

_LOGS_PER_PAGE = 50


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_view_hosts:
        flash("You don't have permission to view network devices.", "error")
        return redirect(url_for("dashboard.index"))


def _get_unifi_client():
    """Create a UniFi client from saved settings."""
    from unifi_client import UniFiClient

    base_url = Setting.get("unifi_base_url", "")
    username = Setting.get("unifi_username", "")
    encrypted_pw = Setting.get("unifi_password", "")
    site = Setting.get("unifi_site", "default")
    is_udm = Setting.get("unifi_is_udm", "true") == "true"

    if not base_url or not username or not encrypted_pw:
        return None

    password = decrypt(encrypted_pw)
    if not password:
        return None

    return UniFiClient(base_url, username, password, site=site, is_udm=is_udm)


def _filter_by_subnet(items, ip_key, subnet_str):
    """Filter a list of dicts by subnet on the given IP key."""
    if not subnet_str:
        return items
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        return items
    filtered = []
    for item in items:
        ip = item.get(ip_key, "")
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in network:
                filtered.append(item)
        except ValueError:
            continue
    return filtered


def _get_accessible_ips(user):
    """Return a set of IP addresses for all guests this user can access."""
    guests = user.accessible_guests()
    return {g.ip_address for g in guests if g.ip_address}


def _get_accessible_networks(user):
    """Return set of UniFi network names accessible to user, or None if unrestricted.

    Returns None for super admins and for users whose tags have no network links
    configured (backwards compatible — no filtering until links are set up).
    Returns a set (possibly empty) once any tag-network links exist for the user.
    """
    if user.is_super_admin:
        return None
    networks = set()
    has_links = False
    for tag in user.allowed_tags:
        for n in tag.unifi_networks:
            networks.add(n.network_name)
            has_links = True
    if not has_links:
        return None  # No links configured yet: don't filter (backwards compatible)
    return networks


@bp.route("/")
def index():
    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        return render_template("unifi.html", enabled=False, devices=[], clients=[], subnet_filter="",
                               chart_direction=[], chart_blocked=[])

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller is not configured. Ask a super admin to set it up in Settings.", "warning")
        return render_template("unifi.html", enabled=False, devices=[], clients=[], subnet_filter="",
                               chart_direction=[], chart_blocked=[])

    devices = client.get_devices() or []
    clients = client.get_clients() or []
    Setting.set("unifi_last_polled", datetime.now(timezone.utc).isoformat())

    subnet_filter = Setting.get("unifi_filter_subnet", "")
    if subnet_filter:
        devices = _filter_by_subnet(devices, "ip", subnet_filter)
        clients = _filter_by_subnet(clients, "ip", subnet_filter)

    # Network-based access control: filter clients to networks linked to user's tags
    accessible_networks = _get_accessible_networks(current_user)
    network_restricted = accessible_networks is not None
    if accessible_networks is not None:
        clients = [c for c in clients if c.get("network", "") in accessible_networks]

    # Sort
    devices.sort(key=lambda d: d.get("name", "").lower())
    clients.sort(key=lambda c: c.get("hostname", "").lower())

    # Build chart data from recent log entries (last 24h)
    chart_direction = []
    chart_blocked = []
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    base_q = UnifiLogEntry.query.filter(UnifiLogEntry.timestamp >= since)
    if not current_user.is_super_admin:
        ips = _get_accessible_ips(current_user)
        if ips:
            base_q = base_q.filter(or_(
                UnifiLogEntry.src_ip.in_(ips),
                UnifiLogEntry.dst_ip.in_(ips),
            ))
        else:
            base_q = base_q.filter(False)

    from sqlalchemy import func
    direction_rows = (
        base_q.with_entities(UnifiLogEntry.direction, func.count().label("cnt"))
        .group_by(UnifiLogEntry.direction)
        .all()
    )
    chart_direction = [{"label": r.direction or "unknown", "count": r.cnt} for r in direction_rows]

    blocked_rows = (
        base_q.filter(UnifiLogEntry.action == "block", UnifiLogEntry.src_ip.isnot(None))
        .with_entities(UnifiLogEntry.src_ip, func.count().label("cnt"))
        .group_by(UnifiLogEntry.src_ip)
        .order_by(func.count().desc())
        .limit(10)
        .all()
    )
    chart_blocked = [{"ip": r.src_ip, "count": r.cnt} for r in blocked_rows]

    return render_template(
        "unifi.html",
        enabled=True,
        devices=devices,
        clients=clients,
        subnet_filter=subnet_filter,
        chart_direction=chart_direction,
        chart_blocked=chart_blocked,
        network_restricted=network_restricted,
        accessible_networks=sorted(accessible_networks) if accessible_networks is not None else None,
    )


@bp.route("/logs")
def logs():
    # Filter parameters
    log_type = request.args.get("type", "")
    action = request.args.get("action", "")
    direction = request.args.get("direction", "")
    search = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    # Time range
    hours_str = request.args.get("hours", "24")
    try:
        hours = int(hours_str)
        if hours not in (1, 6, 24, 48, 168):
            hours = 24
    except ValueError:
        hours = 24

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = UnifiLogEntry.query.filter(UnifiLogEntry.timestamp >= since)

    # Tag-based IP access control: non-super-admins see only traffic for their VMs
    access_restricted = False
    if not current_user.is_super_admin:
        ips = _get_accessible_ips(current_user)
        access_restricted = True
        if ips:
            q = q.filter(or_(
                UnifiLogEntry.src_ip.in_(ips),
                UnifiLogEntry.dst_ip.in_(ips),
            ))
        else:
            q = q.filter(False)

    if log_type:
        q = q.filter(UnifiLogEntry.log_type == log_type)
    if action:
        q = q.filter(UnifiLogEntry.action == action)
    if direction:
        q = q.filter(UnifiLogEntry.direction == direction)
    if search:
        like = f"%{search}%"
        q = q.filter(or_(
            UnifiLogEntry.src_ip.like(like),
            UnifiLogEntry.dst_ip.like(like),
            UnifiLogEntry.msg.like(like),
            UnifiLogEntry.rule_id.like(like),
            UnifiLogEntry.mac.like(like),
            UnifiLogEntry.country.like(like),
        ))

    total = q.count()
    entries = q.order_by(UnifiLogEntry.timestamp.desc()).paginate(
        page=page, per_page=_LOGS_PER_PAGE, error_out=False
    )

    return render_template(
        "unifi_logs.html",
        entries=entries,
        total=total,
        log_type=log_type,
        action=action,
        direction=direction,
        search=search,
        hours=hours,
        page=page,
        access_restricted=access_restricted,
    )


@bp.route("/restart/<mac>", methods=["POST"])
def restart(mac):
    if not current_user.can_restart_unifi:
        flash("You don't have permission to restart devices.", "error")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    ok, msg = client.restart_device(mac)
    if ok:
        log_action("unifi_device_restart", "unifi", resource_name=mac)
        db.session.commit()
        flash(f"Restart command sent to device {mac}.", "success")
    else:
        flash(f"Failed to restart device: {msg}", "error")

    return redirect(url_for("unifi.index"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    return redirect(url_for("unifi.index"))
