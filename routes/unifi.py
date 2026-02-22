import ipaddress
import logging
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, Setting
from credential_store import decrypt
from audit import log_action

logger = logging.getLogger(__name__)

bp = Blueprint("unifi", __name__)


@bp.before_request
@login_required
def _require_login():
    pass


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


@bp.route("/")
def index():
    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        return render_template("unifi.html", enabled=False, devices=[], clients=[], subnet_filter="")

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller is not configured. Ask a super admin to set it up in Settings.", "warning")
        return render_template("unifi.html", enabled=False, devices=[], clients=[], subnet_filter="")

    from datetime import datetime, timezone
    devices = client.get_devices() or []
    clients = client.get_clients() or []
    Setting.set("unifi_last_polled", datetime.now(timezone.utc).isoformat())

    subnet_filter = Setting.get("unifi_filter_subnet", "")
    if subnet_filter:
        devices = _filter_by_subnet(devices, "ip", subnet_filter)
        clients = _filter_by_subnet(clients, "ip", subnet_filter)

    # Sort
    devices.sort(key=lambda d: d.get("name", "").lower())
    clients.sort(key=lambda c: c.get("hostname", "").lower())

    return render_template("unifi.html", enabled=True, devices=devices, clients=clients, subnet_filter=subnet_filter)


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
