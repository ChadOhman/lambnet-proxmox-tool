import json
import threading
import logging
import paramiko
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from flask_sock import Sock
from models import db, Guest, Credential
from credential_store import decrypt

logger = logging.getLogger(__name__)

bp = Blueprint("terminal", __name__)
sock = Sock()


def init_websocket(app):
    """Initialize the WebSocket handler on the app."""
    sock.init_app(app)


def _resolve_guest_ip(guest):
    """Try to resolve a real IP address for a guest. Returns IP string or None."""
    # If we already have a valid stored IP, use it
    ip = guest.ip_address
    if ip and ip != "dhcp" and not ip.startswith("dhcp"):
        return ip

    # Try Proxmox API to get the actual IP
    if guest.proxmox_host and guest.vmid:
        try:
            from proxmox_api import ProxmoxClient
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                resolved_ip = client.get_guest_ip(node, guest.vmid, guest.guest_type)
                if resolved_ip and resolved_ip != "dhcp":
                    # Update the stored IP for future use
                    guest.ip_address = resolved_ip
                    db.session.commit()
                    return resolved_ip
        except Exception as e:
            logger.debug(f"Proxmox IP resolution failed for {guest.name}: {e}")

    # Try UniFi MAC lookup as fallback
    if guest.mac_address:
        try:
            from models import Setting
            if Setting.get("unifi_enabled", "false") == "true":
                from routes.unifi import _get_unifi_client
                unifi = _get_unifi_client()
                if unifi:
                    clients = unifi.get_clients() or []
                    for c in clients:
                        if c.get("mac", "").lower() == guest.mac_address.lower() and c.get("ip"):
                            resolved_ip = c["ip"]
                            guest.ip_address = resolved_ip
                            db.session.commit()
                            return resolved_ip
        except Exception as e:
            logger.debug(f"UniFi IP resolution failed for {guest.name}: {e}")

    return None


def _ws_send(ws, msg_type, data):
    """Safely send a JSON message over WebSocket."""
    try:
        ws.send(json.dumps({"type": msg_type, "data": data}))
    except Exception:
        pass


@bp.route("/")
@login_required
def index():
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    if current_user.is_admin:
        guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()
    else:
        guests = current_user.accessible_guests()

    return render_template("terminal.html", guests=guests)


@bp.route("/<int:guest_id>")
@login_required
def connect(guest_id):
    if not current_user.can_ssh and not current_user.is_admin:
        flash("You don't have SSH terminal permission.", "error")
        return redirect(url_for("dashboard.index"))

    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to access this guest.", "error")
        return redirect(url_for("terminal.index"))

    # Try to resolve IP if needed
    ip = _resolve_guest_ip(guest)

    # Check if credentials are available
    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    needs_credentials = credential is None

    return render_template("terminal_session.html", guest=guest, resolved_ip=ip, needs_credentials=needs_credentials)


@sock.route("/ws/terminal/<int:guest_id>")
def terminal_ws(ws, guest_id):
    """WebSocket handler for SSH terminal sessions."""
    from flask_login import current_user as ws_user

    ssh_client = None
    channel = None

    try:
        # Auth checks
        if not ws_user.is_authenticated:
            _ws_send(ws, "error", "Not authenticated")
            return

        if not ws_user.can_ssh and not ws_user.is_admin:
            _ws_send(ws, "error", "No SSH permission")
            return

        guest = Guest.query.get(guest_id)
        if not guest:
            _ws_send(ws, "error", "Guest not found")
            return

        if not ws_user.is_admin and not ws_user.can_access_guest(guest):
            _ws_send(ws, "error", "Access denied")
            return

        # Wait for initial config message with optional ad-hoc credentials
        config = {}
        try:
            init_msg = ws.receive(timeout=10)
            if init_msg:
                config = json.loads(init_msg)
        except Exception as e:
            logger.debug(f"Terminal init message receive failed: {e}")

        # Resolve IP
        ssh_host = config.get("host") or None
        if not ssh_host:
            ssh_host = _resolve_guest_ip(guest)

        if not ssh_host:
            _ws_send(ws, "error", "Could not resolve IP address for this guest. Try running discovery again or configure a static IP.")
            return

        logger.info(f"Terminal connecting to {guest.name} at {ssh_host}")

        # Resolve credentials
        adhoc_username = config.get("username")
        adhoc_password = config.get("password")

        credential = None
        if not adhoc_username:
            credential = guest.credential
            if not credential:
                credential = Credential.query.filter_by(is_default=True).first()

        if not credential and not adhoc_username:
            _ws_send(ws, "need_credentials", "No credentials available. Please provide username and password.")
            return

        # Build SSH connection
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": ssh_host,
            "port": 22,
            "timeout": 15,
        }

        if adhoc_username:
            connect_kwargs["username"] = adhoc_username
            if adhoc_password:
                connect_kwargs["password"] = adhoc_password
        else:
            connect_kwargs["username"] = credential.username
            decrypted_value = decrypt(credential.encrypted_value)
            if credential.auth_type == "password":
                connect_kwargs["password"] = decrypted_value
            else:
                key_file = io.StringIO(decrypted_value)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file)
                except paramiko.SSHException:
                    key_file.seek(0)
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key(key_file)
                    except paramiko.SSHException:
                        key_file.seek(0)
                        pkey = paramiko.ECDSAKey.from_private_key(key_file)
                connect_kwargs["pkey"] = pkey

        logger.info(f"Terminal SSH connecting as {connect_kwargs.get('username')} to {ssh_host}")
        ssh_client.connect(**connect_kwargs)
        channel = ssh_client.invoke_shell(term="xterm-256color", width=120, height=40)

        _ws_send(ws, "connected", f"Connected to {guest.name} ({ssh_host})")
        logger.info(f"Terminal SSH connected to {guest.name} ({ssh_host})")

        # Read thread: SSH -> WebSocket
        def read_from_ssh():
            try:
                while True:
                    if channel.recv_ready():
                        data = channel.recv(4096).decode("utf-8", errors="replace")
                        if data:
                            ws.send(json.dumps({"type": "output", "data": data}))
                    if channel.closed:
                        break
                    channel.settimeout(0.1)
                    try:
                        channel.recv(0)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"SSH read thread ended: {e}")
            finally:
                _ws_send(ws, "disconnected", "SSH session closed")

        read_thread = threading.Thread(target=read_from_ssh, daemon=True)
        read_thread.start()

        # Main loop: WebSocket -> SSH
        while True:
            try:
                message = ws.receive(timeout=1)
                if message is None:
                    break
                msg = json.loads(message)
                if msg.get("type") == "input":
                    channel.send(msg["data"])
                elif msg.get("type") == "resize":
                    cols = msg.get("cols", 120)
                    rows = msg.get("rows", 40)
                    channel.resize_pty(width=cols, height=rows)
            except json.JSONDecodeError:
                continue
            except Exception:
                break

    except paramiko.AuthenticationException:
        logger.warning(f"Terminal SSH auth failed for guest {guest_id}")
        _ws_send(ws, "error", "SSH authentication failed. Check credentials.")
    except paramiko.SSHException as e:
        logger.warning(f"Terminal SSH error for guest {guest_id}: {e}")
        _ws_send(ws, "error", f"SSH error: {e}")
    except Exception as e:
        logger.error(f"Terminal connection error for guest {guest_id}: {e}", exc_info=True)
        _ws_send(ws, "error", f"Connection failed: {e}")
    finally:
        if channel:
            try:
                channel.close()
            except Exception:
                pass
        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass
        try:
            ws.close()
        except Exception:
            pass
