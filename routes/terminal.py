import json
import threading
import logging
import paramiko
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from flask_sock import Sock
from models import Guest, Credential
from credential_store import decrypt

logger = logging.getLogger(__name__)

bp = Blueprint("terminal", __name__)
sock = Sock()


def init_websocket(app):
    """Initialize the WebSocket handler on the app."""
    sock.init_app(app)


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

    # Filter to guests with IP addresses (required for SSH)
    guests = [g for g in guests if g.ip_address]
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

    if not guest.ip_address:
        flash("This guest has no IP address configured.", "error")
        return redirect(url_for("terminal.index"))

    return render_template("terminal_session.html", guest=guest)


@sock.route("/ws/terminal/<int:guest_id>")
def terminal_ws(ws, guest_id):
    """WebSocket handler for SSH terminal sessions."""
    # Note: WebSocket auth is handled by checking session cookie
    from flask_login import current_user as ws_user

    if not ws_user.is_authenticated:
        ws.send(json.dumps({"type": "error", "data": "Not authenticated"}))
        ws.close()
        return

    if not ws_user.can_ssh and not ws_user.is_admin:
        ws.send(json.dumps({"type": "error", "data": "No SSH permission"}))
        ws.close()
        return

    guest = Guest.query.get(guest_id)
    if not guest:
        ws.send(json.dumps({"type": "error", "data": "Guest not found"}))
        ws.close()
        return

    if not ws_user.is_admin and not ws_user.can_access_guest(guest):
        ws.send(json.dumps({"type": "error", "data": "Access denied"}))
        ws.close()
        return

    # Get credential
    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        ws.send(json.dumps({"type": "error", "data": "No credential available for this guest"}))
        ws.close()
        return

    # Connect via SSH
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": guest.ip_address,
            "port": 22,
            "username": credential.username,
            "timeout": 15,
        }

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

        ssh_client.connect(**connect_kwargs)
        channel = ssh_client.invoke_shell(term="xterm-256color", width=120, height=40)

        ws.send(json.dumps({"type": "connected", "data": f"Connected to {guest.name} ({guest.ip_address})"}))

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
                try:
                    ws.send(json.dumps({"type": "disconnected", "data": "SSH session closed"}))
                except Exception:
                    pass

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
        ws.send(json.dumps({"type": "error", "data": "SSH authentication failed"}))
    except paramiko.SSHException as e:
        ws.send(json.dumps({"type": "error", "data": f"SSH error: {e}"}))
    except Exception as e:
        ws.send(json.dumps({"type": "error", "data": f"Connection failed: {e}"}))
    finally:
        try:
            channel.close()
        except Exception:
            pass
        try:
            ssh_client.close()
        except Exception:
            pass
        try:
            ws.close()
        except Exception:
            pass
