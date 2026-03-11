from flask_login import current_user

from auth.local_network import _get_client_ip
from models import AuditLog, db


def log_action(action, resource_type, resource_id=None, resource_name=None, details=None):
    """Add an AuditLog entry to the current db.session.

    Call before db.session.commit() so the log entry is committed atomically
    with the main change.  Also broadcasts the action to the real-time
    collaboration hub so connected users see it instantly.
    """
    db.session.add(AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details,
        ip_address=_get_client_ip(),
    ))

    # Broadcast to collaboration hub (best-effort — never breaks the audit write)
    try:
        import datetime as _dt

        from core.collaboration import collab_hub
        collab_hub.broadcast({
            "type": "activity",
            "action": action,
            "resource_type": resource_type,
            "resource_name": resource_name or "",
            "username": (current_user.display_name or current_user.username) if current_user.is_authenticated else "anonymous",
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        })
    except Exception:
        pass
