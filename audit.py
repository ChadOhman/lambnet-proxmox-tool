from flask import request
from flask_login import current_user
from models import db, AuditLog


def log_action(action, resource_type, resource_id=None, resource_name=None, details=None):
    """Add an AuditLog entry to the current db.session.

    Call before db.session.commit() so the log entry is committed atomically
    with the main change.
    """
    db.session.add(AuditLog(
        user_id=current_user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details,
        ip_address=request.remote_addr,
    ))
