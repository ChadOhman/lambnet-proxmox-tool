from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, Credential
from credential_store import encrypt
from audit import log_action

bp = Blueprint("credentials", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_manage_credentials:
        flash("Super admin access required.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    credentials = Credential.query.order_by(Credential.is_default.desc(), Credential.name).all()
    return render_template("credentials.html", credentials=credentials)


@bp.route("/add", methods=["POST"])
def add():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "root").strip()
    auth_type = request.form.get("auth_type", "password")
    is_default = "is_default" in request.form

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("credentials.index"))

    if auth_type == "password":
        value = request.form.get("password", "")
    else:
        value = request.form.get("private_key", "")

    if not value:
        flash("Password or private key is required.", "error")
        return redirect(url_for("credentials.index"))

    # If setting as default, unset other defaults
    if is_default:
        Credential.query.filter_by(is_default=True).update({"is_default": False})

    sudo_password = request.form.get("sudo_password", "").strip()

    cred = Credential(
        name=name,
        username=username,
        auth_type=auth_type,
        encrypted_value=encrypt(value),
        encrypted_sudo_password=encrypt(sudo_password) if sudo_password else None,
        is_default=is_default,
    )
    db.session.add(cred)
    db.session.flush()
    log_action("credential_add", "credential", resource_id=cred.id, resource_name=name)
    db.session.commit()

    flash(f"Credential '{name}' added.", "success")
    return redirect(url_for("credentials.index"))


@bp.route("/<int:cred_id>/edit", methods=["POST"])
def edit(cred_id):
    cred = Credential.query.get_or_404(cred_id)

    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    auth_type = request.form.get("auth_type", "")
    is_default = "is_default" in request.form

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("credentials.index"))

    cred.name = name
    cred.username = username or cred.username

    # Only update auth type and value if a new value is provided
    if auth_type:
        if auth_type == "password":
            new_value = request.form.get("password", "")
        else:
            new_value = request.form.get("private_key", "")
        if new_value:
            cred.auth_type = auth_type
            cred.encrypted_value = encrypt(new_value)

    # Update sudo password (blank = clear it)
    sudo_password = request.form.get("sudo_password", "").strip()
    if sudo_password:
        cred.encrypted_sudo_password = encrypt(sudo_password)
    elif "clear_sudo_password" in request.form:
        cred.encrypted_sudo_password = None

    if is_default and not cred.is_default:
        Credential.query.filter_by(is_default=True).update({"is_default": False})
        cred.is_default = True
    elif not is_default and cred.is_default:
        cred.is_default = False

    log_action("credential_edit", "credential", resource_id=cred.id, resource_name=name)
    db.session.commit()
    flash(f"Credential '{name}' updated.", "success")
    return redirect(url_for("credentials.index"))


@bp.route("/<int:cred_id>/set-default", methods=["POST"])
def set_default(cred_id):
    Credential.query.filter_by(is_default=True).update({"is_default": False})
    cred = Credential.query.get_or_404(cred_id)
    cred.is_default = True
    log_action("credential_set_default", "credential", resource_id=cred.id, resource_name=cred.name)
    db.session.commit()
    flash(f"'{cred.name}' set as default credential.", "success")
    return redirect(url_for("credentials.index"))


@bp.route("/<int:cred_id>/delete", methods=["POST"])
def delete(cred_id):
    cred = Credential.query.get_or_404(cred_id)
    name = cred.name
    log_action("credential_delete", "credential", resource_id=cred.id, resource_name=name)
    db.session.delete(cred)
    db.session.commit()
    flash(f"Credential '{name}' deleted.", "warning")
    return redirect(url_for("credentials.index"))
