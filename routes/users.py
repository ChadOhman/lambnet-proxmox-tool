from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, User, Tag

bp = Blueprint("users", __name__)

VALID_ROLES = ("super_admin", "admin", "operator", "viewer")


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_manage_users:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    # Only show users at or below the current user's role level
    users = User.query.order_by(User.username).all()
    tags = Tag.query.order_by(Tag.name).all()
    return render_template("users.html", users=users, tags=tags)


@bp.route("/add", methods=["POST"])
def add():
    username = request.form.get("username", "").strip().lower()
    display_name = request.form.get("display_name", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    tag_ids = request.form.getlist("tag_ids")

    if role not in VALID_ROLES:
        role = "viewer"

    # Cannot assign a role equal to or higher than your own (unless super_admin)
    target_level = User.ROLE_LEVELS.get(role, 1)
    if target_level >= current_user.role_level and not current_user.is_super_admin:
        flash("You cannot create a user with an equal or higher role.", "error")
        return redirect(url_for("users.index"))

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("users.index"))

    if User.query.filter_by(username=username).first():
        flash(f"Username '{username}' already exists.", "error")
        return redirect(url_for("users.index"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("users.index"))

    user = User(
        username=username,
        display_name=display_name or username,
        role=role,
    )
    user.set_password(password)

    # Assign tags
    if tag_ids:
        tags = Tag.query.filter(Tag.id.in_([int(t) for t in tag_ids])).all()
        user.allowed_tags = tags

    db.session.add(user)
    db.session.commit()

    flash(f"User '{username}' created.", "success")
    return redirect(url_for("users.index"))


@bp.route("/<int:user_id>/edit", methods=["POST"])
def edit(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent editing users of equal or higher role (unless editing self or super_admin)
    if not current_user.can_edit_user(user):
        flash("You cannot edit a user with an equal or higher role.", "error")
        return redirect(url_for("users.index"))

    user.display_name = request.form.get("display_name", user.display_name).strip()
    user.is_active_user = "is_active" in request.form

    # Role change (only if not editing self)
    new_role = request.form.get("role", user.role)
    if new_role in VALID_ROLES and user.id != current_user.id:
        target_level = User.ROLE_LEVELS.get(new_role, 1)
        if target_level >= current_user.role_level and not current_user.is_super_admin:
            flash("You cannot assign a role equal to or higher than your own.", "error")
            return redirect(url_for("users.index"))
        user.role = new_role

    tag_ids = request.form.getlist("tag_ids")
    tags = Tag.query.filter(Tag.id.in_([int(t) for t in tag_ids])).all() if tag_ids else []
    user.allowed_tags = tags

    # Optional password reset
    new_password = request.form.get("new_password", "").strip()
    if new_password:
        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("users.index"))
        user.set_password(new_password)

    db.session.commit()
    flash(f"User '{user.username}' updated.", "success")
    return redirect(url_for("users.index"))


@bp.route("/<int:user_id>/delete", methods=["POST"])
def delete(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users.index"))

    user = User.query.get_or_404(user_id)

    if not current_user.can_edit_user(user):
        flash("You cannot delete a user with an equal or higher role.", "error")
        return redirect(url_for("users.index"))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{username}' deleted.", "warning")
    return redirect(url_for("users.index"))


# --- Tag management ---

@bp.route("/tags/add", methods=["POST"])
def add_tag():
    name = request.form.get("name", "").strip()
    color = request.form.get("color", "#6c757d").strip()

    if not name:
        flash("Tag name is required.", "error")
        return redirect(url_for("users.index"))

    if Tag.query.filter_by(name=name).first():
        flash(f"Tag '{name}' already exists.", "error")
        return redirect(url_for("users.index"))

    tag = Tag(name=name, color=color)
    db.session.add(tag)
    db.session.commit()

    flash(f"Tag '{name}' created.", "success")
    return redirect(url_for("users.index"))


@bp.route("/tags/<int:tag_id>/delete", methods=["POST"])
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    name = tag.name
    db.session.delete(tag)
    db.session.commit()
    flash(f"Tag '{name}' deleted.", "warning")
    return redirect(url_for("users.index"))
