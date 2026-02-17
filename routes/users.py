from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, User, Tag

bp = Blueprint("users", __name__)


def admin_required(f):
    """Decorator to require admin access."""
    from functools import wraps

    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.index"))
        return f(*args, **kwargs)
    return decorated


@bp.route("/")
@admin_required
def index():
    users = User.query.order_by(User.username).all()
    tags = Tag.query.order_by(Tag.name).all()
    return render_template("users.html", users=users, tags=tags)


@bp.route("/add", methods=["POST"])
@admin_required
def add():
    username = request.form.get("username", "").strip().lower()
    display_name = request.form.get("display_name", "").strip()
    password = request.form.get("password", "")
    is_admin = "is_admin" in request.form
    can_ssh = "can_ssh" in request.form
    can_update = "can_update" in request.form
    tag_ids = request.form.getlist("tag_ids")

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
        is_admin=is_admin,
        can_ssh=can_ssh,
        can_update=can_update,
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
@admin_required
def edit(user_id):
    user = User.query.get_or_404(user_id)

    user.display_name = request.form.get("display_name", user.display_name).strip()
    user.is_admin = "is_admin" in request.form
    user.can_ssh = "can_ssh" in request.form
    user.can_update = "can_update" in request.form
    user.is_active_user = "is_active" in request.form

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
@admin_required
def delete(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users.index"))

    user = User.query.get_or_404(user_id)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{username}' deleted.", "warning")
    return redirect(url_for("users.index"))


# --- Tag management ---

@bp.route("/tags/add", methods=["POST"])
@admin_required
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
@admin_required
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    name = tag.name
    db.session.delete(tag)
    db.session.commit()
    flash(f"Tag '{name}' deleted.", "warning")
    return redirect(url_for("users.index"))
