from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

bp = Blueprint("applications", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_update:
        flash("Permission denied.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    return render_template("applications.html")
