from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from models import Setting

bp = Blueprint("applications", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_update:
        flash("Permission denied.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    apps = {
        "mastodon": {
            "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false") == "true",
            "update_available": Setting.get("mastodon_update_available", "false") == "true",
            "current_version": Setting.get("mastodon_current_version", ""),
            "latest_version": Setting.get("mastodon_latest_version", ""),
        },
        "ghost": {
            "auto_upgrade": Setting.get("ghost_auto_upgrade", "false") == "true",
            "update_available": Setting.get("ghost_update_available", "false") == "true",
            "current_version": Setting.get("ghost_current_version", ""),
            "latest_version": Setting.get("ghost_latest_version", ""),
        },
        "peertube": {
            "auto_upgrade": Setting.get("peertube_auto_upgrade", "false") == "true",
            "update_available": Setting.get("peertube_update_available", "false") == "true",
            "current_version": Setting.get("peertube_current_version", ""),
            "latest_version": Setting.get("peertube_latest_version", ""),
        },
    }
    return render_template("applications.html", apps=apps)
