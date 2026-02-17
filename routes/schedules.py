from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from models import db, MaintenanceWindow

bp = Blueprint("schedules", __name__)


@bp.before_request
@login_required
def _require_login():
    pass


@bp.route("/")
def index():
    schedules = MaintenanceWindow.query.order_by(MaintenanceWindow.name).all()
    return render_template("schedules.html", schedules=schedules)


@bp.route("/add", methods=["POST"])
def add():
    name = request.form.get("name", "").strip()
    day_of_week = request.form.get("day_of_week", "sunday")
    start_time = request.form.get("start_time", "02:00")
    end_time = request.form.get("end_time", "05:00")
    update_type = request.form.get("update_type", "upgrade")

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("schedules.index"))

    window = MaintenanceWindow(
        name=name,
        day_of_week=day_of_week,
        start_time=start_time,
        end_time=end_time,
        update_type=update_type,
    )
    db.session.add(window)
    db.session.commit()

    flash(f"Maintenance schedule '{name}' created.", "success")
    return redirect(url_for("schedules.index"))


@bp.route("/<int:schedule_id>/toggle", methods=["POST"])
def toggle(schedule_id):
    window = MaintenanceWindow.query.get_or_404(schedule_id)
    window.enabled = not window.enabled
    db.session.commit()
    state = "enabled" if window.enabled else "disabled"
    flash(f"Schedule '{window.name}' {state}.", "success")
    return redirect(url_for("schedules.index"))


@bp.route("/<int:schedule_id>/delete", methods=["POST"])
def delete(schedule_id):
    window = MaintenanceWindow.query.get_or_404(schedule_id)
    name = window.name
    db.session.delete(window)
    db.session.commit()
    flash(f"Schedule '{name}' deleted.", "warning")
    return redirect(url_for("schedules.index"))
