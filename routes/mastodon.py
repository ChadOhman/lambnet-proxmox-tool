import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
from models import db, Setting, Guest

logger = logging.getLogger(__name__)

bp = Blueprint("mastodon", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_mastodon_settings():
    return {
        "guest_id": Setting.get("mastodon_guest_id", ""),
        "db_guest_id": Setting.get("mastodon_db_guest_id", ""),
        "user": Setting.get("mastodon_user", "mastodon"),
        "app_dir": Setting.get("mastodon_app_dir", "/home/mastodon/live"),
        "repo": Setting.get("mastodon_repo", "mastodon/mastodon"),
        "pgbouncer_host": Setting.get("mastodon_pgbouncer_host", ""),
        "pgbouncer_port": Setting.get("mastodon_pgbouncer_port", ""),
        "direct_db_host": Setting.get("mastodon_direct_db_host", ""),
        "direct_db_port": Setting.get("mastodon_direct_db_port", "5432"),
        "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false"),
        "current_version": Setting.get("mastodon_current_version", ""),
        "pg_version": Setting.get("mastodon_pg_version", ""),
        "latest_version": Setting.get("mastodon_latest_version", ""),
        "latest_release_url": Setting.get("mastodon_latest_release_url", ""),
        "last_upgrade_at": Setting.get("mastodon_last_upgrade_at", ""),
        "last_upgrade_status": Setting.get("mastodon_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("mastodon_last_upgrade_log", ""),
    }


@bp.route("/")
def index():
    settings = _get_mastodon_settings()
    guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()
    return render_template("mastodon.html", settings=settings, guests=guests)


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("mastodon_guest_id", request.form.get("mastodon_guest_id", "").strip())
    Setting.set("mastodon_db_guest_id", request.form.get("mastodon_db_guest_id", "").strip())
    Setting.set("mastodon_user", request.form.get("mastodon_user", "mastodon").strip())
    Setting.set("mastodon_app_dir", request.form.get("mastodon_app_dir", "/home/mastodon/live").strip())
    Setting.set("mastodon_repo", request.form.get("mastodon_repo", "mastodon/mastodon").strip())
    Setting.set("mastodon_pgbouncer_host", request.form.get("mastodon_pgbouncer_host", "").strip())
    Setting.set("mastodon_pgbouncer_port", request.form.get("mastodon_pgbouncer_port", "").strip())
    Setting.set("mastodon_direct_db_host", request.form.get("mastodon_direct_db_host", "").strip())
    Setting.set("mastodon_direct_db_port", request.form.get("mastodon_direct_db_port", "5432").strip())
    Setting.set("mastodon_auto_upgrade", "true" if "mastodon_auto_upgrade" in request.form else "false")
    Setting.set("mastodon_current_version", request.form.get("mastodon_current_version", "").strip())

    flash("Mastodon settings saved.", "success")
    return redirect(url_for("mastodon.index"))


@bp.route("/check", methods=["POST"])
def check():
    from mastodon import check_mastodon_release

    update_available, latest, release_url = check_mastodon_release()
    current = Setting.get("mastodon_current_version", "")

    if not latest:
        flash("Could not fetch latest Mastodon release from GitHub.", "error")
    elif update_available:
        flash(f"Mastodon update available: v{current} -> v{latest}", "warning")
    elif current:
        flash(f"Mastodon is up to date (v{current}).", "success")
    else:
        flash(f"Latest Mastodon release: v{latest}. Set your current version to enable update detection.", "info")

    return redirect(url_for("mastodon.index"))


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from mastodon import run_mastodon_upgrade

    ok, log_output = run_mastodon_upgrade()

    now = ""
    if ok:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        flash("Mastodon upgrade completed successfully!", "success")
    else:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        Setting.set("mastodon_last_upgrade_at", now)
        Setting.set("mastodon_last_upgrade_status", "error")
        Setting.set("mastodon_last_upgrade_log", log_output)
        db.session.commit()
        flash(f"Mastodon upgrade failed. Check the log for details.", "error")

    return redirect(url_for("mastodon.index"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from scanner import _execute_command

    guest_id = Setting.get("mastodon_guest_id", "")
    db_guest_id = Setting.get("mastodon_db_guest_id", "")
    user = Setting.get("mastodon_user", "mastodon")
    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")

    detected = []

    # Detect Mastodon version
    if guest_id:
        mastodon_guest = Guest.query.get(int(guest_id))
        if mastodon_guest:
            stdout, error = _execute_command(
                mastodon_guest,
                f"sudo -u {user} cat {app_dir}/VERSION 2>/dev/null || sudo -u {user} bash -c 'cd {app_dir} && git describe --tags 2>/dev/null'",
                timeout=15,
            )
            if stdout and not error:
                version = stdout.strip().lstrip("v")
                if version:
                    Setting.set("mastodon_current_version", version)
                    detected.append(f"Mastodon: v{version}")
            elif error:
                logger.warning(f"Mastodon version detection failed: {error}")
                flash(f"Could not detect Mastodon version: {error}", "warning")
        else:
            flash("Mastodon app guest not found.", "error")
    else:
        flash("Mastodon app guest not configured.", "warning")

    # Detect PostgreSQL version
    if db_guest_id:
        db_guest = Guest.query.get(int(db_guest_id))
        if db_guest:
            stdout, error = _execute_command(
                db_guest,
                "psql --version 2>/dev/null || postgres --version 2>/dev/null",
                timeout=15,
            )
            if stdout and not error:
                import re
                match = re.search(r"(\d+[\.\d]*)", stdout.strip())
                if match:
                    pg_version = match.group(1)
                    Setting.set("mastodon_pg_version", pg_version)
                    detected.append(f"PostgreSQL: {pg_version}")
            elif error:
                logger.warning(f"PostgreSQL version detection failed: {error}")
                flash(f"Could not detect PostgreSQL version: {error}", "warning")
        else:
            flash("PostgreSQL guest not found.", "error")
    else:
        flash("PostgreSQL guest not configured.", "warning")

    if detected:
        flash(f"Detected: {', '.join(detected)}", "success")

    return redirect(url_for("mastodon.index"))
