import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required
from models import db, Setting
from credential_store import encrypt
from config import BASE_DIR

bp = Blueprint("settings", __name__)


@bp.before_request
@login_required
def _require_login():
    pass


def _get_settings_dict():
    return {
        "gmail_address": Setting.get("gmail_address"),
        "gmail_app_password": Setting.get("gmail_app_password"),
        "email_recipients": Setting.get("email_recipients"),
        "email_enabled": Setting.get("email_enabled", "false"),
        "scan_interval": Setting.get("scan_interval", "6"),
        "scan_enabled": Setting.get("scan_enabled", "true"),
        "cf_access_enabled": Setting.get("cf_access_enabled", "false"),
        "cf_access_team_domain": Setting.get("cf_access_team_domain", ""),
        "cf_access_audience": Setting.get("cf_access_audience", ""),
        "cf_access_auto_provision": Setting.get("cf_access_auto_provision", "true"),
        "cf_access_bypass_local_auth": Setting.get("cf_access_bypass_local_auth", "false"),
        "local_bypass_enabled": Setting.get("local_bypass_enabled", "true"),
        "trusted_subnets": Setting.get("trusted_subnets", "10.0.0.0/8"),
    }


@bp.route("/")
def index():
    settings = _get_settings_dict()
    return render_template("settings.html", settings=settings, update_available=False, update_version=None)


@bp.route("/email", methods=["POST"])
def save_email():
    gmail_address = request.form.get("gmail_address", "").strip()
    gmail_app_password = request.form.get("gmail_app_password", "").strip()
    recipients = request.form.get("email_recipients", "").strip()
    enabled = "email_enabled" in request.form

    Setting.set("gmail_address", gmail_address)
    if gmail_app_password:
        Setting.set("gmail_app_password", encrypt(gmail_app_password))
    Setting.set("email_recipients", recipients)
    Setting.set("email_enabled", "true" if enabled else "false")

    flash("Email settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/email/test", methods=["POST"])
def test_email():
    # Save settings first
    save_email()

    from notifier import send_test_email
    ok, message = send_test_email()
    if ok:
        flash(f"Test email sent: {message}", "success")
    else:
        flash(f"Test email failed: {message}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/scan", methods=["POST"])
def save_scan():
    interval = request.form.get("scan_interval", "6").strip()
    enabled = "scan_enabled" in request.form

    Setting.set("scan_interval", interval)
    Setting.set("scan_enabled", "true" if enabled else "false")

    flash("Scan settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/local-bypass", methods=["POST"])
def save_local_bypass():
    import ipaddress

    enabled = "local_bypass_enabled" in request.form
    subnets = request.form.get("trusted_subnets", "10.0.0.0/8").strip()

    # Validate subnets
    if subnets:
        for entry in subnets.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                flash(f"Invalid subnet: {entry}", "error")
                return redirect(url_for("settings.index"))

    Setting.set("local_bypass_enabled", "true" if enabled else "false")
    Setting.set("trusted_subnets", subnets)

    flash("Local network access settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/cloudflare", methods=["POST"])
def save_cloudflare():
    cf_enabled = "cf_access_enabled" in request.form
    team_domain = request.form.get("cf_access_team_domain", "").strip()
    audience = request.form.get("cf_access_audience", "").strip()
    auto_provision = "cf_access_auto_provision" in request.form
    bypass_local = "cf_access_bypass_local_auth" in request.form

    # Validate before enabling bypass mode
    if bypass_local and cf_enabled:
        if not team_domain or not audience:
            flash("Team domain and audience tag are required to enable CF Access-only mode.", "error")
            return redirect(url_for("settings.index"))

    Setting.set("cf_access_enabled", "true" if cf_enabled else "false")
    Setting.set("cf_access_team_domain", team_domain)
    Setting.set("cf_access_audience", audience)
    Setting.set("cf_access_auto_provision", "true" if auto_provision else "false")
    Setting.set("cf_access_bypass_local_auth", "true" if bypass_local else "false")

    flash("Cloudflare Zero Trust settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/check-update", methods=["POST"])
def check_update():
    import urllib.request
    import json

    repo = current_app.config.get("GITHUB_REPO", "")
    current_version = current_app.config.get("APP_VERSION", "0.0.0")

    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "LambNet-Update-Manager"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != current_version:
                settings = _get_settings_dict()
                return render_template("settings.html", settings=settings, update_available=True, update_version=latest)
            flash(f"You are running the latest version (v{current_version}).", "success")
    except Exception as e:
        flash(f"Could not check for updates: {e}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/apply-update", methods=["POST"])
def apply_update():
    import os
    update_script = os.path.join(BASE_DIR, "update.sh")
    if os.path.exists(update_script):
        try:
            subprocess.Popen(["bash", update_script], cwd=BASE_DIR)
            flash("Update started. The application will restart shortly.", "info")
        except Exception as e:
            flash(f"Update failed: {e}", "error")
    else:
        flash("Update script not found.", "error")

    return redirect(url_for("settings.index"))
