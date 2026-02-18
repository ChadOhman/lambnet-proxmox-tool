import os
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from models import db, Setting
from credential_store import encrypt
from config import BASE_DIR, DATA_DIR

bp = Blueprint("settings", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_manage_settings:
        flash("Super admin access required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_settings_dict():
    return {
        "gmail_address": Setting.get("gmail_address"),
        "gmail_app_password": Setting.get("gmail_app_password"),
        "email_recipients": Setting.get("email_recipients"),
        "email_enabled": Setting.get("email_enabled", "false"),
        "scan_interval": Setting.get("scan_interval", "6"),
        "scan_enabled": Setting.get("scan_enabled", "true"),
        "discovery_interval": Setting.get("discovery_interval", "4"),
        "discovery_enabled": Setting.get("discovery_enabled", "true"),
        "service_check_interval": Setting.get("service_check_interval", "5"),
        "service_check_enabled": Setting.get("service_check_enabled", "true"),
        "cf_access_enabled": Setting.get("cf_access_enabled", "false"),
        "cf_access_team_domain": Setting.get("cf_access_team_domain", ""),
        "cf_access_audience": Setting.get("cf_access_audience", ""),
        "cf_access_auto_provision": Setting.get("cf_access_auto_provision", "true"),
        "cf_access_bypass_local_auth": Setting.get("cf_access_bypass_local_auth", "false"),
        "local_bypass_enabled": Setting.get("local_bypass_enabled", "true"),
        "trusted_subnets": Setting.get("trusted_subnets", "10.0.0.0/8"),
        "unifi_enabled": Setting.get("unifi_enabled", "false"),
        "unifi_base_url": Setting.get("unifi_base_url", ""),
        "unifi_username": Setting.get("unifi_username", ""),
        "unifi_password": Setting.get("unifi_password", ""),
        "unifi_site": Setting.get("unifi_site", "default"),
        "unifi_is_udm": Setting.get("unifi_is_udm", "true"),
        "unifi_filter_subnet": Setting.get("unifi_filter_subnet", ""),
        "app_auto_update": Setting.get("app_auto_update", "false"),
        "app_update_branch": Setting.get("app_update_branch", ""),
    }


def _get_latest_release():
    """Fetch the latest release version from GitHub. Returns version string or None."""
    import urllib.request
    import json
    repo = current_app.config.get("GITHUB_REPO", "")
    if not repo:
        return None
    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("tag_name", "").lstrip("v") or None
    except Exception:
        return None


@bp.route("/")
def index():
    settings = _get_settings_dict()
    latest_release = _get_latest_release()
    return render_template("settings.html", settings=settings, update_available=False, update_version=None, latest_release=latest_release)


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
    discovery_interval = request.form.get("discovery_interval", "4").strip()
    discovery_enabled = "discovery_enabled" in request.form

    service_check_interval = request.form.get("service_check_interval", "5").strip()
    service_check_enabled = "service_check_enabled" in request.form

    Setting.set("scan_interval", interval)
    Setting.set("scan_enabled", "true" if enabled else "false")
    Setting.set("discovery_interval", discovery_interval)
    Setting.set("discovery_enabled", "true" if discovery_enabled else "false")
    Setting.set("service_check_interval", service_check_interval)
    Setting.set("service_check_enabled", "true" if service_check_enabled else "false")

    flash("Scan & discovery settings saved.", "success")
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


@bp.route("/unifi", methods=["POST"])
def save_unifi():
    enabled = "unifi_enabled" in request.form
    base_url = request.form.get("unifi_base_url", "").strip()
    username = request.form.get("unifi_username", "").strip()
    password = request.form.get("unifi_password", "").strip()
    site = request.form.get("unifi_site", "default").strip()
    is_udm = "unifi_is_udm" in request.form
    filter_subnet = request.form.get("unifi_filter_subnet", "").strip()

    Setting.set("unifi_enabled", "true" if enabled else "false")
    Setting.set("unifi_base_url", base_url)
    Setting.set("unifi_username", username)
    if password:
        Setting.set("unifi_password", encrypt(password))
    Setting.set("unifi_site", site or "default")
    Setting.set("unifi_is_udm", "true" if is_udm else "false")
    Setting.set("unifi_filter_subnet", filter_subnet)

    flash("UniFi settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unifi/test", methods=["POST"])
def test_unifi():
    save_unifi()

    from credential_store import decrypt
    from unifi_client import UniFiClient

    base_url = Setting.get("unifi_base_url", "")
    username = Setting.get("unifi_username", "")
    encrypted_pw = Setting.get("unifi_password", "")
    site = Setting.get("unifi_site", "default")
    is_udm = Setting.get("unifi_is_udm", "true") == "true"

    if not base_url or not username or not encrypted_pw:
        flash("UniFi controller URL, username, and password are required.", "error")
        return redirect(url_for("settings.index"))

    password = decrypt(encrypted_pw)
    client = UniFiClient(base_url, username, password, site=site, is_udm=is_udm)
    ok, msg = client.test_connection()

    if ok:
        flash(f"UniFi connection successful: {msg}", "success")
    else:
        flash(f"UniFi connection failed: {msg}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/app-update-mode", methods=["POST"])
def save_app_update_mode():
    auto_update = "app_auto_update" in request.form
    update_branch = request.form.get("app_update_branch", "").strip()
    Setting.set("app_auto_update", "true" if auto_update else "false")
    Setting.set("app_update_branch", update_branch)
    flash(f"Application update settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/check-update", methods=["POST"])
def check_update():
    import urllib.request
    import json

    # Also save the settings from the same form
    auto_update = "app_auto_update" in request.form
    update_branch = request.form.get("app_update_branch", "").strip()
    Setting.set("app_auto_update", "true" if auto_update else "false")
    Setting.set("app_update_branch", update_branch)

    repo = current_app.config.get("GITHUB_REPO", "")
    current_version = current_app.config.get("APP_VERSION", "0.0.0")

    # If a branch is configured, check if it has new commits instead of releases
    if update_branch:
        try:
            url = f"https://api.github.com/repos/{repo}/branches/{update_branch}"
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                sha = data.get("commit", {}).get("sha", "")[:8]
                message = data.get("commit", {}).get("commit", {}).get("message", "").split("\n")[0]
                current_commit = current_app.config.get("GIT_COMMIT", "")
                if current_commit and sha == current_commit:
                    flash(f"Already up to date on branch '{update_branch}' ({sha}).", "success")
                    return redirect(url_for("settings.index"))
                settings = _get_settings_dict()
                return render_template(
                    "settings.html", settings=settings,
                    update_available=True,
                    update_version=f"branch '{update_branch}' (latest: {sha} - {message})",
                    latest_release=_get_latest_release(),
                )
        except Exception as e:
            flash(f"Could not check branch '{update_branch}': {e}", "error")
            return redirect(url_for("settings.index"))

    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != current_version:
                settings = _get_settings_dict()
                return render_template("settings.html", settings=settings, update_available=True, update_version=latest, latest_release=latest)
            flash(f"You are running the latest version (v{current_version}).", "success")
    except Exception as e:
        flash(f"Could not check for updates: {e}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/apply-update", methods=["POST"])
def apply_update():
    update_script = os.path.join(BASE_DIR, "update.sh")
    if not os.path.exists(update_script):
        flash("Update script not found.", "error")
        return redirect(url_for("settings.index"))

    try:
        update_branch = Setting.get("app_update_branch", "")
        cmd = ["bash", update_script]
        if update_branch:
            cmd += ["--branch", update_branch]

        proc = subprocess.Popen(cmd, cwd=BASE_DIR)

        # Write PID marker so we can track the process
        pid_file = os.path.join(DATA_DIR, "update.pid")
        with open(pid_file, "w") as f:
            f.write(str(proc.pid))

    except Exception as e:
        flash(f"Update failed to start: {e}", "error")
        return redirect(url_for("settings.index"))

    return redirect(url_for("settings.update_progress"))


@bp.route("/update-progress")
def update_progress():
    return render_template("update_progress.html")


@bp.route("/update-status")
def update_status():
    log_file = os.path.join(DATA_DIR, "update.log")
    pid_file = os.path.join(DATA_DIR, "update.pid")

    # Read log contents
    log_text = ""
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                log_text = f.read()
        except Exception:
            log_text = ""

    # Check if process is still running
    running = False
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # signal 0 = check if process exists
            running = True
        except (ProcessLookupError, ValueError, PermissionError):
            running = False

    return jsonify({
        "log": log_text,
        "running": running,
        "line_count": log_text.count("\n"),
    })
