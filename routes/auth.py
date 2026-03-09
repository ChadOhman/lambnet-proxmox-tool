import collections
import threading
import time
import zoneinfo
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from auth.audit import log_action

bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# Login rate-limiting (in-process; works with single gunicorn worker / gthread)
# ---------------------------------------------------------------------------
_FAIL_WINDOW = 300   # 5-minute sliding window
_FAIL_LIMIT = 10     # failed attempts before lockout

_failed_attempts: dict = collections.defaultdict(list)
_failed_lock = threading.Lock()


def _check_rate_limit(ip: str) -> bool:
    """Return True if this IP is currently locked out."""
    cutoff = time.time() - _FAIL_WINDOW
    with _failed_lock:
        _failed_attempts[ip] = [t for t in _failed_attempts[ip] if t > cutoff]
        return len(_failed_attempts[ip]) >= _FAIL_LIMIT


def _record_failed_login(ip: str) -> None:
    with _failed_lock:
        _failed_attempts[ip].append(time.time())


def _get_client_ip() -> str:
    """Return the real client IP, respecting proxy headers only from trusted sources.

    Only trust CF-Connecting-IP / X-Forwarded-For when the direct connection is
    from a loopback or private address (i.e. a reverse proxy).  This prevents
    external clients from spoofing headers to bypass rate limiting.
    """
    import ipaddress

    remote_addr = request.remote_addr or "unknown"

    try:
        remote_ip = ipaddress.ip_address(remote_addr)
        trust_forwarded = remote_ip.is_loopback or remote_ip.is_private
    except ValueError:
        return remote_addr

    if trust_forwarded:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return remote_addr


def _is_safe_next_url(target):
    """Allow redirects only to local paths."""
    if not target:
        return False
    parsed = urlparse(target)
    return parsed.scheme == "" and parsed.netloc == "" and target.startswith("/")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        ip = _get_client_ip()
        if _check_rate_limit(ip):
            flash("Too many failed login attempts. Please try again later.", "error")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            # Regenerate session to prevent session fixation attacks
            session.clear()
            login_user(user, remember="remember" in request.form)
            log_action("login", "user", resource_id=user.id, resource_name=user.username)
            db.session.commit()
            next_page = request.args.get("next")
            if _is_safe_next_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))

        _record_failed_login(ip)
        log_action("login_failed", "user",
                   resource_id=user.id if user else None,
                   resource_name=username,
                   details={"reason": "inactive" if user and not user.is_active else "bad_credentials"})
        db.session.commit()
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("logout", "user", resource_id=current_user.id, resource_name=current_user.username)
    db.session.commit()
    is_cf_user = current_user.created_via == "cloudflare"
    logout_user()
    if is_cf_user:
        from models import Setting
        team_domain = Setting.get("cf_access_team_domain", "")
        if team_domain and team_domain.endswith(".cloudflareaccess.com"):
            return redirect(f"https://{team_domain}/cdn-cgi/access/logout")
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if current_user.created_via == "cloudflare":
        flash("Password management is not available for Cloudflare-authenticated accounts.", "error")
        return redirect(url_for("auth.profile"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_user.check_password(current_pw):
            flash("Current password is incorrect.", "error")
        elif new_pw != confirm_pw:
            flash("New passwords do not match.", "error")
        elif len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "error")
        else:
            current_user.set_password(new_pw)
            log_action("password_change", "user", resource_id=current_user.id, resource_name=current_user.username)
            db.session.commit()
            flash("Password changed successfully.", "success")
            return redirect(url_for("dashboard.index"))

    return render_template("change_password.html")


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        tz = request.form.get("timezone", "").strip()
        if tz and tz not in zoneinfo.available_timezones():
            flash("Invalid timezone.", "error")
            return redirect(url_for("auth.profile"))
        current_user.timezone = tz or None
        db.session.commit()
        flash("Profile saved.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("profile.html")
