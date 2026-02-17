import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models import Setting
from credential_store import decrypt

logger = logging.getLogger(__name__)

GMAIL_SMTP_SERVER = "smtp.gmail.com"
GMAIL_SMTP_PORT = 587


def _get_email_config():
    gmail_address = Setting.get("gmail_address")
    gmail_app_password_enc = Setting.get("gmail_app_password")
    recipients = Setting.get("email_recipients", "")
    enabled = Setting.get("email_enabled", "false") == "true"

    gmail_app_password = decrypt(gmail_app_password_enc) if gmail_app_password_enc else None

    return {
        "address": gmail_address,
        "password": gmail_app_password,
        "recipients": [r.strip() for r in recipients.split(",") if r.strip()],
        "enabled": enabled,
    }


def _send_email(subject, html_body):
    config = _get_email_config()

    if not config["enabled"]:
        return False, "Email notifications are disabled"

    if not config["address"] or not config["password"]:
        return False, "Gmail address or App Password not configured"

    if not config["recipients"]:
        return False, "No recipients configured"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"LambNet Update Manager <{config['address']}>"
    msg["To"] = ", ".join(config["recipients"])

    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(GMAIL_SMTP_SERVER, GMAIL_SMTP_PORT) as server:
            server.starttls()
            server.login(config["address"], config["password"])
            server.sendmail(config["address"], config["recipients"], msg.as_string())
        return True, "Email sent successfully"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed. Check your Gmail App Password."
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False, str(e)


def send_test_email():
    html = """
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1a1a2e; color: #e0e0e0; padding: 20px; border-radius: 8px;">
            <h2 style="color: #4fc3f7; margin-top: 0;">LambNet Update Manager</h2>
            <p>This is a test email from your LambNet Proxmox Update Manager.</p>
            <p style="color: #81c784;">Email notifications are working correctly!</p>
        </div>
    </div>
    """
    return _send_email("LambNet Update Manager - Test Notification", html)


def send_update_notification(scan_results):
    """Send notification about available updates after a scan."""
    config = _get_email_config()
    if not config["enabled"]:
        return

    # Filter to only guests with updates
    guests_with_updates = []
    total_updates = 0
    total_security = 0

    for result in scan_results:
        if result.status == "success" and result.total_updates > 0:
            guests_with_updates.append(result)
            total_updates += result.total_updates
            total_security += result.security_updates

    if not guests_with_updates:
        return

    # Build HTML email
    rows = ""
    for result in guests_with_updates:
        guest = result.guest
        severity_color = "#dc3545" if result.security_updates > 0 else "#ffc107"
        rows += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #333;">{guest.name}</td>
            <td style="padding: 8px; border-bottom: 1px solid #333;">{guest.guest_type.upper()}</td>
            <td style="padding: 8px; border-bottom: 1px solid #333;">{result.total_updates}</td>
            <td style="padding: 8px; border-bottom: 1px solid #333; color: {severity_color}; font-weight: bold;">{result.security_updates}</td>
        </tr>
        """

    severity_banner = ""
    if total_security > 0:
        severity_banner = f"""
        <div style="background: #dc3545; color: white; padding: 12px; border-radius: 4px; margin-bottom: 16px;">
            <strong>CRITICAL:</strong> {total_security} security update(s) require immediate attention!
        </div>
        """

    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 700px; margin: 0 auto;">
        <div style="background: #1a1a2e; color: #e0e0e0; padding: 20px; border-radius: 8px;">
            <h2 style="color: #4fc3f7; margin-top: 0;">LambNet Update Manager - Updates Available</h2>

            {severity_banner}

            <p><strong>{total_updates}</strong> update(s) available across <strong>{len(guests_with_updates)}</strong> guest(s).</p>

            <table style="width: 100%; border-collapse: collapse; background: #16213e; border-radius: 4px;">
                <thead>
                    <tr style="background: #0f3460;">
                        <th style="padding: 10px; text-align: left; color: #4fc3f7;">Guest</th>
                        <th style="padding: 10px; text-align: left; color: #4fc3f7;">Type</th>
                        <th style="padding: 10px; text-align: left; color: #4fc3f7;">Updates</th>
                        <th style="padding: 10px; text-align: left; color: #4fc3f7;">Security</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>

            <p style="margin-top: 16px; color: #888; font-size: 12px;">
                Log in to your LambNet Update Manager to review and apply updates.
            </p>
        </div>
    </div>
    """

    subject = f"[LambNet] {total_updates} update(s) available"
    if total_security > 0:
        subject = f"[LambNet] CRITICAL: {total_security} security update(s) available"

    ok, msg = _send_email(subject, html)
    if ok:
        logger.info(f"Update notification sent to {len(config['recipients'])} recipient(s)")
    else:
        logger.error(f"Failed to send update notification: {msg}")


def send_mastodon_update_notification(current_version, new_version, release_url):
    """Send email notification about a new Mastodon release."""
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1a1a2e; color: #e0e0e0; padding: 20px; border-radius: 8px;">
            <h2 style="color: #4fc3f7; margin-top: 0;">Mastodon Update Available</h2>

            <div style="background: #16213e; border-radius: 4px; padding: 16px; margin-bottom: 16px;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 6px 0; color: #888;">Current Version</td>
                        <td style="padding: 6px 0; font-weight: bold;">v{current_version or 'unknown'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #888;">New Version</td>
                        <td style="padding: 6px 0; font-weight: bold; color: #ffc107;">v{new_version}</td>
                    </tr>
                </table>
            </div>

            <p>A new Mastodon release is available. {"Auto-upgrade is enabled and will run shortly." if _mastodon_auto_enabled() else "Log in to LambNet Update Manager to upgrade."}</p>

            {f'<p><a href="{release_url}" style="color: #4fc3f7;">View release notes on GitHub</a></p>' if release_url else ''}

            <p style="margin-top: 16px; color: #888; font-size: 12px;">
                Sent by LambNet Proxmox Update Manager
            </p>
        </div>
    </div>
    """
    subject = f"[LambNet] Mastodon update available: v{new_version}"
    ok, msg = _send_email(subject, html)
    if ok:
        logger.info(f"Mastodon update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Mastodon update notification: {msg}")
    return ok, msg


def _mastodon_auto_enabled():
    return Setting.get("mastodon_auto_upgrade", "false") == "true"


def send_app_update_notification(current_version, new_version):
    """Send email notification about a new LambNet release."""
    auto_update = Setting.get("app_auto_update", "false") == "true"
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1a1a2e; color: #e0e0e0; padding: 20px; border-radius: 8px;">
            <h2 style="color: #4fc3f7; margin-top: 0;">LambNet Update Available</h2>

            <div style="background: #16213e; border-radius: 4px; padding: 16px; margin-bottom: 16px;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 6px 0; color: #888;">Current Version</td>
                        <td style="padding: 6px 0; font-weight: bold;">v{current_version}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #888;">New Version</td>
                        <td style="padding: 6px 0; font-weight: bold; color: #ffc107;">v{new_version}</td>
                    </tr>
                </table>
            </div>

            <p>{"Auto-update is enabled. The application will update and restart shortly." if auto_update else "Log in to LambNet Update Manager and go to Settings to apply the update."}</p>

            <p style="margin-top: 16px; color: #888; font-size: 12px;">
                Sent by LambNet Proxmox Update Manager
            </p>
        </div>
    </div>
    """
    subject = f"[LambNet] Application update available: v{new_version}"
    ok, msg = _send_email(subject, html)
    if ok:
        logger.info(f"App update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send app update notification: {msg}")
    return ok, msg
