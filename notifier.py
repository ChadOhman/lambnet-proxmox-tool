import json
import logging
import urllib.request
import urllib.error
from models import Setting

logger = logging.getLogger(__name__)

# Discord embed color constants (decimal integers)
_COLOR_GREEN = 8505220   # #81c784
_COLOR_CYAN = 5227511    # #4fc3f7
_COLOR_YELLOW = 16761095  # #ffc107
_COLOR_RED = 14431557    # #dc3545


def _get_discord_config():
    webhook_url = Setting.get("discord_webhook_url")
    enabled = Setting.get("discord_enabled", "false") == "true"
    return {"webhook_url": webhook_url, "enabled": enabled}


def _send_discord(embeds):
    """POST embeds to the configured Discord webhook. Returns (ok, message)."""
    config = _get_discord_config()

    if not config["enabled"]:
        return False, "Discord notifications are disabled"

    if not config["webhook_url"]:
        return False, "Discord webhook URL not configured"

    payload = json.dumps({"embeds": embeds}).encode()
    req = urllib.request.Request(
        config["webhook_url"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 204):
                return True, "Notification sent successfully"
            return False, f"Discord returned HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            detail = body.get("message", "")
        except Exception:
            detail = ""
        msg = f"Discord HTTP {e.code}: {detail or e.reason}"
        logger.error(f"Discord webhook error: {msg}")
        return False, msg
    except Exception as e:
        logger.error(f"Discord send failed: {e}")
        return False, str(e)


def send_test_notification():
    embeds = [{
        "title": "Mastodon Canada Administration Tool",
        "description": "Discord notifications are working correctly!",
        "color": _COLOR_GREEN,
    }]
    return _send_discord(embeds)


def send_update_notification(scan_results):
    """Send notification about available updates after a scan."""
    if Setting.get("discord_notify_updates", "true") != "true":
        return

    security_only = Setting.get("discord_notify_updates_security_only", "false") == "true"

    guests_with_updates = []
    total_updates = 0
    total_security = 0

    for result in scan_results:
        if result.status == "success" and result.total_updates > 0:
            if security_only and result.security_updates == 0:
                continue
            guests_with_updates.append(result)
            total_updates += result.total_updates
            total_security += result.security_updates

    if not guests_with_updates:
        return

    color = _COLOR_RED if total_security > 0 else _COLOR_YELLOW

    fields = []
    for result in guests_with_updates:
        guest = result.guest
        sec_label = f"{result.security_updates} \U0001f534" if result.security_updates > 0 else str(result.security_updates)
        fields.append({
            "name": f"{guest.name} ({guest.guest_type.upper()})",
            "value": f"Updates: **{result.total_updates}** | Security: **{sec_label}**",
            "inline": False,
        })

    title = (
        f"\U0001f6a8 CRITICAL: {total_security} security update(s) available"
        if total_security > 0
        else f"\U0001f4e6 {total_updates} update(s) available"
    )

    embeds = [{
        "title": title,
        "description": f"**{total_updates}** update(s) across **{len(guests_with_updates)}** guest(s).",
        "color": color,
        "fields": fields,
        "footer": {"text": "Log in to MCAT to review and apply updates."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Update notification sent for {len(guests_with_updates)} guest(s)")
    else:
        logger.error(f"Failed to send update notification: {msg}")


def send_mastodon_update_notification(current_version, new_version, release_url):
    """Send notification about a new Mastodon release."""
    if Setting.get("discord_notify_mastodon", "true") != "true":
        return False, "Mastodon notifications disabled"

    auto_upgrade = Setting.get("mastodon_auto_upgrade", "false") == "true"
    note = "Auto-upgrade is enabled and will run shortly." if auto_upgrade else "Log in to MCAT to upgrade."

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]
    if release_url:
        fields.append({"name": "Release Notes", "value": f"[View on GitHub]({release_url})", "inline": False})

    embeds = [{
        "title": f"\U0001f43b Mastodon update available: v{new_version}",
        "description": note,
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Mastodon update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Mastodon update notification: {msg}")
    return ok, msg


def send_ghost_update_notification(current_version, new_version, release_url):
    """Send notification about a new Ghost release."""
    if Setting.get("discord_notify_ghost", "true") != "true":
        return False, "Ghost notifications disabled"

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]
    if release_url:
        fields.append({"name": "Release Notes", "value": f"[View on GitHub]({release_url})", "inline": False})

    embeds = [{
        "title": f"\U0001f47b Ghost update available: v{new_version}",
        "description": "Log in to MCAT to upgrade.",
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Ghost update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Ghost update notification: {msg}")
    return ok, msg


def send_app_update_notification(current_version, new_version):
    """Send notification about a new MCAT app release."""
    if Setting.get("discord_notify_app", "true") != "true":
        return False, "App update notifications disabled"

    auto_update = Setting.get("app_auto_update", "false") == "true"
    note = (
        "Auto-update is enabled. The application will update and restart shortly."
        if auto_update
        else "Log in to MCAT and go to Settings to apply the update."
    )

    embeds = [{
        "title": f"\u2b06\ufe0f MCAT application update available: v{new_version}",
        "description": note,
        "color": _COLOR_CYAN,
        "fields": [
            {"name": "Current Version", "value": f"v{current_version}", "inline": True},
            {"name": "New Version", "value": f"v{new_version}", "inline": True},
        ],
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"App update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send app update notification: {msg}")
    return ok, msg
