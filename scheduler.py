import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_scheduler = None


def _run_scan(app):
    """Run a full scan of all guests and send notifications."""
    with app.app_context():
        from models import Setting
        if Setting.get("scan_enabled", "true") == "false":
            logger.info("Automatic scanning is disabled, skipping.")
            return

        logger.info("Starting scheduled scan of all guests...")
        from scanner import scan_all_guests
        results = scan_all_guests()

        from notifier import send_update_notification
        send_update_notification(results)

        logger.info(f"Scheduled scan complete. Scanned {len(results)} guest(s).")


def _run_auto_updates(app):
    """Apply updates to guests with auto-update enabled during their maintenance window."""
    with app.app_context():
        from models import Guest, MaintenanceWindow
        from scanner import apply_updates
        import calendar

        now = datetime.now()
        current_day = calendar.day_name[now.weekday()].lower()
        current_time = now.strftime("%H:%M")

        guests = Guest.query.filter_by(enabled=True, auto_update=True).all()

        for guest in guests:
            window = guest.maintenance_window
            if not window or not window.enabled:
                continue

            # Check if current day matches
            if window.day_of_week != "daily" and window.day_of_week != current_day:
                continue

            # Check if current time is within window
            if not (window.start_time <= current_time <= window.end_time):
                continue

            # Check if there are pending updates
            if not guest.pending_updates():
                continue

            dist_upgrade = window.update_type == "dist-upgrade"
            logger.info(f"Auto-updating {guest.name} (window: {window.name})")

            ok, output = apply_updates(guest, dist_upgrade=dist_upgrade)
            if ok:
                logger.info(f"Auto-update successful for {guest.name}")
            else:
                logger.error(f"Auto-update failed for {guest.name}: {output}")


def _check_mastodon_release(app):
    """Check for new Mastodon releases and optionally auto-upgrade."""
    with app.app_context():
        from models import Setting

        # Only check if a Mastodon guest is configured
        if not Setting.get("mastodon_guest_id"):
            return

        from mastodon import check_mastodon_release
        update_available, latest, release_url = check_mastodon_release()

        if not update_available:
            return

        current = Setting.get("mastodon_current_version", "")
        logger.info(f"Mastodon update available: v{current} -> v{latest}")

        # Send email notification
        from notifier import send_mastodon_update_notification
        send_mastodon_update_notification(current, latest, release_url)

        # Auto-upgrade if enabled
        if Setting.get("mastodon_auto_upgrade", "false") == "true":
            logger.info("Auto-upgrade enabled, starting Mastodon upgrade...")
            from mastodon import run_mastodon_upgrade
            ok, log_output = run_mastodon_upgrade()
            if ok:
                logger.info("Mastodon auto-upgrade completed successfully")
            else:
                logger.error(f"Mastodon auto-upgrade failed")


def init_scheduler(app):
    global _scheduler

    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler()

    # Scan job - runs every N hours
    with app.app_context():
        from models import Setting
        interval_hours = int(Setting.get("scan_interval", "6") or 6)

    _scheduler.add_job(
        _run_scan,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="scan_all",
        name="Scan all guests for updates",
        replace_existing=True,
    )

    # Auto-update check - runs every 15 minutes to check maintenance windows
    _scheduler.add_job(
        _run_auto_updates,
        trigger=IntervalTrigger(minutes=15),
        args=[app],
        id="auto_update",
        name="Check maintenance windows and apply updates",
        replace_existing=True,
    )

    # Mastodon release check - runs alongside the scan job
    _scheduler.add_job(
        _check_mastodon_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="mastodon_check",
        name="Check for Mastodon releases",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info(f"Scheduler started: scan every {interval_hours}h, auto-update check every 15m, mastodon check every {interval_hours}h")

    return _scheduler
