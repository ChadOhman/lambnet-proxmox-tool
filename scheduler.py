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


def _run_discovery(app):
    """Refresh guest discovery for all Proxmox hosts."""
    with app.app_context():
        import re
        from models import Setting, ProxmoxHost, Guest, Tag
        from proxmox_api import ProxmoxClient

        if Setting.get("discovery_enabled", "true") == "false":
            logger.info("Automatic discovery is disabled, skipping.")
            return

        hosts = ProxmoxHost.query.all()
        if not hosts:
            return

        for host in hosts:
            try:
                client = ProxmoxClient(host)
                node_name = client.get_local_node_name()
                if node_name:
                    node_guests = client.get_node_guests(node_name)
                else:
                    node_guests = client.get_all_guests()
                    node_name = "cluster"

                repl_map = client.get_replication_map()

                # Clean up stale guests on this host
                node_vmids = {g.get("vmid") for g in node_guests}
                stale = Guest.query.filter(
                    Guest.proxmox_host_id == host.id,
                    Guest.vmid.isnot(None),
                    ~Guest.vmid.in_(node_vmids),
                ).all()
                for s in stale:
                    db.session.delete(s)

                added = 0
                updated = 0
                for g in node_guests:
                    vmid = g.get("vmid")
                    status = g.get("status", "")

                    existing = Guest.query.filter_by(proxmox_host_id=host.id, vmid=vmid).first()

                    if not existing:
                        other = Guest.query.filter(Guest.vmid == vmid, Guest.proxmox_host_id != host.id).first()
                        if other:
                            if status != "running":
                                continue
                            existing = other
                            existing.proxmox_host_id = host.id

                    proxmox_tags = g.get("tags", "")
                    tag_names = [t.strip() for t in re.split(r"[;,]", proxmox_tags) if t.strip()] if proxmox_tags else []

                    ip = None
                    if status == "running":
                        ip = client.get_guest_ip(g["node"], vmid, g["type"])

                    repl_target = repl_map.get(vmid)
                    mac = client.get_guest_mac(g["node"], vmid, g["type"])
                    power_state = status if status in ("running", "stopped", "paused") else "unknown"

                    if not existing:
                        guest = Guest(
                            proxmox_host_id=host.id,
                            vmid=vmid,
                            name=g.get("name", f"guest-{vmid}"),
                            guest_type=g["type"],
                            ip_address=ip,
                            connection_method="auto",
                            replication_target=repl_target,
                            mac_address=mac,
                            power_state=power_state,
                        )
                        db.session.add(guest)
                        added += 1

                        for tag_name in tag_names:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            guest.tags.append(tag)
                    else:
                        if ip:
                            existing.ip_address = ip
                        existing.name = g.get("name", existing.name)
                        existing.replication_target = repl_target
                        existing.power_state = power_state
                        if mac:
                            existing.mac_address = mac
                        existing.tags.clear()
                        for tag_name in tag_names:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            existing.tags.append(tag)
                        updated += 1

                db.session.commit()
                logger.info(f"Discovery for '{host.name}' node '{node_name}': {added} new, {updated} updated, {len(stale)} stale removed")
            except Exception as e:
                logger.error(f"Scheduled discovery failed for '{host.name}': {e}")


def _check_app_update(app):
    """Check for new app releases, store result, and optionally auto-update."""
    with app.app_context():
        from models import Setting
        import urllib.request
        import json
        import subprocess
        import os
        from config import BASE_DIR

        repo = app.config.get("GITHUB_REPO", "")
        current_version = app.config.get("APP_VERSION", "0.0.0")
        update_branch = Setting.get("app_update_branch", "")
        auto_update = Setting.get("app_auto_update", "false") == "true"
        update_script = os.path.join(BASE_DIR, "update.sh")

        if not repo:
            return

        # Always fetch the latest release and store it
        try:
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                latest = data.get("tag_name", "").lstrip("v")
                if latest:
                    Setting.set("latest_app_version", latest)
                    Setting.set("latest_app_check", datetime.now().isoformat())
        except Exception as e:
            logger.error(f"Failed to check for app updates: {e}")
            return

        if not auto_update:
            return

        # Branch-based auto-update: always pull latest from configured branch
        if update_branch:
            import re as _re
            if not _re.match(r'^[A-Za-z0-9._\-/]+$', update_branch) or update_branch.startswith("-"):
                logger.error(f"Invalid update branch name, skipping auto-update")
                return
            logger.info(f"Auto-update from branch '{update_branch}'...")
            if os.path.exists(update_script):
                subprocess.Popen(["bash", update_script, "--branch", update_branch], cwd=BASE_DIR)
            else:
                logger.warning("update.sh not found, cannot auto-update")
            return

        if current_version == "unknown":
            return

        if not latest or latest == current_version:
            return

        logger.info(f"New app version available: v{current_version} -> v{latest}")

        # Send email notification if configured
        from notifier import send_app_update_notification
        send_app_update_notification(current_version, latest)

        # Run update.sh
        if os.path.exists(update_script):
            logger.info("Auto-update enabled, running update.sh...")
            subprocess.Popen(["bash", update_script], cwd=BASE_DIR)
        else:
            logger.warning("update.sh not found, cannot auto-update")


def _run_service_health_checks(app):
    """Check status of all tracked services on all guests."""
    with app.app_context():
        from models import Setting, Guest
        from scanner import check_service_statuses

        if Setting.get("service_check_enabled", "true") == "false":
            logger.info("Service health checks disabled, skipping.")
            return

        guests = Guest.query.filter(Guest.enabled == True, Guest.services.any()).all()
        if not guests:
            return

        checked = 0
        for guest in guests:
            try:
                check_service_statuses(guest)
                checked += 1
            except Exception as e:
                logger.debug(f"Service check failed for {guest.name}: {e}")

        logger.info(f"Service health checks complete: {checked}/{len(guests)} guests checked.")


def init_scheduler(app):
    global _scheduler

    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler()

    with app.app_context():
        from models import Setting
        interval_hours = int(Setting.get("scan_interval", "6") or 6)
        discovery_hours = int(Setting.get("discovery_interval", "4") or 4)
        service_check_minutes = int(Setting.get("service_check_interval", "5") or 5)

    # Discovery job - refresh hosts periodically
    _scheduler.add_job(
        _run_discovery,
        trigger=IntervalTrigger(hours=discovery_hours),
        args=[app],
        id="discovery",
        name="Refresh guest discovery for all hosts",
        replace_existing=True,
    )

    # Scan job - runs every N hours

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

    # Service health checks - runs every N minutes
    _scheduler.add_job(
        _run_service_health_checks,
        trigger=IntervalTrigger(minutes=service_check_minutes),
        args=[app],
        id="service_health",
        name="Check service health on all guests",
        replace_existing=True,
    )

    # App self-update check - runs every 6 hours
    _scheduler.add_job(
        _check_app_update,
        trigger=IntervalTrigger(hours=6),
        args=[app],
        id="app_update_check",
        name="Check for app updates",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info(f"Scheduler started: discovery every {discovery_hours}h, scan every {interval_hours}h, auto-update check every 15m, service check every {service_check_minutes}m, mastodon check every {interval_hours}h, app update check every 6h")

    return _scheduler
