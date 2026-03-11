"""Shared Proxmox snapshot and backup helpers for application upgrade automation."""

import logging
import time
from datetime import datetime

from clients.proxmox_api import ProxmoxClient

logger = logging.getLogger(__name__)


def snapshot_guest(guest, prefix: str) -> tuple[bool, str]:
    """Create a Proxmox snapshot of a guest before upgrade.

    Args:
        guest: Guest model instance with proxmox_host set.
        prefix: Short app name used in snapshot name (e.g. "mastodon", "ghost").

    Returns:
        (success, message)
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    try:
        client = ProxmoxClient(guest.proxmox_host)
        node = client.find_guest_node(guest.vmid)
        if not node:
            return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        snapname = f"pre-{prefix}-{timestamp}"
        description = f"Auto-snapshot before {prefix.capitalize()} upgrade at {timestamp}"

        return client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)
    except Exception as e:
        logger.error("Snapshot of %s failed: %s", guest.name, e)
        return False, f"Snapshot failed: {e}"


def backup_guest(guest, storage: str, prefix: str, mode: str = "snapshot") -> tuple[bool, str]:
    """Create a vzdump backup of a guest before upgrade. Polls until the task completes.

    Args:
        guest: Guest model instance with proxmox_host set.
        storage: Proxmox storage ID to store the backup in.
        prefix: Short app name used in backup notes (e.g. "mastodon", "ghost").
        mode: "snapshot" (live, no downtime), "suspend" (brief pause), "stop" (shut down).

    Returns:
        (success, message)
    """
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    try:
        client = ProxmoxClient(guest.proxmox_host)
        node = client.find_guest_node(guest.vmid)
        if not node:
            return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        notes = f"pre-{prefix}-{timestamp}"

        ok, upid = client.create_backup(node, guest.vmid, storage, mode=mode, notes=notes)
        if not ok:
            return False, f"Failed to start backup: {upid}"

        timeout = 1800  # 30 minutes
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(5)
            try:
                status = client.get_task_status(node, upid)
                if status.get("status") == "stopped":
                    exit_status = status.get("exitstatus", "")
                    if exit_status == "OK":
                        return True, f"Backup of '{guest.name}' to '{storage}' completed"
                    return False, f"Backup task failed: {exit_status}"
            except Exception as e:
                logger.debug("Error polling backup task for %s: %s", guest.name, e)

        return False, f"Backup of '{guest.name}' timed out after {timeout // 60} minutes"
    except Exception as e:
        logger.error("Backup of %s failed: %s", guest.name, e)
        return False, f"Backup failed: {e}"
