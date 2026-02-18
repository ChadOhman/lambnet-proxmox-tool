import logging
from datetime import datetime, timezone
from models import db, Guest, UpdatePackage, ScanResult, GuestService
from ssh_client import SSHClient
from proxmox_api import ProxmoxClient

logger = logging.getLogger(__name__)

APT_CHECK_CMD = "apt-get update -qq 2>/dev/null && apt-get -s upgrade 2>/dev/null"
APT_LIST_CMD = "apt list --upgradable 2>/dev/null"
APT_SECURITY_CMD = "apt-get -s upgrade 2>/dev/null | grep -i security"


def parse_upgradable(output):
    """Parse 'apt list --upgradable' output into package dicts."""
    packages = []
    for line in output.strip().split("\n"):
        if "/" not in line or "Listing..." in line:
            continue
        try:
            # Format: package/source version arch [upgradable from: old_version]
            name_part, rest = line.split("/", 1)
            parts = rest.split()
            available_version = parts[1] if len(parts) > 1 else "unknown"
            current_version = "unknown"
            if "upgradable from:" in line:
                current_version = line.split("upgradable from: ")[-1].rstrip("]").strip()
            packages.append({
                "name": name_part.strip(),
                "current_version": current_version,
                "available_version": available_version,
            })
        except (IndexError, ValueError) as e:
            logger.debug(f"Could not parse line: {line} ({e})")
    return packages


def determine_severity(package_name, security_output):
    """Check if a package appears in security upgrade output."""
    if security_output and package_name in security_output:
        return "critical"
    return "normal"


def _execute_on_guest(guest):
    """Execute APT commands on a guest and return (upgradable_output, security_output, error)."""
    # Try SSH first if configured
    if guest.connection_method in ("ssh", "auto") and guest.ip_address:
        credential = guest.credential
        if not credential:
            # Try default credential
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and guest.ip_address:
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    # Update package lists
                    ssh.execute("apt-get update -qq 2>/dev/null", timeout=120)
                    # Get upgradable list
                    stdout, stderr, code = ssh.execute(APT_LIST_CMD, timeout=60)
                    if code == 0:
                        # Check for security updates
                        sec_out, _, _ = ssh.execute(APT_SECURITY_CMD, timeout=60)
                        return stdout, sec_out, None
                    if guest.connection_method == "ssh":
                        return None, None, f"SSH apt list failed: {stderr}"
            except Exception as e:
                if guest.connection_method == "ssh":
                    return None, None, f"SSH failed: {e}"
                logger.debug(f"SSH failed for {guest.name}, trying agent: {e}")

    # Try QEMU guest agent
    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            # Find the node this VM is on
            all_guests = client.get_all_guests()
            node = None
            for g in all_guests:
                if g.get("vmid") == guest.vmid:
                    node = g.get("node")
                    break

            if node:
                # Update apt
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq")
                # Get upgradable
                stdout, err = client.exec_guest_agent(node, guest.vmid, "apt list --upgradable 2>/dev/null")
                if err is None:
                    sec_out, _ = client.exec_guest_agent(node, guest.vmid,
                                                         "apt-get -s upgrade 2>/dev/null | grep -i security")
                    return stdout, sec_out, None
                return None, None, f"Agent exec failed: {err}"
            return None, None, f"Could not find VM {guest.vmid} on any node"
        except Exception as e:
            return None, None, f"Agent failed: {e}"

    return None, None, "No viable connection method available"


def _execute_command(guest, command, timeout=60):
    """Execute a single command on a guest via SSH or agent. Returns (stdout, error)."""
    if guest.connection_method in ("ssh", "auto") and guest.ip_address:
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and guest.ip_address:
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    stdout, stderr, code = ssh.execute(command, timeout=timeout)
                    if code == 0:
                        return stdout, None
                    if guest.connection_method == "ssh":
                        return stdout, stderr or f"Exit code {code}"
            except Exception as e:
                if guest.connection_method == "ssh":
                    return None, f"SSH failed: {e}"
                logger.debug(f"SSH failed for {guest.name}, trying agent: {e}")

    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                stdout, err = client.exec_guest_agent(node, guest.vmid, command)
                return stdout, err
            return None, f"Could not find VM {guest.vmid} on any node"
        except Exception as e:
            return None, f"Agent failed: {e}"

    return None, "No viable connection method available"


def detect_services(guest):
    """Detect known services on a guest via systemctl. Called during scan."""
    unit_names = [info[1] for info in GuestService.KNOWN_SERVICES.values()]
    cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"

    stdout, error = _execute_command(guest, cmd)
    if error and not stdout:
        logger.debug(f"Service detection failed for {guest.name}: {error}")
        return

    lines = (stdout or "").strip().split("\n")
    now = datetime.now(timezone.utc)

    for i, (key, (display_name, unit_name, default_port)) in enumerate(GuestService.KNOWN_SERVICES.items()):
        status_str = lines[i].strip() if i < len(lines) else "unknown"
        # Map systemctl output to our status
        if status_str == "active":
            status = "running"
        elif status_str == "inactive":
            status = "stopped"
        elif status_str == "failed":
            status = "failed"
        else:
            status = "unknown"

        # Only create/update if the service is actually present (not unknown/inactive from never installed)
        if status in ("running", "failed"):
            existing = GuestService.query.filter_by(guest_id=guest.id, service_name=key).first()
            if existing:
                existing.status = status
                existing.last_checked = now
            else:
                svc = GuestService(
                    guest_id=guest.id,
                    service_name=key,
                    unit_name=unit_name,
                    port=default_port,
                    status=status,
                    last_checked=now,
                    auto_detected=True,
                )
                db.session.add(svc)
        elif status == "stopped":
            # Update existing services that were previously detected
            existing = GuestService.query.filter_by(guest_id=guest.id, service_name=key).first()
            if existing:
                existing.status = status
                existing.last_checked = now

    db.session.commit()


def check_service_statuses(guest):
    """Lightweight status refresh for all services on a guest."""
    if not guest.services:
        return

    unit_names = [svc.unit_name for svc in guest.services]
    cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"
    stdout, error = _execute_command(guest, cmd)

    if error and not stdout:
        logger.debug(f"Service status check failed for {guest.name}: {error}")
        return

    lines = (stdout or "").strip().split("\n")
    now = datetime.now(timezone.utc)

    for i, svc in enumerate(guest.services):
        status_str = lines[i].strip() if i < len(lines) else "unknown"
        if status_str == "active":
            svc.status = "running"
        elif status_str == "inactive":
            svc.status = "stopped"
        elif status_str == "failed":
            svc.status = "failed"
        else:
            svc.status = "unknown"
        svc.last_checked = now

    db.session.commit()


def service_action(guest, service, action):
    """Execute start/stop/restart on a service. Returns (success, output)."""
    if action not in ("start", "stop", "restart"):
        return False, "Invalid action"

    cmd = f"systemctl {action} {service.unit_name}"
    stdout, error = _execute_command(guest, cmd, timeout=30)

    if error:
        return False, error

    # Refresh status after action
    status_out, _ = _execute_command(guest, f"systemctl is-active {service.unit_name} 2>/dev/null")
    now = datetime.now(timezone.utc)
    status_str = (status_out or "").strip()
    if status_str == "active":
        service.status = "running"
    elif status_str == "inactive":
        service.status = "stopped"
    elif status_str == "failed":
        service.status = "failed"
    else:
        service.status = "unknown"
    service.last_checked = now
    db.session.commit()

    return True, stdout or f"{action.capitalize()} command sent"


def get_service_logs(guest, service, lines=50):
    """Fetch recent journal logs for a service. Returns log text."""
    cmd = f"journalctl -u {service.unit_name} -n {lines} --no-pager 2>/dev/null"
    stdout, error = _execute_command(guest, cmd, timeout=30)
    if error:
        return f"Error fetching logs: {error}"
    return stdout or "No log output"


def scan_guest(guest):
    """Scan a single guest for updates. Returns ScanResult."""
    logger.info(f"Scanning {guest.name} ({guest.guest_type})...")

    upgradable_output, security_output, error = _execute_on_guest(guest)

    now = datetime.now(timezone.utc)

    if error:
        logger.error(f"Scan failed for {guest.name}: {error}")
        result = ScanResult(
            guest_id=guest.id,
            scanned_at=now,
            total_updates=0,
            security_updates=0,
            status="error",
            error_message=error,
        )
        guest.status = "error"
        guest.last_scan = now
        db.session.add(result)
        db.session.commit()
        return result

    # Parse packages
    packages = parse_upgradable(upgradable_output or "")

    # Clear old pending updates for this guest
    UpdatePackage.query.filter_by(guest_id=guest.id, status="pending").delete()

    security_count = 0
    for pkg in packages:
        severity = determine_severity(pkg["name"], security_output)
        if severity == "critical":
            security_count += 1

        update = UpdatePackage(
            guest_id=guest.id,
            package_name=pkg["name"],
            current_version=pkg["current_version"],
            available_version=pkg["available_version"],
            severity=severity,
            discovered_at=now,
            status="pending",
        )
        db.session.add(update)

    result = ScanResult(
        guest_id=guest.id,
        scanned_at=now,
        total_updates=len(packages),
        security_updates=security_count,
        status="success",
    )

    guest.status = "updates-available" if packages else "up-to-date"
    guest.last_scan = now

    db.session.add(result)
    db.session.commit()

    logger.info(f"Scan complete for {guest.name}: {len(packages)} updates ({security_count} security)")

    # Auto-detect services during scan
    try:
        detect_services(guest)
    except Exception as e:
        logger.debug(f"Service detection failed for {guest.name}: {e}")

    return result


def scan_all_guests():
    """Scan all enabled guests."""
    guests = Guest.query.filter_by(enabled=True).all()
    results = []
    for guest in guests:
        try:
            result = scan_guest(guest)
            results.append(result)
        except Exception as e:
            logger.error(f"Unexpected error scanning {guest.name}: {e}")
    return results


def apply_updates(guest, dist_upgrade=False):
    """Apply pending updates to a guest."""
    cmd = "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y" if dist_upgrade else "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"

    logger.info(f"Applying updates to {guest.name} (dist_upgrade={dist_upgrade})...")

    if guest.connection_method in ("ssh", "auto") and guest.ip_address:
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential:
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    ssh.execute("apt-get update -qq", timeout=120)
                    stdout, stderr, code = ssh.execute(cmd, timeout=600)
                    if code == 0:
                        # Mark all pending as applied
                        now = datetime.now(timezone.utc)
                        for pkg in guest.pending_updates():
                            pkg.status = "applied"
                            pkg.applied_at = now
                        guest.status = "up-to-date"
                        db.session.commit()
                        return True, stdout
                    return False, stderr
            except Exception as e:
                return False, str(e)

    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            all_guests = client.get_all_guests()
            node = None
            for g in all_guests:
                if g.get("vmid") == guest.vmid:
                    node = g.get("node")
                    break
            if node:
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq")
                stdout, err = client.exec_guest_agent(node, guest.vmid, cmd)
                if err is None:
                    now = datetime.now(timezone.utc)
                    for pkg in guest.pending_updates():
                        pkg.status = "applied"
                        pkg.applied_at = now
                    guest.status = "up-to-date"
                    db.session.commit()
                    return True, stdout
                return False, err
        except Exception as e:
            return False, str(e)

    return False, "No viable connection method"
