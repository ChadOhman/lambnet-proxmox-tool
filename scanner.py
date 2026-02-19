import logging
from datetime import datetime, timezone
from models import db, Guest, UpdatePackage, ScanResult, GuestService
from ssh_client import SSHClient
from proxmox_api import ProxmoxClient

logger = logging.getLogger(__name__)

def _has_valid_ip(guest):
    """Check if a guest has a usable IP address (not dhcp/auto placeholders)."""
    ip = guest.ip_address
    return bool(ip) and ip.lower() not in ("dhcp", "dhcp6", "auto")


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
    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            # Try default credential
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and _has_valid_ip(guest):
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    # Update package lists (needs root)
                    ssh.execute_sudo("apt-get update -qq 2>/dev/null", timeout=120)
                    # Get upgradable list
                    stdout, stderr, code = ssh.execute(APT_LIST_CMD, timeout=60)
                    if code == 0:
                        # Check for security updates
                        sec_out, _, _ = ssh.execute_sudo(APT_SECURITY_CMD, timeout=60)
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


def _execute_command(guest, command, timeout=60, sudo=False):
    """Execute a single command on a guest via SSH or agent. Returns (stdout, error).

    If sudo=True, wraps the command with sudo when connected as a non-root user.
    """
    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and _has_valid_ip(guest):
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    if sudo:
                        stdout, stderr, code = ssh.execute_sudo(command, timeout=timeout)
                    else:
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


def _map_systemctl_status(status_str):
    """Map systemctl is-active output to our status strings."""
    if status_str == "active":
        return "running"
    elif status_str == "inactive":
        return "stopped"
    elif status_str == "failed":
        return "failed"
    return "unknown"


def detect_services(guest):
    """Detect known services on a guest via systemctl. Called during scan."""
    now = datetime.now(timezone.utc)

    # Split services into fixed and glob patterns
    fixed_services = {}
    glob_services = {}
    for key, (display_name, unit_name, default_port) in GuestService.KNOWN_SERVICES.items():
        if "*" in unit_name:
            glob_services[key] = (display_name, unit_name, default_port)
        else:
            fixed_services[key] = (display_name, unit_name, default_port)

    # Check fixed services with a single systemctl call
    if fixed_services:
        unit_names = [info[1] for info in fixed_services.values()]
        cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"
        stdout, error = _execute_command(guest, cmd)

        if stdout or not error:
            lines = (stdout or "").strip().split("\n")
            for i, (key, (display_name, unit_name, default_port)) in enumerate(fixed_services.items()):
                status_str = lines[i].strip() if i < len(lines) else "unknown"
                status = _map_systemctl_status(status_str)
                _upsert_service(guest, key, unit_name, default_port, status, now)

    # Discover glob-pattern services (e.g., mastodon-sidekiq*.service)
    for key, (display_name, unit_pattern, default_port) in glob_services.items():
        cmd = f"systemctl list-units '{unit_pattern}' --no-legend --plain 2>/dev/null"
        stdout, error = _execute_command(guest, cmd)
        if not stdout:
            continue
        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) < 3:
                continue
            discovered_unit = parts[0]  # e.g. mastodon-sidekiq1.service
            active_state = parts[2]     # active/inactive/failed
            status = _map_systemctl_status(active_state)
            _upsert_service(guest, key, discovered_unit, default_port, status, now)

    db.session.commit()


def _upsert_service(guest, service_key, unit_name, default_port, status, now):
    """Create or update a GuestService record."""
    existing = GuestService.query.filter_by(guest_id=guest.id, unit_name=unit_name).first()
    if status in ("running", "failed"):
        if existing:
            existing.status = status
            existing.last_checked = now
        else:
            svc = GuestService(
                guest_id=guest.id,
                service_name=service_key,
                unit_name=unit_name,
                port=default_port,
                status=status,
                last_checked=now,
                auto_detected=True,
            )
            db.session.add(svc)
    elif status == "stopped" and existing:
        existing.status = status
        existing.last_checked = now


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
    stdout, error = _execute_command(guest, cmd, timeout=30, sudo=True)

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


def _parse_systemd_props(output):
    """Parse systemctl show output into a dict."""
    props = {}
    for line in (output or "").strip().split("\n"):
        if "=" in line:
            key, _, val = line.partition("=")
            props[key.strip()] = val.strip()
    return props


def _human_bytes(n):
    """Convert bytes to human-readable string."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _parse_redis_info(output):
    """Parse redis-cli info output into a dict."""
    info = {}
    for line in (output or "").strip().split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


def get_service_stats(guest, service):
    """Fetch service-specific stats via SSH. Returns a dict with stats and a 'type' key."""
    import json as _json

    stype = service.service_name
    stats = {"type": stype, "error": None}

    # Common: get systemd resource usage
    unit = service.unit_name
    props_cmd = f"systemctl show {unit} --property=MemoryCurrent,CPUUsageNSec,MainPID,ActiveState,ActiveEnterTimestamp 2>/dev/null"
    props_out, _ = _execute_command(guest, props_cmd, timeout=15)
    props = _parse_systemd_props(props_out)

    mem_current = props.get("MemoryCurrent", "")
    if mem_current and mem_current not in ("[not set]", "infinity", ""):
        try:
            stats["memory_bytes"] = int(mem_current)
            stats["memory_human"] = _human_bytes(int(mem_current))
        except ValueError:
            pass

    cpu_ns = props.get("CPUUsageNSec", "")
    if cpu_ns and cpu_ns not in ("[not set]", ""):
        try:
            secs = int(cpu_ns) / 1_000_000_000
            if secs >= 3600:
                stats["cpu_time"] = f"{secs / 3600:.1f}h"
            elif secs >= 60:
                stats["cpu_time"] = f"{secs / 60:.1f}m"
            else:
                stats["cpu_time"] = f"{secs:.1f}s"
        except ValueError:
            pass

    stats["pid"] = props.get("MainPID", "")
    stats["active_state"] = props.get("ActiveState", "")
    active_enter = props.get("ActiveEnterTimestamp", "")
    if active_enter and active_enter not in ("n/a", ""):
        stats["started_at"] = active_enter

    # Service-specific stats
    try:
        if stype == "elasticsearch":
            stats.update(_stats_elasticsearch(guest, service))
        elif stype == "redis":
            stats.update(_stats_redis(guest))
        elif stype == "postgresql":
            stats.update(_stats_postgresql(guest))
        elif stype == "puma":
            stats.update(_stats_puma(guest, service))
        elif stype == "sidekiq":
            stats.update(_stats_sidekiq(guest, service))
        elif stype == "libretranslate":
            stats.update(_stats_libretranslate(guest, service))
    except Exception as e:
        logger.error(f"Error collecting {stype} stats for {guest.name}: {e}")
        stats["error"] = str(e)

    return stats


def _stats_elasticsearch(guest, service):
    """Collect Elasticsearch stats."""
    import json as _json
    port = service.port or 9200
    stats = {}

    # Cluster health
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_cluster/health 2>/dev/null", timeout=15)
    if out:
        try:
            health = _json.loads(out)
            stats["cluster_status"] = health.get("status", "unknown")
            stats["cluster_name"] = health.get("cluster_name", "")
            stats["node_count"] = health.get("number_of_nodes", 0)
            stats["active_shards"] = health.get("active_shards", 0)
            stats["relocating_shards"] = health.get("relocating_shards", 0)
            stats["unassigned_shards"] = health.get("unassigned_shards", 0)
        except _json.JSONDecodeError:
            pass

    # Cluster stats (doc count, store size)
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_cluster/stats 2>/dev/null", timeout=15)
    if out:
        try:
            cstats = _json.loads(out)
            indices = cstats.get("indices", {})
            stats["index_count"] = indices.get("count", 0)
            docs = indices.get("docs", {})
            stats["doc_count"] = docs.get("count", 0)
            store = indices.get("store", {})
            stats["store_size_bytes"] = store.get("size_in_bytes", 0)
            stats["store_size"] = _human_bytes(store.get("size_in_bytes", 0))
        except _json.JSONDecodeError:
            pass

    # JVM heap
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_nodes/stats/jvm 2>/dev/null", timeout=15)
    if out:
        try:
            jvm_data = _json.loads(out)
            nodes = jvm_data.get("nodes", {})
            total_heap_used = 0
            total_heap_max = 0
            for node_info in nodes.values():
                jvm = node_info.get("jvm", {}).get("mem", {})
                total_heap_used += jvm.get("heap_used_in_bytes", 0)
                total_heap_max += jvm.get("heap_max_in_bytes", 0)
            stats["jvm_heap_used"] = _human_bytes(total_heap_used)
            stats["jvm_heap_max"] = _human_bytes(total_heap_max)
            if total_heap_max > 0:
                stats["jvm_heap_percent"] = round(total_heap_used / total_heap_max * 100, 1)
        except _json.JSONDecodeError:
            pass

    # Per-index stats
    out, _ = _execute_command(guest, f"curl -s 'localhost:{port}/_cat/indices?format=json&h=index,health,docs.count,store.size' 2>/dev/null", timeout=15)
    if out:
        try:
            stats["indices"] = _json.loads(out)
        except _json.JSONDecodeError:
            pass

    return stats


def _stats_redis(guest):
    """Collect Redis stats."""
    stats = {}

    # Memory section
    out, _ = _execute_command(guest, "redis-cli info memory 2>/dev/null", timeout=10)
    info = _parse_redis_info(out)
    if info:
        stats["used_memory"] = info.get("used_memory_human", "")
        stats["used_memory_peak"] = info.get("used_memory_peak_human", "")
        stats["used_memory_bytes"] = info.get("used_memory", "0")
        stats["maxmemory"] = info.get("maxmemory_human", "0B")

    # Clients section
    out, _ = _execute_command(guest, "redis-cli info clients 2>/dev/null", timeout=10)
    info = _parse_redis_info(out)
    if info:
        stats["connected_clients"] = info.get("connected_clients", "0")

    # Stats section
    out, _ = _execute_command(guest, "redis-cli info stats 2>/dev/null", timeout=10)
    info = _parse_redis_info(out)
    if info:
        stats["ops_per_sec"] = info.get("instantaneous_ops_per_sec", "0")
        hits = int(info.get("keyspace_hits", 0))
        misses = int(info.get("keyspace_misses", 0))
        total = hits + misses
        stats["keyspace_hits"] = hits
        stats["keyspace_misses"] = misses
        stats["hit_ratio"] = f"{(hits / total * 100):.1f}%" if total > 0 else "N/A"
        stats["total_commands"] = info.get("total_commands_processed", "0")

    # Keyspace section
    out, _ = _execute_command(guest, "redis-cli info keyspace 2>/dev/null", timeout=10)
    info = _parse_redis_info(out)
    keyspace = {}
    for key, val in info.items():
        if key.startswith("db"):
            keyspace[key] = val
    stats["keyspace"] = keyspace

    return stats


def _stats_postgresql(guest):
    """Collect PostgreSQL stats."""
    stats = {}

    # Database sizes
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT datname, pg_database_size(datname) FROM pg_database WHERE datistemplate = false\" 2>/dev/null",
        timeout=15, sudo=True)
    if out:
        databases = []
        for line in out.strip().split("\n"):
            parts = line.strip().split("|")
            if len(parts) == 2:
                databases.append({
                    "name": parts[0],
                    "size_bytes": int(parts[1]) if parts[1].isdigit() else 0,
                    "size": _human_bytes(int(parts[1]) if parts[1].isdigit() else 0),
                })
        stats["databases"] = databases

    # Active queries
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT count(*) FROM pg_stat_activity WHERE state = 'active'\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["active_queries"] = out.strip()

    # Total connections
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT sum(numbackends) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["total_connections"] = out.strip()

    # Max connections
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SHOW max_connections\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["max_connections"] = out.strip()

    # Cache hit ratio
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT round(sum(blks_hit)::numeric / nullif(sum(blks_hit) + sum(blks_read), 0) * 100, 2) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out and out.strip():
        stats["cache_hit_ratio"] = f"{out.strip()}%"

    # Transactions
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT sum(xact_commit), sum(xact_rollback) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        parts = out.strip().split("|")
        if len(parts) == 2:
            stats["total_commits"] = parts[0].strip()
            stats["total_rollbacks"] = parts[1].strip()

    return stats


def _stats_puma(guest, service):
    """Collect Puma/mastodon-web stats."""
    stats = {}
    port = service.port or 3000

    # Health endpoint
    out, _ = _execute_command(guest, f"curl -s -o /dev/null -w '%{{http_code}}' localhost:{port}/health 2>/dev/null", timeout=10)
    if out:
        stats["health_status"] = "OK" if out.strip() == "200" else f"HTTP {out.strip()}"

    return stats


def _stats_sidekiq(guest, service):
    """Collect Sidekiq stats — per-instance systemd info plus aggregate queue stats from Redis."""
    stats = {}

    # Aggregate stats from Redis (only fetch once per guest, not per-instance)
    # Queue info
    out, _ = _execute_command(guest, "redis-cli smembers queues 2>/dev/null", timeout=10)
    queues = []
    if out:
        queue_names = [q.strip() for q in out.strip().split("\n") if q.strip()]
        for qname in queue_names:
            len_out, _ = _execute_command(guest, f"redis-cli llen queue:{qname} 2>/dev/null", timeout=5)
            queues.append({
                "name": qname,
                "size": int(len_out.strip()) if len_out and len_out.strip().isdigit() else 0,
            })
    stats["queues"] = queues

    # Processed / failed counters
    out, _ = _execute_command(guest, "redis-cli get stat:processed 2>/dev/null", timeout=5)
    stats["processed"] = out.strip() if out and out.strip() not in ("(nil)", "") else "0"

    out, _ = _execute_command(guest, "redis-cli get stat:failed 2>/dev/null", timeout=5)
    stats["failed"] = out.strip() if out and out.strip() not in ("(nil)", "") else "0"

    # Retry set size
    out, _ = _execute_command(guest, "redis-cli zcard retry 2>/dev/null", timeout=5)
    stats["retry_size"] = out.strip() if out and out.strip().isdigit() else "0"

    # Dead set size
    out, _ = _execute_command(guest, "redis-cli zcard dead 2>/dev/null", timeout=5)
    stats["dead_size"] = out.strip() if out and out.strip().isdigit() else "0"

    # Scheduled set size
    out, _ = _execute_command(guest, "redis-cli zcard schedule 2>/dev/null", timeout=5)
    stats["scheduled_size"] = out.strip() if out and out.strip().isdigit() else "0"

    # All sidekiq instances on this guest
    sibling_services = GuestService.query.filter_by(guest_id=guest.id, service_name="sidekiq").all()
    instances = []
    for svc in sibling_services:
        props_out, _ = _execute_command(guest,
            f"systemctl show {svc.unit_name} --property=MemoryCurrent,CPUUsageNSec,ActiveState,MainPID 2>/dev/null",
            timeout=10)
        p = _parse_systemd_props(props_out)
        mem = p.get("MemoryCurrent", "")
        mem_human = ""
        if mem and mem not in ("[not set]", "infinity", ""):
            try:
                mem_human = _human_bytes(int(mem))
            except ValueError:
                pass
        instances.append({
            "unit_name": svc.unit_name,
            "status": _map_systemctl_status(p.get("ActiveState", "unknown")),
            "pid": p.get("MainPID", ""),
            "memory": mem_human,
        })
    stats["instances"] = instances

    return stats


def _stats_libretranslate(guest, service):
    """Collect LibreTranslate stats."""
    import json as _json
    stats = {}
    port = service.port or 5000

    # Health / languages
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/languages 2>/dev/null", timeout=10)
    if out:
        try:
            langs = _json.loads(out)
            stats["languages_count"] = len(langs)
            stats["languages"] = [l.get("name", l.get("code", "")) for l in langs[:20]]
        except _json.JSONDecodeError:
            pass

    # Simple health check
    out, _ = _execute_command(guest, f"curl -s -o /dev/null -w '%{{http_code}}' localhost:{port}/languages 2>/dev/null", timeout=10)
    if out:
        stats["health_status"] = "OK" if out.strip() == "200" else f"HTTP {out.strip()}"

    return stats


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

    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential:
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    ssh.execute_sudo("apt-get update -qq", timeout=120)
                    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=600)
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
