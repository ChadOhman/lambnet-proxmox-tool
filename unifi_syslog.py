"""
UniFi syslog receiver: UDP listener + parser for UniFi network events.

Parses firewall (kernel UFW-style), DHCP (dnsmasq/dhcpd), Wi-Fi (hostapd),
and generic system events from syslog messages forwarded by a UniFi device.

Configure UniFi to forward syslog to this host:
  Settings → System → Advanced → Remote Logging → Syslog Host: <host>:<port>

Default port is 5514 (avoids requiring root). Standard syslog is 514.
"""
import ipaddress
import logging
import re
import socket
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── regex patterns ─────────────────────────────────────────────────────────────

# RFC3164 syslog header: "Jan 15 12:34:56 hostname process[pid]:"
_RE_HDR = re.compile(
    r"^(?:<\d+>)?"                          # optional priority
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+?)(?:\[\d+\])?:\s*"
    r"(?P<body>.*)",
    re.DOTALL,
)

# Firewall: kernel message containing netfilter/UFW log fields
# Example: [WAN_LOCAL-default-D]IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=12345 DPT=443
_RE_FW = re.compile(
    r"\[(?P<rule>[^\]]+)\]"
    r".*?IN=(?P<iface>\S*)"
    r".*?SRC=(?P<src>\S+)"
    r".*?DST=(?P<dst>\S+)"
    r".*?PROTO=(?P<proto>\S+)"
    r"(?:.*?SPT=(?P<spt>\d+))?"
    r"(?:.*?DPT=(?P<dpt>\d+))?",
)

# DHCP: dnsmasq or ISC dhcpd lease events
# dnsmasq: "DHCPACK(eth1) 192.168.4.5 aa:bb:cc:dd:ee:ff myhostname"
# dhcpd:   "DHCPACK on 192.168.4.5 to aa:bb:cc:dd:ee:ff (hostname) via eth1"
_RE_DHCP_DNSMASQ = re.compile(
    r"(?P<type>DHCP\w+)\((?P<iface>[^)]+)\)\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>[0-9a-f:]{17})"
    r"(?:\s+(?P<hostname>\S+))?",
    re.IGNORECASE,
)
_RE_DHCP_ISC = re.compile(
    r"(?P<type>DHCP\w+)\s+on\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"to\s+(?P<mac>[0-9a-f:]{17})"
    r"(?:\s+\((?P<hostname>[^)]+)\))?"
    r"(?:\s+via\s+(?P<iface>\S+))?",
    re.IGNORECASE,
)

# Wi-Fi: hostapd association/disassociation events
# "wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11 associated"
_RE_WIFI = re.compile(
    r"(?P<iface>\w+):\s+STA\s+(?P<mac>[0-9a-f:]{17})\s+IEEE 802\.11\s+(?P<event>\S+)",
    re.IGNORECASE,
)

# Private address ranges (for direction classification)
_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE)
    except ValueError:
        return False


def _classify_direction(src_ip, dst_ip, iface=""):
    """Classify traffic direction based on src/dst RFC1918 status."""
    src_priv = _is_private(src_ip) if src_ip else True
    dst_priv = _is_private(dst_ip) if dst_ip else True
    if not src_priv and dst_priv:
        return "inbound"
    if src_priv and not dst_priv:
        return "outbound"
    if src_priv and dst_priv:
        return "inter_vlan"
    return "outbound"


def _infer_action(rule_id):
    """Infer allow/block from the firewall rule identifier."""
    rule_upper = (rule_id or "").upper()
    for token in ("-D", "-DROP", "BLOCK", "DENY", "REJECT"):
        if token in rule_upper:
            return "block"
    for token in ("-A", "-ACCEPT", "ALLOW", "PERMIT"):
        if token in rule_upper:
            return "allow"
    return "block"  # UniFi default-deny logs are blocks


def parse_syslog_line(line):
    """
    Parse a raw syslog line from a UniFi device.

    Returns a dict suitable for constructing a UnifiLogEntry, or None if
    the line is not a recognized UniFi network event.

    Keys: log_type, action, direction, src_ip, dst_ip, src_port, dst_port,
          protocol, interface, rule_id, mac, msg, raw
    """
    line = line.strip()
    if not line:
        return None

    m = _RE_HDR.match(line)
    if not m:
        # Try to handle lines without a proper header
        body = line
        proc = ""
    else:
        body = m.group("body")
        proc = m.group("proc").lower()

    # ── Firewall ──────────────────────────────────────────────────────────────
    if "kernel" in proc or _RE_FW.search(body):
        fw = _RE_FW.search(body)
        if fw:
            rule_id = fw.group("rule")
            src_ip = fw.group("src")
            dst_ip = fw.group("dst")
            proto = fw.group("proto")
            iface = fw.group("iface")
            spt = fw.group("spt")
            dpt = fw.group("dpt")
            action = _infer_action(rule_id)
            direction = _classify_direction(src_ip, dst_ip, iface)
            return {
                "log_type": "firewall",
                "action": action,
                "direction": direction,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(spt) if spt else None,
                "dst_port": int(dpt) if dpt else None,
                "protocol": proto.upper() if proto else None,
                "interface": iface or None,
                "rule_id": rule_id,
                "mac": None,
                "msg": f"{action.upper()} {src_ip}→{dst_ip} [{rule_id}]",
                "raw": line,
            }

    # ── DHCP ──────────────────────────────────────────────────────────────────
    if "dhcp" in proc or body.upper().startswith("DHCP"):
        dhcp = _RE_DHCP_DNSMASQ.search(body) or _RE_DHCP_ISC.search(body)
        if dhcp:
            ip = dhcp.group("ip") if "ip" in dhcp.groupdict() else None
            mac = dhcp.group("mac") if "mac" in dhcp.groupdict() else None
            hostname = dhcp.groupdict().get("hostname") or None
            iface = dhcp.groupdict().get("iface") or None
            event_type = dhcp.group("type").upper()
            return {
                "log_type": "dhcp",
                "action": "allow",
                "direction": "local",
                "src_ip": None,
                "dst_ip": ip,
                "src_port": None,
                "dst_port": None,
                "protocol": "UDP",
                "interface": iface,
                "rule_id": None,
                "mac": mac,
                "msg": f"{event_type} {ip} {mac or ''} {hostname or ''}".strip(),
                "raw": line,
            }

    # ── Wi-Fi ──────────────────────────────────────────────────────────────────
    if "hostapd" in proc:
        wifi = _RE_WIFI.search(body)
        if wifi:
            mac = wifi.group("mac")
            event = wifi.group("event").lower()
            iface = wifi.group("iface")
            action = "allow" if "associated" in event else "block"
            return {
                "log_type": "wifi",
                "action": action,
                "direction": "local",
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "interface": iface,
                "rule_id": None,
                "mac": mac,
                "msg": f"STA {mac} {event}",
                "raw": line,
            }

    return None


def _parse_timestamp(m):
    """Build a UTC datetime from syslog header match groups (no year — use current)."""
    try:
        now = datetime.now(timezone.utc)
        ts_str = f"{m.group('month')} {m.group('day').zfill(2)} {m.group('time')} {now.year}"
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        # If the parsed date is in the future, it probably rolled over to the prior year
        if dt > now:
            dt = dt.replace(year=now.year - 1)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


class UnifiSyslogReceiver:
    """
    Background UDP syslog receiver that parses incoming UniFi log messages
    and inserts them into the database via a Flask app context.
    """

    def __init__(self, app, host="0.0.0.0", port=5514):
        self.app = app
        self.host = host
        self.port = port
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="unifi-syslog")
        self._thread.start()
        logger.info("UniFi syslog receiver started on UDP %s:%d", self.host, self.port)

    def stop(self):
        self._stop_event.set()

    def _run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind((self.host, self.port))
        except OSError as e:
            logger.error("UniFi syslog: cannot bind UDP %s:%d — %s", self.host, self.port, e)
            return

        while not self._stop_event.is_set():
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                line = data.decode("utf-8", errors="replace")
                self._handle(line)
            except Exception as e:
                logger.debug("UniFi syslog handle error: %s", e)

        sock.close()

    def _handle(self, line):
        parsed = parse_syslog_line(line)
        if parsed is None:
            return

        # Determine timestamp from header if possible
        m = _RE_HDR.match(line.strip())
        ts = _parse_timestamp(m) if m else datetime.now(timezone.utc)

        # GeoIP enrichment
        geo = {}
        with self.app.app_context():
            from models import Setting
            geoip_enabled = Setting.get("unifi_geoip_enabled", "false") == "true"
            geoip_db_path = Setting.get("unifi_geoip_db_path", "")

        if geoip_enabled and geoip_db_path:
            import unifi_geoip
            ext_ip = parsed.get("src_ip") or parsed.get("dst_ip")
            geo = unifi_geoip.lookup(ext_ip, geoip_db_path)

        with self.app.app_context():
            from models import db, UnifiLogEntry
            entry = UnifiLogEntry(
                timestamp=ts,
                source="syslog",
                log_type=parsed["log_type"],
                action=parsed.get("action"),
                direction=parsed.get("direction"),
                src_ip=parsed.get("src_ip"),
                dst_ip=parsed.get("dst_ip"),
                src_port=parsed.get("src_port"),
                dst_port=parsed.get("dst_port"),
                protocol=parsed.get("protocol"),
                interface=parsed.get("interface"),
                rule_id=parsed.get("rule_id"),
                mac=parsed.get("mac"),
                msg=parsed.get("msg"),
                raw=parsed.get("raw"),
                country=geo.get("country"),
                country_code=geo.get("country_code"),
                city=geo.get("city"),
            )
            db.session.add(entry)
            db.session.commit()


def start_syslog_receiver(app):
    """
    Create and start the syslog receiver if enabled in settings.
    Called once from app.py after the scheduler is initialized.
    """
    with app.app_context():
        from models import Setting
        enabled = Setting.get("unifi_syslog_enabled", "false") == "true"
        port = int(Setting.get("unifi_syslog_port", "5514") or 5514)

    if not enabled:
        logger.debug("UniFi syslog receiver is disabled.")
        return None

    receiver = UnifiSyslogReceiver(app, port=port)
    receiver.start()
    return receiver
