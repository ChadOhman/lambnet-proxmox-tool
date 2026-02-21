import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class UniFiClient:
    """Client for UniFi Controller / UniFi OS API."""

    def __init__(self, base_url, username, password, site="default", is_udm=True):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.is_udm = is_udm
        self.session = requests.Session()
        self.session.verify = False
        self._logged_in = False

    @property
    def _prefix(self):
        return "/proxy/network" if self.is_udm else ""

    def login(self):
        if self._logged_in:
            return True

        if self.is_udm:
            url = f"{self.base_url}/api/auth/login"
        else:
            url = f"{self.base_url}/api/login"

        try:
            resp = self.session.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=10,
            )
            if resp.status_code == 200:
                self._logged_in = True
                return True
            logger.warning("UniFi login failed: HTTP %s", resp.status_code)
            return False
        except requests.RequestException as e:
            logger.error("UniFi login error: %s", e)
            return False

    def _api_get(self, path):
        if not self._logged_in:
            if not self.login():
                return None
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", [])
            logger.warning("UniFi API GET %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("UniFi API error: %s", e)
            return None

    def _api_post(self, path, payload):
        if not self._logged_in:
            if not self.login():
                return False, "Not authenticated"
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return True, "OK"
            return False, f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            return False, str(e)

    def get_devices(self):
        raw = self._api_get(f"/api/s/{self.site}/stat/device")
        if raw is None:
            return []
        devices = []
        for d in raw:
            devices.append({
                "name": d.get("name", d.get("hostname", "Unknown")),
                "mac": d.get("mac", ""),
                "ip": d.get("ip", ""),
                "model": d.get("model", ""),
                "type": d.get("type", ""),
                "state": d.get("state", 0),
                "uptime": d.get("uptime", 0),
                "version": d.get("version", ""),
                "adopted": d.get("adopted", False),
            })
        return devices

    @staticmethod
    def _parse_client(c):
        radio = c.get("radio", "")
        radio_band = {
            "ng": "2.4 GHz", "na": "5 GHz", "ac": "5 GHz (ac)",
            "ax": "Wi-Fi 6", "6e": "Wi-Fi 6E", "be": "Wi-Fi 7",
        }.get(radio, radio or None)
        return {
            "hostname": c.get("hostname", c.get("name", c.get("oui", "Unknown"))),
            "ip": c.get("ip", ""),
            "mac": c.get("mac", ""),
            "network": c.get("network", ""),
            "is_wired": c.get("is_wired", False),
            "signal": c.get("signal", None),
            "rssi": c.get("rssi", None),
            "noise": c.get("noise", None),
            "satisfaction": c.get("satisfaction", None),
            "uptime": c.get("uptime", 0),
            "idle_time": c.get("idletime", None),
            "last_seen": c.get("last_seen", None),
            "tx_bytes": c.get("tx_bytes", None),
            "rx_bytes": c.get("rx_bytes", None),
            "tx_packets": c.get("tx_packets", None),
            "rx_packets": c.get("rx_packets", None),
            "tx_rate": c.get("tx_rate", None),
            "rx_rate": c.get("rx_rate", None),
            "ap_mac": c.get("ap_mac", None),
            "channel": c.get("channel", None),
            "radio": radio,
            "radio_band": radio_band,
            "blocked": c.get("blocked", False),
        }

    def get_clients(self):
        raw = self._api_get(f"/api/s/{self.site}/stat/sta")
        if raw is None:
            return []
        return [self._parse_client(c) for c in raw]

    def get_client_by_mac(self, mac):
        """Fetch live stats for a single client by MAC address."""
        raw = self._api_get(f"/api/s/{self.site}/stat/sta/{mac.lower()}")
        if not raw:
            return None
        return self._parse_client(raw[0])

    def reconnect_client(self, mac):
        """Force reconnect a wireless client."""
        return self._api_post(
            f"/api/s/{self.site}/cmd/stamgr",
            {"cmd": "kick-sta", "mac": mac},
        )

    def block_client(self, mac):
        """Block a client from the network."""
        return self._api_post(
            f"/api/s/{self.site}/cmd/stamgr",
            {"cmd": "block-sta", "mac": mac},
        )

    def unblock_client(self, mac):
        """Unblock a client on the network."""
        return self._api_post(
            f"/api/s/{self.site}/cmd/stamgr",
            {"cmd": "unblock-sta", "mac": mac},
        )

    def restart_device(self, mac):
        return self._api_post(
            f"/api/s/{self.site}/cmd/devmgr",
            {"cmd": "restart", "mac": mac},
        )

    def test_connection(self):
        if not self.login():
            return False, "Login failed"
        devices = self.get_devices()
        if devices is None:
            return False, "Could not fetch devices"
        return True, f"Connected. {len(devices)} device(s) found."
