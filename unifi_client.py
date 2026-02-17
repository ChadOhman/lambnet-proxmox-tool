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

    def get_clients(self):
        raw = self._api_get(f"/api/s/{self.site}/stat/sta")
        if raw is None:
            return []
        clients = []
        for c in raw:
            clients.append({
                "hostname": c.get("hostname", c.get("name", c.get("oui", "Unknown"))),
                "ip": c.get("ip", ""),
                "mac": c.get("mac", ""),
                "network": c.get("network", ""),
                "is_wired": c.get("is_wired", False),
                "signal": c.get("signal", None),
                "uptime": c.get("uptime", 0),
            })
        return clients

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
