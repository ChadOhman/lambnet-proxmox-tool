"""
Redfish API client for Supermicro IPMI / BMC management.

Provides session-based HTTPS access to the DMTF Redfish REST API exposed
by Supermicro BMCs (and compatible Dell iDRAC / HPE iLO controllers).
"""

import logging

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

# Redfish reset type values
_RESET_TYPES = {
    "on": "On",
    "off": "ForceOff",
    "reset": "ForceRestart",
    "cycle": "PowerCycle",
    "graceful_shutdown": "GracefulShutdown",
}


class RedfishClient:
    """Client for the DMTF Redfish REST API on a BMC."""

    def __init__(self, base_url, username, password, verify_ssl=False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self._token = None
        self._session_uri = None

    def login(self):
        """Authenticate via Redfish session service. Returns True on success."""
        if self._token:
            return True

        url = f"{self.base_url}/redfish/v1/SessionService/Sessions"
        try:
            resp = self.session.post(
                url,
                json={"UserName": self.username, "Password": self.password},
                timeout=10,
            )
            if resp.status_code in (200, 201):
                self._token = resp.headers.get("X-Auth-Token")
                self._session_uri = resp.headers.get("Location", "")
                if self._token:
                    self.session.headers["X-Auth-Token"] = self._token
                return True
            logger.warning("Redfish login failed: HTTP %s", resp.status_code)
            return False
        except requests.RequestException as e:
            logger.error("Redfish login error: %s", e)
            return False

    def logout(self):
        """Delete the Redfish session."""
        if self._session_uri and self._token:
            try:
                self.session.delete(
                    f"{self.base_url}{self._session_uri}" if self._session_uri.startswith("/") else self._session_uri,
                    timeout=10,
                )
            except requests.RequestException:
                pass
        self._token = None
        self._session_uri = None
        self.session.headers.pop("X-Auth-Token", None)

    def _get(self, path):
        """GET a Redfish resource. Auto-authenticates and retries on 401."""
        if not self._token and not self.login():
            return None

        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 401:
                self._token = None
                if self.login():
                    resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            logger.warning("Redfish GET %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("Redfish GET error: %s", e)
            return None

    def _post(self, path, payload):
        """POST to a Redfish resource. Returns (success, message)."""
        if not self._token and not self.login():
            return False, "Not authenticated"

        url = f"{self.base_url}{path}"
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 401:
                self._token = None
                if self.login():
                    resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code in (200, 202, 204):
                return True, "OK"
            body = ""
            try:
                body = resp.json().get("error", {}).get("message", "")
            except Exception:
                pass
            return False, f"HTTP {resp.status_code}: {body}"
        except requests.RequestException as e:
            return False, str(e)

    def test_connection(self):
        """Test connectivity to the BMC. Returns (success, message)."""
        data = self._get("/redfish/v1")
        if data is None:
            return False, "Could not reach Redfish service root"
        product = data.get("Product", data.get("Name", "Redfish Service"))
        return True, f"Connected to {product}"

    # ----- System Info -----

    def get_system_info(self):
        """Get basic system information."""
        data = self._get("/redfish/v1/Systems/1")
        if not data:
            return None
        return {
            "manufacturer": data.get("Manufacturer", ""),
            "model": data.get("Model", ""),
            "serial": data.get("SerialNumber", ""),
            "bios_version": data.get("BiosVersion", ""),
            "hostname": data.get("HostName", ""),
            "uuid": data.get("UUID", ""),
            "power_state": data.get("PowerState", "Unknown"),
            "health": data.get("Status", {}).get("Health", "Unknown"),
            "state": data.get("Status", {}).get("State", "Unknown"),
            "total_memory_gb": (data.get("MemorySummary", {}).get("TotalSystemMemoryGiB") or 0),
            "processor_count": (data.get("ProcessorSummary", {}).get("Count") or 0),
            "processor_model": (data.get("ProcessorSummary", {}).get("Model", "")),
        }

    # ----- Thermal (temperatures + fans) -----

    def get_thermal(self):
        """Get temperature and fan sensor readings."""
        data = self._get("/redfish/v1/Chassis/1/Thermal")
        if not data:
            return {"temperatures": [], "fans": []}

        temperatures = []
        for t in data.get("Temperatures", []):
            reading = t.get("ReadingCelsius")
            if reading is None:
                continue
            temperatures.append({
                "name": t.get("Name", "Unknown"),
                "reading_celsius": reading,
                "upper_threshold_critical": t.get("UpperThresholdCritical"),
                "upper_threshold_fatal": t.get("UpperThresholdFatal"),
                "health": t.get("Status", {}).get("Health", "OK"),
                "state": t.get("Status", {}).get("State", "Enabled"),
            })

        fans = []
        for f in data.get("Fans", []):
            reading = f.get("Reading", f.get("CurrentReading"))
            if reading is None:
                continue
            fans.append({
                "name": f.get("Name", f.get("FanName", "Unknown")),
                "reading_rpm": reading,
                "units": f.get("ReadingUnits", f.get("Units", "RPM")),
                "health": f.get("Status", {}).get("Health", "OK"),
                "state": f.get("Status", {}).get("State", "Enabled"),
            })

        return {"temperatures": temperatures, "fans": fans}

    # ----- Power (PSUs + consumption) -----

    def get_power(self):
        """Get power supply and consumption info."""
        data = self._get("/redfish/v1/Chassis/1/Power")
        if not data:
            return {"power_supplies": [], "power_control": []}

        psus = []
        for p in data.get("PowerSupplies", []):
            psus.append({
                "name": p.get("Name", "PSU"),
                "model": p.get("Model", ""),
                "serial": p.get("SerialNumber", ""),
                "power_output_watts": p.get("PowerOutputWatts") or p.get("LastPowerOutputWatts"),
                "power_capacity_watts": p.get("PowerCapacityWatts"),
                "health": p.get("Status", {}).get("Health", "OK"),
                "state": p.get("Status", {}).get("State", "Enabled"),
            })

        power_control = []
        for pc in data.get("PowerControl", []):
            power_control.append({
                "name": pc.get("Name", "System Power"),
                "power_consumed_watts": pc.get("PowerConsumedWatts"),
                "power_capacity_watts": pc.get("PowerCapacityWatts"),
                "min_consumed_watts": pc.get("PowerMetrics", {}).get("MinConsumedWatts"),
                "max_consumed_watts": pc.get("PowerMetrics", {}).get("MaxConsumedWatts"),
                "avg_consumed_watts": pc.get("PowerMetrics", {}).get("AverageConsumedWatts"),
            })

        return {"power_supplies": psus, "power_control": power_control}

    # ----- System Event Log (SEL) -----

    def get_sel_entries(self, limit=100):
        """Get System Event Log entries."""
        data = self._get(f"/redfish/v1/Managers/1/LogServices/Log1/Entries?$top={limit}")
        if not data:
            return []

        entries = []
        for e in data.get("Members", []):
            entries.append({
                "id": e.get("Id", ""),
                "created": e.get("Created", ""),
                "message": e.get("Message", ""),
                "severity": e.get("Severity", e.get("EntryType", "")),
                "sensor_type": e.get("SensorType", ""),
            })
        return entries

    # ----- Power Control -----

    def power_action(self, action):
        """Execute a power action. action must be one of: on, off, reset, cycle, graceful_shutdown."""
        reset_type = _RESET_TYPES.get(action)
        if not reset_type:
            return False, f"Unknown power action: {action}. Valid: {', '.join(_RESET_TYPES)}"
        return self._post(
            "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
            {"ResetType": reset_type},
        )

    def power_on(self):
        return self.power_action("on")

    def power_off(self):
        return self.power_action("off")

    def power_reset(self):
        return self.power_action("reset")

    def power_cycle(self):
        return self.power_action("cycle")

    def graceful_shutdown(self):
        return self.power_action("graceful_shutdown")

    # ----- Convenience: combined snapshot -----

    def get_health_snapshot(self):
        """Get a combined snapshot of system info, thermal, and power data."""
        info = self.get_system_info()
        thermal = self.get_thermal()
        power = self.get_power()

        if not info:
            return None

        # Extract key metrics for dashboard display
        temps = thermal.get("temperatures", [])
        cpu_temp = None
        system_temp = None
        for t in temps:
            name_lower = t["name"].lower()
            if "cpu" in name_lower and cpu_temp is None:
                cpu_temp = t["reading_celsius"]
            elif ("system" in name_lower or "board" in name_lower) and system_temp is None:
                system_temp = t["reading_celsius"]

        total_watts = None
        for pc in power.get("power_control", []):
            if pc.get("power_consumed_watts") is not None:
                total_watts = pc["power_consumed_watts"]
                break

        return {
            **info,
            "temperatures": temps,
            "fans": thermal.get("fans", []),
            "power_supplies": power.get("power_supplies", []),
            "power_control": power.get("power_control", []),
            "cpu_temp": cpu_temp,
            "system_temp": system_temp,
            "total_watts": total_watts,
        }
