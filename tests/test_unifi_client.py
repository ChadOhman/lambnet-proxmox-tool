"""Tests for the UniFi API client (clients/unifi_client.py)."""

from unittest.mock import MagicMock, patch

import clients.unifi_client as unifi_module
from clients.unifi_client import UniFiClient, _safe_float


class TestSafeFloat:
    def test_none(self):
        assert _safe_float(None) is None

    def test_valid_float(self):
        assert _safe_float("3.14") == 3.14

    def test_valid_int(self):
        assert _safe_float(42) == 42.0

    def test_invalid(self):
        assert _safe_float("abc") is None


class TestUniFiClientInit:
    def test_strips_trailing_slash(self):
        c = UniFiClient("https://example.com/", "user", "pass")
        assert c.base_url == "https://example.com"

    def test_defaults(self):
        c = UniFiClient("https://example.com", "user", "pass")
        assert c.site == "default"
        assert c.is_udm is True

    def test_prefix_udm(self):
        c = UniFiClient("https://example.com", "user", "pass", is_udm=True)
        assert c._prefix == "/proxy/network"

    def test_prefix_legacy(self):
        c = UniFiClient("https://example.com", "user", "pass", is_udm=False)
        assert c._prefix == ""


class TestGetDevicesEnriched:
    """Test that get_devices() returns enriched device data."""

    def _make_client(self):
        c = UniFiClient("https://example.com", "user", "pass")
        c._logged_in = True
        return c

    @patch.object(UniFiClient, "_api_get")
    def test_enriched_fields(self, mock_get):
        mock_get.return_value = [{
            "name": "AP-01",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.10",
            "model": "U6-LR",
            "type": "uap",
            "state": 1,
            "uptime": 86400,
            "version": "6.5.28",
            "adopted": True,
            "system-stats": {"cpu": "15.2", "mem": "42.5"},
            "general_temperature": 55.0,
            "num_sta": 12,
            "loadavg_1": "0.5",
            "uplink": {"type": "wire", "speed": 1000, "tx_bytes": 1000000, "rx_bytes": 2000000},
            "radio_table_stats": [
                {"name": "ra0", "channel": 36, "ht": "VHT80", "tx_power": 23, "num_sta": 8, "cu_total": 35},
            ],
            "port_table": [
                {"name": "eth0", "speed": 1000, "up": True, "enable": True, "tx_bytes": 500, "rx_bytes": 600},
            ],
        }]

        client = self._make_client()
        devices = client.get_devices()

        assert len(devices) == 1
        d = devices[0]
        assert d["name"] == "AP-01"
        assert d["cpu"] == 15.2
        assert d["mem"] == 42.5
        assert d["temperature"] == 55.0
        assert d["num_sta"] == 12
        assert d["loadavg_1"] == 0.5
        assert d["uplink"]["speed"] == 1000
        assert d["uplink"]["tx_bytes"] == 1000000
        assert len(d["radio_table"]) == 1
        assert d["radio_table"][0]["channel"] == 36
        assert d["radio_table"][0]["cu_total"] == 35
        assert len(d["port_table"]) == 1
        assert d["port_table"][0]["up"] is True

    @patch.object(UniFiClient, "_api_get")
    def test_empty_response(self, mock_get):
        mock_get.return_value = None
        client = self._make_client()
        assert client.get_devices() == []


class TestParseClientEnriched:
    def test_enriched_fields(self):
        raw = {
            "hostname": "laptop",
            "ip": "192.168.1.50",
            "mac": "11:22:33:44:55:66",
            "network": "LAN",
            "is_wired": False,
            "uptime": 3600,
            "signal": -65,
            "satisfaction": 85,
            "channel": 36,
            "radio": "na",
            "essid": "MyWiFi",
            "ap_mac": "aa:bb:cc:dd:ee:ff",
            "oui": "Apple",
            "first_seen": 1700000000,
            "last_seen": 1700003600,
        }
        result = UniFiClient._parse_client(raw)
        assert result["signal"] == -65
        assert result["satisfaction"] == 85
        assert result["channel"] == 36
        assert result["essid"] == "MyWiFi"
        assert result["ap_mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["oui"] == "Apple"
        assert result["first_seen"] == 1700000000

    def test_defaults(self):
        result = UniFiClient._parse_client({})
        assert result["hostname"] == "Unknown"
        assert result["signal"] is None
        assert result["satisfaction"] is None
        assert result["ap_mac"] is None


class TestNewApiMethods:
    def _make_client(self):
        c = UniFiClient("https://example.com", "user", "pass")
        c._logged_in = True
        return c

    @patch.object(UniFiClient, "_api_get")
    def test_get_site_health(self, mock_get):
        mock_get.return_value = [{"subsystem": "wan", "status": "ok"}]
        client = self._make_client()
        result = client.get_site_health()
        assert result == [{"subsystem": "wan", "status": "ok"}]
        mock_get.assert_called_once_with("/api/s/default/stat/health")

    @patch.object(UniFiClient, "_api_get")
    def test_get_wlan_conf(self, mock_get):
        mock_get.return_value = [{"_id": "1", "name": "MyWiFi", "enabled": True, "security": "wpapsk"}]
        client = self._make_client()
        result = client.get_wlan_conf()
        assert len(result) == 1
        assert result[0]["name"] == "MyWiFi"
        assert result[0]["security"] == "wpapsk"

    @patch.object(UniFiClient, "_api_get")
    def test_get_all_clients(self, mock_get):
        mock_get.return_value = [{"hostname": "test", "ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        client = self._make_client()
        result = client.get_all_clients(within=48)
        assert len(result) == 1
        assert result[0]["hostname"] == "test"
        mock_get.assert_called_once_with("/api/s/default/stat/alluser?within=48")

    @patch.object(UniFiClient, "_api_get")
    def test_get_dpi_stats(self, mock_get):
        mock_get.return_value = [{"by_cat": [{"cat": 13, "rx_bytes": 100}]}]
        client = self._make_client()
        result = client.get_dpi_stats()
        assert len(result) == 1

    @patch.object(UniFiClient, "_api_get")
    def test_get_port_forward_rules(self, mock_get):
        mock_get.return_value = [{"_id": "1", "name": "SSH", "dst_port": "22", "fwd": "10.0.0.5", "fwd_port": "22"}]
        client = self._make_client()
        result = client.get_port_forward_rules()
        assert len(result) == 1
        assert result[0]["name"] == "SSH"
        assert result[0]["dst_port"] == "22"

    @patch.object(UniFiClient, "_api_get")
    def test_get_firewall_rules(self, mock_get):
        mock_get.return_value = [
            {"_id": "2", "name": "Allow DNS", "action": "accept", "rule_index": 2000},
            {"_id": "1", "name": "Block All", "action": "drop", "rule_index": 1000},
        ]
        client = self._make_client()
        result = client.get_firewall_rules()
        assert len(result) == 2
        # Should be sorted by rule_index
        assert result[0]["rule_index"] == 1000
        assert result[1]["rule_index"] == 2000

    @patch.object(UniFiClient, "_api_get")
    def test_get_site_health_none(self, mock_get):
        mock_get.return_value = None
        client = self._make_client()
        assert client.get_site_health() == []

    @patch.object(UniFiClient, "_api_get")
    def test_get_wlan_conf_none(self, mock_get):
        mock_get.return_value = None
        client = self._make_client()
        assert client.get_wlan_conf() == []


class TestApiPostData:
    @patch("clients.unifi_client.requests.Session")
    def test_returns_data(self, MockSession):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"time": 1000, "bytes": 500}]}
        mock_session.post.return_value = mock_resp

        c = UniFiClient("https://example.com", "user", "pass")
        c._logged_in = True
        c.session = mock_session

        result = c._api_post_data("/api/s/default/stat/report/daily.site", {"attrs": ["bytes"]})
        assert result == [{"time": 1000, "bytes": 500}]

    @patch("clients.unifi_client.requests.Session")
    def test_returns_none_on_error(self, MockSession):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_session.post.return_value = mock_resp

        c = UniFiClient("https://example.com", "user", "pass")
        c._logged_in = True
        c.session = mock_session

        result = c._api_post_data("/api/s/default/stat/report/daily.site", {})
        assert result is None


class TestCachedClient:
    """Tests for the module-level cached UniFi client."""

    def setup_method(self):
        """Clear cache before each test."""
        unifi_module._cached_client = None
        unifi_module._cached_settings_hash = None

    def test_returns_client_instance(self):
        from clients.unifi_client import get_cached_client
        c = get_cached_client("https://example.com", "user", "pass")
        assert isinstance(c, UniFiClient)
        assert c.base_url == "https://example.com"

    def test_returns_same_instance_on_repeat_call(self):
        from clients.unifi_client import get_cached_client
        c1 = get_cached_client("https://example.com", "user", "pass")
        c2 = get_cached_client("https://example.com", "user", "pass")
        assert c1 is c2

    def test_returns_new_instance_when_settings_change(self):
        from clients.unifi_client import get_cached_client
        c1 = get_cached_client("https://example.com", "user", "pass")
        c2 = get_cached_client("https://example.com", "user", "newpass")
        assert c1 is not c2

    def test_invalidate_clears_cache(self):
        from clients.unifi_client import get_cached_client, invalidate_cached_client
        c1 = get_cached_client("https://example.com", "user", "pass")
        invalidate_cached_client()
        c2 = get_cached_client("https://example.com", "user", "pass")
        assert c1 is not c2


class TestSessionExpiry:
    """Test that API methods retry login on 401."""

    def _make_client(self):
        c = UniFiClient("https://example.com", "user", "pass")
        c._logged_in = True
        return c

    @patch.object(UniFiClient, "login", return_value=True)
    def test_api_get_retries_on_401(self, mock_login):
        c = self._make_client()
        resp_401 = MagicMock(status_code=401)
        resp_200 = MagicMock(status_code=200)
        resp_200.json.return_value = {"data": [{"id": 1}]}
        c.session.get = MagicMock(side_effect=[resp_401, resp_200])
        result = c._api_get("/test")
        assert result == [{"id": 1}]
        assert mock_login.called

    @patch.object(UniFiClient, "login", return_value=False)
    def test_api_get_fails_after_retry_login_fails(self, mock_login):
        c = self._make_client()
        resp_401 = MagicMock(status_code=401)
        c.session.get = MagicMock(return_value=resp_401)
        result = c._api_get("/test")
        assert result is None

    @patch.object(UniFiClient, "login", return_value=True)
    def test_api_post_retries_on_401(self, mock_login):
        c = self._make_client()
        resp_401 = MagicMock(status_code=401)
        resp_200 = MagicMock(status_code=200)
        c.session.post = MagicMock(side_effect=[resp_401, resp_200])
        ok, msg = c._api_post("/test", {"key": "val"})
        assert ok is True
        assert mock_login.called

    @patch.object(UniFiClient, "login", return_value=True)
    def test_api_post_data_retries_on_401(self, mock_login):
        c = self._make_client()
        resp_401 = MagicMock(status_code=401)
        resp_200 = MagicMock(status_code=200)
        resp_200.json.return_value = {"data": [{"id": 1}]}
        c.session.post = MagicMock(side_effect=[resp_401, resp_200])
        result = c._api_post_data("/test", {"key": "val"})
        assert result == [{"id": 1}]
        assert mock_login.called
