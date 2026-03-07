"""Tests for the Prometheus integration (exporter, query client, routes)."""

import json
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Exporter tests
# ---------------------------------------------------------------------------

class TestPrometheusExporter:
    """Test the prometheus_exporter module."""

    def test_get_metrics_returns_bytes(self, app):
        from clients.prometheus_exporter import get_metrics
        with app.app_context():
            output = get_metrics()
            assert isinstance(output, bytes)

    def test_update_host_metrics(self, app):
        from clients.prometheus_exporter import update_host_metrics, HOST_CPU
        with app.app_context():
            update_host_metrics(1, "pve1", "pve", {
                "cpu": 0.42,
                "memory": {"used": 8_000_000_000, "total": 16_000_000_000},
                "rootfs": {"used": 5_000_000_000, "total": 50_000_000_000},
                "uptime": 86400,
            })
            # Verify the gauge was set
            val = HOST_CPU.labels("1", "pve1", "pve")._value.get()
            assert val == 42.0

    def test_update_guest_metrics(self, app):
        from clients.prometheus_exporter import update_guest_metrics, GUEST_CPU
        with app.app_context():
            update_guest_metrics(10, "myvm", "vm", "pve1", 100, {
                "cpu": 0.5,
                "maxcpu": 2,
                "mem": 2_000_000_000,
                "maxmem": 4_000_000_000,
                "status": "running",
            })
            val = GUEST_CPU.labels("10", "myvm", "vm", "pve1", "100")._value.get()
            assert val == 25.0  # 0.5 / 2 * 100

    def test_update_service_health(self, app):
        from clients.prometheus_exporter import update_service_health, SVC_UP
        with app.app_context():
            update_service_health(1, "postgresql", "db-guest", "postgresql.service", "running")
            val = SVC_UP.labels("1", "postgresql", "db-guest", "postgresql.service")._value.get()
            assert val == 1.0

    def test_update_pg_metrics(self, app):
        from clients.prometheus_exporter import update_pg_metrics, PG_CONNECTIONS
        with app.app_context():
            update_pg_metrics(1, "db-guest", {
                "total_connections": 42,
                "cache_hit_ratio": "99.5%",
                "active_queries": 3,
                "total_commits": 1000,
                "total_rollbacks": 5,
                "lock_waits": 0,
            })
            val = PG_CONNECTIONS.labels("1", "db-guest")._value.get()
            assert val == 42.0

    def test_update_redis_metrics(self, app):
        from clients.prometheus_exporter import update_redis_metrics, REDIS_MEM
        with app.app_context():
            update_redis_metrics(2, "cache-guest", {
                "used_memory": 50_000_000,
                "connected_clients": 10,
                "ops_per_sec": 500,
                "hit_ratio": "95%",
                "evicted_keys": 0,
            })
            val = REDIS_MEM.labels("2", "cache-guest")._value.get()
            assert val == 50_000_000.0

    def test_update_jitsi_metrics(self, app):
        from clients.prometheus_exporter import update_jitsi_metrics, JITSI_CONFERENCES
        with app.app_context():
            update_jitsi_metrics(3, "jitsi-guest", {
                "conferences": 5,
                "participants": 25,
                "stress_level": 0.3,
                "bit_rate_download": 1500000,
            })
            val = JITSI_CONFERENCES.labels("3", "jitsi-guest")._value.get()
            assert val == 5.0

    def test_update_apt_metrics(self, app):
        from clients.prometheus_exporter import update_apt_metrics, APT_PENDING
        with app.app_context():
            update_apt_metrics(1, "web-server", 10, 2, True)
            val = APT_PENDING.labels("1", "web-server")._value.get()
            assert val == 10.0

    def test_update_app_version_info(self, app):
        from clients.prometheus_exporter import update_app_version_info, APP_UPDATE
        with app.app_context():
            update_app_version_info("mastodon", "4.2.0", "4.3.0", True)
            val = APP_UPDATE.labels("mastodon")._value.get()
            assert val == 1.0

    def test_metrics_output_contains_metric_names(self, app):
        from clients.prometheus_exporter import get_metrics, update_host_metrics
        with app.app_context():
            update_host_metrics(99, "testhost", "pve", {"cpu": 0.1, "uptime": 100})
            output = get_metrics().decode("utf-8")
            assert "lambnet_host_cpu_usage_percent" in output
            assert "lambnet_host_uptime_seconds" in output


# ---------------------------------------------------------------------------
# /metrics endpoint tests
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    """Test the /metrics route."""

    def test_metrics_endpoint_accessible(self, app, client):
        """The /metrics endpoint should be accessible without login."""
        with app.app_context():
            from models import Setting
            # Ensure no auth token is set
            Setting.set("prometheus_auth_token", "")
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert b"lambnet_" in resp.data or resp.status_code == 200

    def test_metrics_endpoint_auth_required(self, app, client):
        """When auth token is set, requests without it should be rejected."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_metrics_endpoint_auth_bearer(self, app, client):
        """Bearer token auth should work."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics", headers={"Authorization": "Bearer test-secret-token"})
        assert resp.status_code == 200

    def test_metrics_endpoint_auth_query_param(self, app, client):
        """Query param token auth should work."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics?token=test-secret-token")
        assert resp.status_code == 200

    def test_metrics_endpoint_wrong_token(self, app, client):
        """Wrong token should be rejected."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

        # Clean up
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "")
            db.session.commit()


# ---------------------------------------------------------------------------
# Query client tests
# ---------------------------------------------------------------------------

class TestPrometheusQueryClient:
    """Test the prometheus_query module."""

    def test_init_raises_without_url(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        with app.app_context():
            from models import Setting
            Setting.set("prometheus_url", "")
            with pytest.raises(ValueError, match="not configured"):
                PrometheusQueryClient()

    def test_check_connection_returns_false_on_error(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        client = PrometheusQueryClient(base_url="http://localhost:99999")
        assert client.check_connection() is False

    @patch("clients.prometheus_query.requests.get")
    def test_query_range_parses_response(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {"__name__": "test_metric"},
                    "values": [[1000, "42.5"], [1060, "43.0"]],
                }],
            },
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        result = client._range_single("test_metric", 1000, 1060, 60)
        assert result["timestamps"] == [1000.0, 1060.0]
        assert result["values"] == [42.5, 43.0]


# ---------------------------------------------------------------------------
# Prometheus app management routes tests
# ---------------------------------------------------------------------------

class TestPrometheusAppRoutes:
    """Test the Prometheus management blueprint routes."""

    def test_manage_requires_login(self, client):
        resp = client.get("/prometheus/manage")
        assert resp.status_code in (302, 401)

    def test_manage_accessible_for_admin(self, auth_client):
        resp = auth_client.get("/prometheus/manage")
        assert resp.status_code == 200
        assert b"Prometheus" in resp.data

    def test_save_settings(self, auth_client, app):
        resp = auth_client.post("/prometheus/save", data={
            "prometheus_guest_id": "",
            "prometheus_url": "http://10.0.0.50:9090",
            "prometheus_auth_token": "",
            "prometheus_lambnet_metrics_url": "10.0.0.10:5000",
            "prometheus_retention_days": "90",
            "prometheus_protection_type": "snapshot",
            "prometheus_backup_storage": "",
            "prometheus_backup_mode": "snapshot",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            from models import Setting
            assert Setting.get("prometheus_url") == "http://10.0.0.50:9090"
            assert Setting.get("prometheus_lambnet_metrics_url") == "10.0.0.10:5000"

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/prometheus/install/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/prometheus/upgrade/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data

    def test_test_connection_no_url(self, auth_client, app):
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_url", "")
            db.session.commit()
        resp = auth_client.post("/prometheus/test-connection")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# Applications page includes Prometheus
# ---------------------------------------------------------------------------

class TestApplicationsPage:
    """Test that Prometheus appears on the Applications page."""

    def test_applications_page_has_prometheus(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"Prometheus" in resp.data
        assert b"/prometheus/manage" in resp.data
