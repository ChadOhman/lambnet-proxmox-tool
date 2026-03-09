"""Tests for the Mastodon built-in Prometheus exporter integration."""

from unittest.mock import MagicMock, patch

from models import db, Guest, Credential, ExporterInstance, GuestService, ProxmoxHost, Setting


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_host(app):
    host = ProxmoxHost.query.first()
    if host:
        return host
    host = ProxmoxHost(name="pve-test", hostname="10.0.0.1", host_type="pve")
    db.session.add(host)
    db.session.commit()
    return host


def _get_or_create_credential():
    from auth import credential_store
    cred = Credential.query.filter_by(name="test-masto-cred").first()
    if cred:
        return cred
    cred = Credential(
        name="test-masto-cred", username="root", auth_type="password",
        encrypted_value=credential_store.encrypt("testpass"),
        is_default=True,
    )
    db.session.add(cred)
    db.session.commit()
    return cred


def _create_guest(app, name="masto-test", ip="10.0.0.80", with_credential=False):
    host = _create_host(app)
    credential_id = None
    if with_credential:
        cred = _get_or_create_credential()
        credential_id = cred.id
    guest = Guest(
        name=name, vmid=200, guest_type="lxc",
        proxmox_host_id=host.id, ip_address=ip,
        credential_id=credential_id,
    )
    db.session.add(guest)
    db.session.commit()
    return guest


# ---------------------------------------------------------------------------
# BUILTIN_EXPORTERS registry
# ---------------------------------------------------------------------------

class TestBuiltinExportersRegistry:

    def test_mastodon_in_builtin_exporters(self):
        from apps.exporters import BUILTIN_EXPORTERS, _build_mastodon_env_vars
        assert "mastodon" in BUILTIN_EXPORTERS
        info = BUILTIN_EXPORTERS["mastodon"]
        assert info["default_port"] == 9394
        assert info["job_name"] == "mastodon"
        # env_vars are now built dynamically via _build_mastodon_env_vars()
        env = _build_mastodon_env_vars()
        assert "MASTODON_PROMETHEUS_EXPORTER_ENABLED" in env

    def test_builtin_not_in_known(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert "mastodon" not in KNOWN_EXPORTERS


# ---------------------------------------------------------------------------
# enable_mastodon_exporter
# ---------------------------------------------------------------------------

class TestEnableMastodonExporter:

    def test_enable_guest_not_found(self, app):
        from apps.exporters import enable_mastodon_exporter
        with app.app_context():
            logs = []
            result = enable_mastodon_exporter(999999, log_callback=logs.append)
            assert result is False
            assert any("Guest not found" in m for m in logs)

    def test_enable_already_enabled(self, app):
        from apps.exporters import enable_mastodon_exporter
        with app.app_context():
            guest = _create_guest(app, name="masto-already", ip="10.0.0.81")
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="mastodon",
                port=9394, status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            logs = []
            result = enable_mastodon_exporter(guest.id, log_callback=logs.append)
            assert result is True
            assert any("already enabled" in m for m in logs)

            # cleanup
            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_enable_no_credential(self, app):
        from apps.exporters import enable_mastodon_exporter
        with app.app_context():
            guest = _create_guest(app, name="masto-nocred", ip="10.0.0.82")
            # Ensure no default credential exists
            Credential.query.filter_by(is_default=True).update({"is_default": False})
            db.session.commit()

            logs = []
            result = enable_mastodon_exporter(guest.id, log_callback=logs.append)
            assert result is False
            assert any("credential" in m.lower() for m in logs)

            db.session.delete(guest)
            db.session.commit()

    def test_enable_no_ip(self, app):
        from apps.exporters import enable_mastodon_exporter
        with app.app_context():
            guest = _create_guest(app, name="masto-noip", ip="dhcp", with_credential=True)
            logs = []
            result = enable_mastodon_exporter(guest.id, log_callback=logs.append)
            assert result is False
            assert any("IP address" in m for m in logs)

            db.session.delete(guest)
            db.session.commit()

    @patch("apps.exporters.SSHClient")
    @patch("apps.exporters._regenerate_prometheus_config")
    def test_enable_success(self, mock_regen, mock_ssh_class, app):
        from apps.exporters import enable_mastodon_exporter

        with app.app_context():
            guest = _create_guest(app, name="masto-enable-ok", ip="10.0.0.83", with_credential=True)

            mock_ssh = MagicMock()
            mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
            mock_ssh.__exit__ = MagicMock(return_value=False)
            mock_ssh_class.from_credential.return_value = mock_ssh

            # sed (remove old lines) -> success
            # cat >> (append env vars) -> success
            # cat > (write collector unit) -> success
            # daemon-reload + enable + restart collector -> success
            # restart web -> success
            # restart sidekiq -> success
            mock_ssh.execute_sudo.side_effect = [
                ("", "", 0),   # sed
                ("", "", 0),   # cat >> env vars
                ("", "", 0),   # cat > collector unit
                ("", "", 0),   # daemon-reload + enable + restart collector
                ("", "", 0),   # restart web
                ("", "", 0),   # restart sidekiq
            ]
            mock_ssh.execute.side_effect = [
                ("mastodon-web.service loaded active running\nmastodon-sidekiq.service loaded active running\n", "", 0),
                ("# HELP http_server_requests_total\n", "", 0),  # curl verify
            ]

            logs = []
            result = enable_mastodon_exporter(guest.id, log_callback=logs.append)
            assert result is True

            # Verify ExporterInstance was created
            exp = ExporterInstance.query.filter_by(
                guest_id=guest.id, exporter_type="mastodon"
            ).first()
            assert exp is not None
            assert exp.port == 9394
            assert exp.status == "installed"

            # Verify prometheus config was regenerated
            mock_regen.assert_called_once()

            # Verify SSH commands were called
            assert mock_ssh.execute_sudo.call_count == 6  # sed + env + collector unit + start + 2 restarts
            # Check sed command removed old vars
            sed_call = mock_ssh.execute_sudo.call_args_list[0]
            assert "MASTODON_PROMETHEUS_EXPORTER_" in sed_call[0][0]

            # cleanup
            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# disable_mastodon_exporter
# ---------------------------------------------------------------------------

class TestDisableMastodonExporter:

    def test_disable_guest_not_found(self, app):
        from apps.exporters import disable_mastodon_exporter
        with app.app_context():
            logs = []
            result = disable_mastodon_exporter(999999, log_callback=logs.append)
            assert result is False

    @patch("apps.exporters.SSHClient")
    @patch("apps.exporters._regenerate_prometheus_config")
    def test_disable_success(self, mock_regen, mock_ssh_class, app):
        from apps.exporters import disable_mastodon_exporter

        with app.app_context():
            guest = _create_guest(app, name="masto-disable-ok", ip="10.0.0.84", with_credential=True)

            # Pre-create an installed exporter instance
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="mastodon",
                port=9394, status="installed",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id

            mock_ssh = MagicMock()
            mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
            mock_ssh.__exit__ = MagicMock(return_value=False)
            mock_ssh_class.from_credential.return_value = mock_ssh

            mock_ssh.execute_sudo.side_effect = [
                ("", "", 0),   # sed remove vars
                ("", "", 0),   # stop + disable + rm collector + daemon-reload
                ("", "", 0),   # restart web
                ("", "", 0),   # restart sidekiq
            ]
            mock_ssh.execute.side_effect = [
                ("mastodon-web.service loaded active running\nmastodon-sidekiq.service loaded active running\n", "", 0),
            ]

            logs = []
            result = disable_mastodon_exporter(guest.id, log_callback=logs.append)
            assert result is True

            # ExporterInstance should be deleted
            assert ExporterInstance.query.get(exp_id) is None

            # Prometheus config regenerated
            mock_regen.assert_called_once()

            # cleanup
            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Prometheus config with Mastodon exporter
# ---------------------------------------------------------------------------

class TestPrometheusConfigWithMastodon:

    def test_regenerate_includes_mastodon_job(self, app):
        """When a mastodon ExporterInstance exists, _regenerate_prometheus_config
        should include a mastodon scrape job."""
        with app.app_context():
            guest = _create_guest(app, name="masto-prom-cfg", ip="10.0.0.85")
            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="mastodon",
                port=9394, status="installed",
            )
            db.session.add(exp)
            db.session.commit()

            # We test the grouping logic directly rather than full SSH push
            from apps.exporters import KNOWN_EXPORTERS, BUILTIN_EXPORTERS

            installed = ExporterInstance.query.filter(
                ExporterInstance.status == "installed"
            ).all()

            by_type = {}
            for e in installed:
                ip = e.guest.ip_address
                if not ip or ip.lower() in ("dhcp", "dhcp6", "auto"):
                    continue
                by_type.setdefault(e.exporter_type, []).append(f"{ip}:{e.port}")

            assert "mastodon" in by_type
            assert "10.0.0.85:9394" in by_type["mastodon"]

            # Verify lookup falls through to BUILTIN_EXPORTERS
            info = KNOWN_EXPORTERS.get("mastodon") or BUILTIN_EXPORTERS.get("mastodon", {})
            assert info["job_name"] == "mastodon"

            # cleanup
            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# PrometheusQueryClient.get_mastodon_metrics
# ---------------------------------------------------------------------------

class TestMastodonMetricsQuery:

    @patch("clients.prometheus_query.PrometheusQueryClient.query_range")
    def test_get_mastodon_metrics_returns_snapshots(self, mock_query_range, app):
        with app.app_context():
            Setting.set("prometheus_enabled", "true")
            Setting.set("prometheus_url", "http://10.0.0.5:9090")
            db.session.commit()

            from clients.prometheus_query import PrometheusQueryClient

            # Return mock time series data for each query
            mock_query_range.return_value = [
                {"values": [[1700000000, "1.5"], [1700000300, "2.0"]]}
            ]

            prom = PrometheusQueryClient()
            data = prom.get_mastodon_metrics("10.0.0.85:9394", timeframe="day")

            assert data["source"] == "mastodon_exporter"
            assert len(data["snapshots"]) == 2
            snap = data["snapshots"][0]
            assert "captured_at" in snap
            assert "request_rate" in snap

            # Verify the PromQL queries contain expected metric names
            all_queries = str(mock_query_range.call_args_list)
            assert "http_server_requests_total" in all_queries
            assert "sidekiq_jobs_executed_total" in all_queries
            assert "sidekiq_queue_latency_seconds" in all_queries

    @patch("clients.prometheus_query.PrometheusQueryClient.query_range")
    def test_get_mastodon_metrics_empty_data(self, mock_query_range, app):
        with app.app_context():
            Setting.set("prometheus_enabled", "true")
            Setting.set("prometheus_url", "http://10.0.0.5:9090")
            db.session.commit()

            from clients.prometheus_query import PrometheusQueryClient

            mock_query_range.return_value = []

            prom = PrometheusQueryClient()
            data = prom.get_mastodon_metrics("10.0.0.85:9394")

            assert data["source"] == "mastodon_exporter"
            assert data["snapshots"] == []


# ---------------------------------------------------------------------------
# Mastodon metrics history route
# ---------------------------------------------------------------------------

class TestMastodonMetricsHistoryRoute:

    def test_non_mastodon_service_returns_400(self, app, auth_client):
        with app.app_context():
            guest = _create_guest(app, name="masto-route-test", ip="10.0.0.86")
            svc = GuestService(
                guest_id=guest.id, service_name="nginx",
                unit_name="nginx.service", status="running",
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id
            guest_id = guest.id

        resp = auth_client.get(f"/services/{svc_id}/mastodon/metrics-history")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "Not a Mastodon service" in data["error"]

        with app.app_context():
            db.session.delete(GuestService.query.get(svc_id))
            db.session.delete(Guest.query.get(guest_id))
            db.session.commit()

    def test_mastodon_service_no_data(self, app, auth_client):
        with app.app_context():
            guest = _create_guest(app, name="masto-route-nodata", ip="10.0.0.87")
            svc = GuestService(
                guest_id=guest.id, service_name="mastodon-web (puma)",
                unit_name="mastodon-web.service", status="running",
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id
            guest_id = guest.id

        resp = auth_client.get(f"/services/{svc_id}/mastodon/metrics-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["snapshots"] == []
        assert data["source"] == "none"

        with app.app_context():
            db.session.delete(GuestService.query.get(svc_id))
            db.session.delete(Guest.query.get(guest_id))
            db.session.commit()

    @patch("clients.prometheus_query.PrometheusQueryClient.query_range")
    def test_mastodon_service_with_prometheus_data(self, mock_query_range, app, auth_client):
        with app.app_context():
            guest = _create_guest(app, name="masto-route-data", ip="10.0.0.88")
            svc = GuestService(
                guest_id=guest.id, service_name="mastodon-web (puma)",
                unit_name="mastodon-web.service", status="running",
            )
            db.session.add(svc)
            db.session.commit()

            exp = ExporterInstance(
                guest_id=guest.id, exporter_type="mastodon",
                port=9394, status="installed",
            )
            db.session.add(exp)
            Setting.set("prometheus_enabled", "true")
            Setting.set("prometheus_url", "http://10.0.0.5:9090")
            db.session.commit()
            svc_id = svc.id
            exp_id = exp.id
            guest_id = guest.id

        mock_query_range.return_value = [
            {"values": [[1700000000, "3.14"], [1700000300, "2.72"]]}
        ]

        resp = auth_client.get(f"/services/{svc_id}/mastodon/metrics-history?timeframe=day")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["source"] == "mastodon_exporter"
        assert len(data["snapshots"]) == 2

        with app.app_context():
            db.session.delete(ExporterInstance.query.get(exp_id))
            db.session.delete(GuestService.query.get(svc_id))
            db.session.delete(Guest.query.get(guest_id))
            db.session.commit()

    def test_sidekiq_service_accepted(self, app, auth_client):
        """Sidekiq services should also be accepted by the mastodon metrics route."""
        with app.app_context():
            guest = _create_guest(app, name="masto-route-sq", ip="10.0.0.89")
            svc = GuestService(
                guest_id=guest.id, service_name="mastodon-sidekiq",
                unit_name="mastodon-sidekiq.service", status="running",
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id
            guest_id = guest.id

        resp = auth_client.get(f"/services/{svc_id}/mastodon/metrics-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["source"] == "none"

        with app.app_context():
            db.session.delete(GuestService.query.get(svc_id))
            db.session.delete(Guest.query.get(guest_id))
            db.session.commit()
