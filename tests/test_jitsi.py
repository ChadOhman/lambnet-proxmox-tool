"""Tests for Jitsi Meet install/upgrade routes and scheduler integration."""
import sys
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Helpers (mirror test_elk.py patterns)
# ---------------------------------------------------------------------------

def _make_app(config=None):
    """Return a minimal Flask-like app mock with working app_context()."""
    app = MagicMock()
    app.config = config or {}
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=ctx)
    ctx.__exit__ = MagicMock(return_value=False)
    app.app_context.return_value = ctx
    return app


class _SysModulesPatch:
    """Context-manager: temporarily inject mock modules into sys.modules."""

    def __init__(self, mocks: dict):
        self._mocks = mocks
        self._saved = {}

    def __enter__(self):
        for name, mock in self._mocks.items():
            self._saved[name] = sys.modules.get(name)
            sys.modules[name] = mock
        return self

    def __exit__(self, *_):
        for name, original in self._saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


class TestJitsiRouteAuth:
    """Jitsi routes require authentication and can_update permission."""

    def test_upgrade_page_unauthenticated(self, client):
        resp = client.get("/jitsi/upgrade", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_save_unauthenticated(self, client):
        resp = client.post("/jitsi/save", follow_redirects=False)
        assert resp.status_code == 302

    def test_check_unauthenticated(self, client):
        resp = client.post("/jitsi/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_unauthenticated(self, client):
        resp = client.post("/jitsi/detect-versions", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_unauthenticated(self, client):
        resp = client.post("/jitsi/preflight", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_post_unauthenticated(self, client):
        resp = client.post("/jitsi/upgrade", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_unauthenticated(self, client):
        resp = client.post("/jitsi/install", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_status_unauthenticated(self, client):
        resp = client.get("/jitsi/upgrade/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_status_unauthenticated(self, client):
        resp = client.get("/jitsi/preflight/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_status_unauthenticated(self, client):
        resp = client.get("/jitsi/install/status", follow_redirects=False)
        assert resp.status_code == 302


class TestJitsiRouteViewer:
    """Viewer users (can_update=False) should be denied access."""

    def test_viewer_denied_upgrade_page(self, app, client):
        from models import db, User, Role

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_jitsi_test_viewer",
                display_name="Jitsi Viewer",
                role_id=viewer_role.id,
            )
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        try:
            client.post(
                "/login",
                data={"username": "_jitsi_test_viewer", "password": "ViewerPass123!"},
                follow_redirects=False,
            )
            resp = client.get("/jitsi/upgrade", follow_redirects=False)
            assert resp.status_code == 302
            location = resp.headers.get("Location", "")
            assert "/jitsi" not in location
        finally:
            with app.app_context():
                User.query.filter_by(username="_jitsi_test_viewer").delete()
                db.session.commit()


class TestJitsiRouteAuthed:
    """Admin users (can_update=True) can access Jitsi routes."""

    def test_upgrade_page_loads(self, auth_client):
        resp = auth_client.get("/jitsi/upgrade")
        assert resp.status_code == 200
        assert b"Jitsi" in resp.data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/upgrade/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/preflight/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_save_persists_settings(self, app, auth_client):
        from models import Setting

        resp = auth_client.post(
            "/jitsi/save",
            data={
                "jitsi_guest_id": "99",
                "jitsi_hostname": "meet.example.com",
                "jitsi_cert_type": "letsencrypt",
                "jitsi_letsencrypt_email": "admin@example.com",
                "jitsi_url": "https://meet.example.com",
                "jitsi_current_version": "2.0.9457",
                "jitsi_auto_upgrade": "on",
                "jitsi_protection_type": "snapshot",
                "jitsi_backup_storage": "",
                "jitsi_backup_mode": "snapshot",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("jitsi_guest_id") == "99"
            assert Setting.get("jitsi_hostname") == "meet.example.com"
            assert Setting.get("jitsi_cert_type") == "letsencrypt"
            assert Setting.get("jitsi_letsencrypt_email") == "admin@example.com"
            assert Setting.get("jitsi_url") == "https://meet.example.com"
            assert Setting.get("jitsi_current_version") == "2.0.9457"
            assert Setting.get("jitsi_auto_upgrade") == "true"

    def test_save_validates_cert_type(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cert_type": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_cert_type") == "self-signed"

    def test_save_validates_protection_type(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={"jitsi_protection_type": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_protection_type") == "snapshot"

    def test_save_validates_backup_mode(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={
                "jitsi_backup_mode": "invalid",
                "jitsi_protection_type": "backup",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_backup_mode") == "snapshot"

    def test_check_no_guest_configured(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_guest_id", "")
        resp = auth_client.post("/jitsi/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_no_guest(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_guest_id", "")
        resp = auth_client.post("/jitsi/detect-versions", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Applications index
# ---------------------------------------------------------------------------


class TestApplicationsIndexJitsi:
    """Jitsi appears on the applications index page."""

    def test_jitsi_card_present(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"Jitsi" in resp.data
        assert b"/jitsi/upgrade" in resp.data


# ---------------------------------------------------------------------------
# Scheduler: _check_jitsi_release
# ---------------------------------------------------------------------------


class TestCheckJitsiRelease:
    def test_returns_early_when_no_jitsi_guest_configured(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_jitsi = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.check_jitsi_release.assert_not_called()

    def test_returns_early_when_not_installed(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "false",
        }.get(k, d)
        mock_jitsi = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.check_jitsi_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
            "jitsi_current_version": "2.0.9400",
            "jitsi_auto_upgrade": "false",
            "jitsi_last_notified_version": "",
        }.get(k, d)

        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (True, "2.0.9500", "")
        mock_notifier = MagicMock()
        mock_notifier.send_jitsi_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_called_once_with(
            "2.0.9400", "2.0.9500", ""
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
            "jitsi_current_version": "2.0.9400",
            "jitsi_auto_upgrade": "false",
            "jitsi_last_notified_version": "2.0.9500",
        }.get(k, d)

        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (True, "2.0.9500", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
        }.get(k, d)
        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (False, "2.0.9400", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
            "jitsi_current_version": "2.0.9400",
            "jitsi_auto_upgrade": "true",
            "jitsi_last_notified_version": "",
        }.get(k, d)

        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (True, "2.0.9500", "")
        mock_jitsi.run_jitsi_upgrade.return_value = (True, "")
        mock_notifier = MagicMock()
        mock_notifier.send_jitsi_update_notification.return_value = (True, "ok")
        mock_audit = MagicMock()
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=mock_db),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
            "auth.audit": mock_audit,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.run_jitsi_upgrade.assert_called_once()


# ---------------------------------------------------------------------------
# Notifier
# ---------------------------------------------------------------------------


class TestJitsiNotifier:
    """Jitsi notification functions exist and follow patterns."""

    def test_send_jitsi_update_notification_exists(self):
        from core.notifier import send_jitsi_update_notification
        assert callable(send_jitsi_update_notification)

    def test_upgrade_started_supports_jitsi(self, app):
        with app.app_context():
            from core.notifier import send_upgrade_started_notification
            ok, msg = send_upgrade_started_notification("jitsi", "2.0.9500", "manual")
            assert isinstance(ok, bool)

    def test_upgrade_result_supports_jitsi(self, app):
        with app.app_context():
            from core.notifier import send_upgrade_result_notification
            ok, msg = send_upgrade_result_notification("jitsi", "2.0.9500", True, "manual")
            assert isinstance(ok, bool)


# ---------------------------------------------------------------------------
# Cloudflare Zero Trust configuration
# ---------------------------------------------------------------------------


class TestJitsiCfRouteAuth:
    """Cloudflare configure routes require authentication."""

    def test_cf_configure_unauthenticated(self, client):
        resp = client.post("/jitsi/configure-cloudflare", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_cf_configure_status_unauthenticated(self, client):
        resp = client.get("/jitsi/configure-cloudflare/status", follow_redirects=False)
        assert resp.status_code == 302


class TestJitsiCfRouteAuthed:
    """Authenticated admin can use Cloudflare configure routes."""

    def test_cf_configure_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/configure-cloudflare/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_cf_configure_blocked_when_not_installed(self, app, auth_client):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_installed", "false")
        resp = auth_client.post("/jitsi/configure-cloudflare", follow_redirects=False)
        assert resp.status_code == 302

    def test_save_persists_cf_mode(self, app, auth_client):
        from models import Setting
        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cf_mode": "tcp_only", "jitsi_public_ip": ""},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_cf_mode") == "tcp_only"

    def test_save_validates_cf_mode(self, app, auth_client):
        from models import Setting
        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cf_mode": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_cf_mode") == "none"

    def test_save_persists_public_ip(self, app, auth_client):
        from models import Setting
        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cf_mode": "hybrid", "jitsi_public_ip": "203.0.113.1"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_public_ip") == "203.0.113.1"


class TestJitsiCloudflareLogic:
    """Unit tests for run_cloudflare_configure validation paths."""

    def test_mode_none_returns_error(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "none")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "nothing" in log.lower()

    def test_not_installed_returns_error(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "tcp_only")
            Setting.set("jitsi_installed", "false")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "installed" in log.lower()

    def test_hybrid_mode_requires_public_ip(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "hybrid")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")
            Setting.set("jitsi_public_ip", "")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "public ip" in log.lower() or "required" in log.lower()

    def test_hybrid_mode_validates_ip_format(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "hybrid")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")
            Setting.set("jitsi_public_ip", "not-an-ip")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "valid" in log.lower()

    def test_no_hostname_returns_error(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "tcp_only")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "hostname" in log.lower()


# ---------------------------------------------------------------------------
# Service monitoring tests
# ---------------------------------------------------------------------------


class TestJitsiServiceMonitoring:
    """Tests for Jitsi service monitoring integration."""

    def test_known_services_includes_jitsi(self):
        from models import GuestService
        assert "jitsi-videobridge2" in GuestService.KNOWN_SERVICES
        assert "jicofo" in GuestService.KNOWN_SERVICES
        assert "prosody" in GuestService.KNOWN_SERVICES
        # JVB should have port 8080
        assert GuestService.KNOWN_SERVICES["jitsi-videobridge2"][2] == 8080

    def test_jvb_metrics_history_unauthenticated(self, app, client):
        """Metrics history endpoint should redirect unauthenticated users."""
        from models import db, Guest, GuestService
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="jvb-test", vmid=9999, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="jitsi-videobridge2",
                unit_name="jitsi-videobridge2.service",
                port=8080,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = client.get(f"/services/{svc_id}/jvb/metrics-history")
        assert resp.status_code == 302

    def test_jvb_metrics_history_wrong_service_type(self, app, auth_client):
        """Metrics history returns 400 for non-JVB services."""
        from models import db, Guest, GuestService
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="pg-test", vmid=9998, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="postgresql",
                unit_name="postgresql.service",
                port=5432,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/jvb/metrics-history")
        assert resp.status_code == 400

    def test_jvb_metrics_history_empty(self, app, auth_client):
        """Metrics history returns empty snapshots for a JVB service with no data."""
        from models import db, Guest, GuestService
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="jvb-empty", vmid=9997, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="jitsi-videobridge2",
                unit_name="jitsi-videobridge2.service",
                port=8080,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/jvb/metrics-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["snapshots"] == []

    def test_stats_route_saves_jvb_snapshot(self, app, auth_client):
        """Stats route should persist a JVB metric snapshot."""
        from unittest.mock import patch
        from models import db, Guest, GuestService, ServiceMetricSnapshot
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="jvb-snap", vmid=9996, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="jitsi-videobridge2",
                unit_name="jitsi-videobridge2.service",
                port=8080,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        mock_stats = {
            "type": "jitsi-videobridge2",
            "conferences": 3,
            "participants": 12,
            "stress_level": 0.25,
            "bit_rate_download": 5000,
        }
        with patch("routes.services.get_service_stats", return_value=mock_stats):
            resp = auth_client.get(f"/services/{svc_id}/stats")
            assert resp.status_code == 200

        with app.app_context():
            snap = ServiceMetricSnapshot.query.filter_by(service_id=svc_id).first()
            assert snap is not None
            import json
            d = json.loads(snap.data)
            assert d["conferences"] == 3
            assert d["participants"] == 12

    def test_enable_jvb_rest_api_idempotent(self):
        """_enable_jvb_rest_api should skip if REST API already enabled."""
        from apps.jitsi import _enable_jvb_rest_api
        ssh = MagicMock()
        ssh.execute_sudo.return_value = (
            'videobridge {\n  apis {\n    rest {\n      enabled = true\n    }\n  }\n}',
            "",
            0,
        )
        logs = []
        _enable_jvb_rest_api(ssh, logs.append)
        assert any("SKIP" in msg for msg in logs)
        # Should not have written the file back
        assert ssh.execute_sudo.call_count == 1

    def test_enable_jvb_rest_api_patches_conf(self):
        """_enable_jvb_rest_api should patch jvb.conf when REST not enabled."""
        from apps.jitsi import _enable_jvb_rest_api
        ssh = MagicMock()
        original_conf = 'videobridge {\n  ice {\n    udp {\n      port = 10000\n    }\n  }\n}'
        # First call reads the file, subsequent calls are write + restart
        ssh.execute_sudo.side_effect = [
            (original_conf, "", 0),  # cat
            ("", "", 0),  # tee (write)
            ("", "", 0),  # restart
        ]
        logs = []
        _enable_jvb_rest_api(ssh, logs.append)
        assert any("REST API enabled" in msg for msg in logs)
        # Should have called write (tee) and restart
        assert ssh.execute_sudo.call_count == 3
