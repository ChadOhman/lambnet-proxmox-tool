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
        from scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_jitsi = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "jitsi": mock_jitsi,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.check_jitsi_release.assert_not_called()

    def test_returns_early_when_not_installed(self):
        from scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "false",
        }.get(k, d)
        mock_jitsi = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "jitsi": mock_jitsi,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.check_jitsi_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from scheduler import _check_jitsi_release

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
            "jitsi": mock_jitsi,
            "notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_called_once_with(
            "2.0.9400", "2.0.9500", ""
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from scheduler import _check_jitsi_release

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
            "jitsi": mock_jitsi,
            "notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from scheduler import _check_jitsi_release

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
            "jitsi": mock_jitsi,
            "notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from scheduler import _check_jitsi_release

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
            "jitsi": mock_jitsi,
            "notifier": mock_notifier,
            "audit": mock_audit,
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
        from notifier import send_jitsi_update_notification
        assert callable(send_jitsi_update_notification)

    def test_upgrade_started_supports_jitsi(self, app):
        with app.app_context():
            from notifier import send_upgrade_started_notification
            ok, msg = send_upgrade_started_notification("jitsi", "2.0.9500", "manual")
            assert isinstance(ok, bool)

    def test_upgrade_result_supports_jitsi(self, app):
        with app.app_context():
            from notifier import send_upgrade_result_notification
            ok, msg = send_upgrade_result_notification("jitsi", "2.0.9500", True, "manual")
            assert isinstance(ok, bool)
