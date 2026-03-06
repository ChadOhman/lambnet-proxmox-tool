"""Tests for Elk install/upgrade routes and scheduler integration."""
import sys
from unittest.mock import MagicMock, patch



# ---------------------------------------------------------------------------
# Helpers (mirror test_peertube.py patterns)
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


class TestElkRouteAuth:
    """Elk routes require authentication and can_update permission."""

    def test_upgrade_page_unauthenticated(self, client):
        resp = client.get("/elk/upgrade", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_save_unauthenticated(self, client):
        resp = client.post("/elk/save", follow_redirects=False)
        assert resp.status_code == 302

    def test_check_unauthenticated(self, client):
        resp = client.post("/elk/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_unauthenticated(self, client):
        resp = client.post("/elk/detect-versions", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_unauthenticated(self, client):
        resp = client.post("/elk/preflight", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_post_unauthenticated(self, client):
        resp = client.post("/elk/upgrade", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_unauthenticated(self, client):
        resp = client.post("/elk/install", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_status_unauthenticated(self, client):
        resp = client.get("/elk/upgrade/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_status_unauthenticated(self, client):
        resp = client.get("/elk/preflight/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_status_unauthenticated(self, client):
        resp = client.get("/elk/install/status", follow_redirects=False)
        assert resp.status_code == 302


class TestElkRouteViewer:
    """Viewer users (can_update=False) should be denied access."""

    def test_viewer_denied_upgrade_page(self, app, client):
        from models import db, User, Role

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_elk_test_viewer",
                display_name="Elk Viewer",
                role_id=viewer_role.id,
            )
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        try:
            client.post(
                "/login",
                data={"username": "_elk_test_viewer", "password": "ViewerPass123!"},
                follow_redirects=False,
            )
            resp = client.get("/elk/upgrade", follow_redirects=False)
            assert resp.status_code == 302
            location = resp.headers.get("Location", "")
            assert "/elk" not in location
        finally:
            with app.app_context():
                User.query.filter_by(username="_elk_test_viewer").delete()
                db.session.commit()


class TestElkRouteAuthed:
    """Admin users (can_update=True) can access Elk routes."""

    def test_upgrade_page_loads(self, auth_client):
        resp = auth_client.get("/elk/upgrade")
        assert resp.status_code == 200
        assert b"Elk" in resp.data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/elk/upgrade/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/elk/preflight/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/elk/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_save_persists_settings(self, app, auth_client):
        from models import Setting

        resp = auth_client.post(
            "/elk/save",
            data={
                "elk_guest_id": "77",
                "elk_user": "elkuser",
                "elk_dir": "/opt/elk",
                "elk_url": "https://elk.example.com",
                "elk_instance_url": "https://mastodon.example.com",
                "elk_deploy_method": "docker",
                "elk_current_version": "0.13.1",
                "elk_auto_upgrade": "on",
                "elk_protection_type": "snapshot",
                "elk_backup_storage": "",
                "elk_backup_mode": "snapshot",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("elk_guest_id") == "77"
            assert Setting.get("elk_user") == "elkuser"
            assert Setting.get("elk_dir") == "/opt/elk"
            assert Setting.get("elk_url") == "https://elk.example.com"
            assert Setting.get("elk_instance_url") == "https://mastodon.example.com"
            assert Setting.get("elk_deploy_method") == "docker"
            assert Setting.get("elk_current_version") == "0.13.1"
            assert Setting.get("elk_auto_upgrade") == "true"

    def test_save_defaults_user_and_dir(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/elk/save",
            data={
                "elk_guest_id": "",
                "elk_user": "",
                "elk_dir": "",
                "elk_url": "",
                "elk_instance_url": "",
                "elk_deploy_method": "docker",
                "elk_current_version": "",
                "elk_protection_type": "snapshot",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("elk_user") == "elk"
            assert Setting.get("elk_dir") == "/opt/elk"

    def test_save_validates_protection_type(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/elk/save",
            data={"elk_protection_type": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("elk_protection_type") == "snapshot"

    def test_save_validates_backup_mode(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/elk/save",
            data={
                "elk_backup_mode": "invalid",
                "elk_protection_type": "backup",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("elk_backup_mode") == "snapshot"

    def test_save_validates_deploy_method(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/elk/save",
            data={"elk_deploy_method": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("elk_deploy_method") == "docker"

    def test_save_bare_metal_deploy_method(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/elk/save",
            data={"elk_deploy_method": "bare-metal"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("elk_deploy_method") == "bare-metal"

    def test_check_redirects(self, auth_client):
        resp = auth_client.post("/elk/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_no_guest(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("elk_guest_id", "")
        resp = auth_client.post("/elk/detect-versions", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Applications index
# ---------------------------------------------------------------------------


class TestApplicationsIndexElk:
    """Elk appears on the applications index page."""

    def test_elk_card_present(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"Elk" in resp.data
        assert b"/elk/upgrade" in resp.data


# ---------------------------------------------------------------------------
# Scheduler: _check_elk_release
# ---------------------------------------------------------------------------


class TestCheckElkRelease:
    def test_returns_early_when_no_elk_guest_configured(self):
        from core.scheduler import _check_elk_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_elk = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.elk": mock_elk,
        }
        with _SysModulesPatch(mocks):
            _check_elk_release(app)

        mock_elk.check_elk_release.assert_not_called()

    def test_returns_early_when_not_installed(self):
        from core.scheduler import _check_elk_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "elk_guest_id": "42",
            "elk_installed": "false",
        }.get(k, d)
        mock_elk = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.elk": mock_elk,
        }
        with _SysModulesPatch(mocks):
            _check_elk_release(app)

        mock_elk.check_elk_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from core.scheduler import _check_elk_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "elk_guest_id": "42",
            "elk_installed": "true",
            "elk_current_version": "0.12.0",
            "elk_auto_upgrade": "false",
            "elk_last_notified_version": "",
        }.get(k, d)

        mock_elk = MagicMock()
        mock_elk.check_elk_release.return_value = (True, "0.13.0", "https://example.com")
        mock_notifier = MagicMock()
        mock_notifier.send_elk_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.elk": mock_elk,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_elk_release(app)

        mock_notifier.send_elk_update_notification.assert_called_once_with(
            "0.12.0", "0.13.0", "https://example.com"
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from core.scheduler import _check_elk_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "elk_guest_id": "42",
            "elk_installed": "true",
            "elk_current_version": "0.12.0",
            "elk_auto_upgrade": "false",
            "elk_last_notified_version": "0.13.0",
        }.get(k, d)

        mock_elk = MagicMock()
        mock_elk.check_elk_release.return_value = (True, "0.13.0", "https://example.com")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.elk": mock_elk,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_elk_release(app)

        mock_notifier.send_elk_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from core.scheduler import _check_elk_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "elk_guest_id": "42",
            "elk_installed": "true",
        }.get(k, d)
        mock_elk = MagicMock()
        mock_elk.check_elk_release.return_value = (False, "0.12.0", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.elk": mock_elk,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_elk_release(app)

        mock_notifier.send_elk_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from core.scheduler import _check_elk_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "elk_guest_id": "42",
            "elk_installed": "true",
            "elk_current_version": "0.12.0",
            "elk_auto_upgrade": "true",
            "elk_last_notified_version": "",
        }.get(k, d)

        mock_elk = MagicMock()
        mock_elk.check_elk_release.return_value = (True, "0.13.0", "https://example.com")
        mock_elk.run_elk_upgrade.return_value = (True, "")
        mock_notifier = MagicMock()
        mock_notifier.send_elk_update_notification.return_value = (True, "ok")
        mock_audit = MagicMock()
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=mock_db),
            "apps.elk": mock_elk,
            "core.notifier": mock_notifier,
            "auth.audit": mock_audit,
        }
        with _SysModulesPatch(mocks):
            _check_elk_release(app)

        mock_elk.run_elk_upgrade.assert_called_once()


# ---------------------------------------------------------------------------
# Notifier
# ---------------------------------------------------------------------------


class TestElkNotifier:
    """Elk notification functions exist and follow patterns."""

    def test_send_elk_update_notification_exists(self):
        from core.notifier import send_elk_update_notification
        assert callable(send_elk_update_notification)

    def test_upgrade_started_supports_elk(self, app):
        with app.app_context():
            from core.notifier import send_upgrade_started_notification
            ok, msg = send_upgrade_started_notification("elk", "0.13.0", "manual")
            assert isinstance(ok, bool)

    def test_upgrade_result_supports_elk(self, app):
        with app.app_context():
            from core.notifier import send_upgrade_result_notification
            ok, msg = send_upgrade_result_notification("elk", "0.13.0", True, "manual")
            assert isinstance(ok, bool)


# ---------------------------------------------------------------------------
# Version check (unit)
# ---------------------------------------------------------------------------


class TestCheckElkReleaseUnit:
    """Unit tests for elk.check_elk_release()."""

    def test_returns_false_on_network_error(self, app):
        with app.app_context():
            with patch("apps.elk.urlopen", side_effect=Exception("timeout")):
                from apps.elk import check_elk_release
                update, version, url = check_elk_release()
                assert update is False
                assert version == ""

    def test_parses_github_release(self, app):
        import json
        fake_data = json.dumps({
            "tag_name": "v0.13.1",
            "html_url": "https://github.com/elk-zone/elk/releases/tag/v0.13.1",
        }).encode()

        from unittest.mock import MagicMock as MM
        fake_resp = MM()
        fake_resp.read.return_value = fake_data
        fake_resp.__enter__ = lambda s: s
        fake_resp.__exit__ = MM(return_value=False)

        with app.app_context():
            from models import Setting
            Setting.set("elk_current_version", "0.12.0")
            from models import db
            db.session.commit()

            with patch("apps.elk.urlopen", return_value=fake_resp):
                from apps.elk import check_elk_release
                update, version, url = check_elk_release()
                assert update is True
                assert version == "0.13.1"
                assert "v0.13.1" in url
