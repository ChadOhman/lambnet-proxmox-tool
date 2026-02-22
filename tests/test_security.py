"""Tests for security helpers and the local-bypass migration notice."""
import pytest
from models import db, Setting


# Import helpers directly from the routes module
from routes.security import _safe_int, _safe_int_list


class TestSafeInt:
    def test_valid_integer_string(self):
        assert _safe_int("42") == 42

    def test_zero(self):
        assert _safe_int("0") == 0

    def test_negative(self):
        assert _safe_int("-5") == -5

    def test_non_numeric_returns_none(self):
        assert _safe_int("abc") is None

    def test_empty_string_returns_none(self):
        assert _safe_int("") is None

    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_float_string_returns_none(self):
        assert _safe_int("3.14") is None


class TestSafeIntList:
    def test_valid_list(self):
        assert _safe_int_list(["1", "2", "3"]) == [1, 2, 3]

    def test_empty_list(self):
        assert _safe_int_list([]) == []

    def test_one_invalid_returns_none(self):
        assert _safe_int_list(["1", "bad", "3"]) is None

    def test_all_invalid_returns_none(self):
        assert _safe_int_list(["x", "y"]) is None


class TestLocalBypassNotice:
    def test_notice_shown_when_setting_absent(self, app, auth_client):
        """Warning banner appears when local_bypass_enabled has never been saved."""
        with app.app_context():
            existing = Setting.query.filter_by(key="local_bypass_enabled").first()
            if existing:
                db.session.delete(existing)
                db.session.commit()

        resp = auth_client.get("/security/")
        assert resp.status_code == 200
        assert b"Default changed" in resp.data

    def test_notice_hidden_when_setting_present(self, app, auth_client):
        """Warning banner is absent once the setting has been explicitly saved."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "false")

        resp = auth_client.get("/security/")
        assert resp.status_code == 200
        assert b"Default changed" not in resp.data

    def test_dismiss_notice_sets_setting(self, app, auth_client):
        """POSTing to dismiss endpoint explicitly saves the setting."""
        with app.app_context():
            existing = Setting.query.filter_by(key="local_bypass_enabled").first()
            if existing:
                db.session.delete(existing)
                db.session.commit()

        resp = auth_client.post(
            "/security/access/dismiss-bypass-notice",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.query.filter_by(key="local_bypass_enabled").first() is not None
