"""Unit tests for model helpers."""
import pytest
from models import db, Guest, UpdatePackage, Setting


@pytest.fixture()
def guest_with_updates(app):
    """Guest with a mix of pending and applied packages, one of which is critical."""
    with app.app_context():
        g = Guest(name="_test-model-guest", guest_type="ct")
        db.session.add(g)
        db.session.flush()

        pkgs = [
            UpdatePackage(guest_id=g.id, package_name="pkg-normal-pending",
                          severity="normal", status="pending"),
            UpdatePackage(guest_id=g.id, package_name="pkg-critical-pending",
                          severity="critical", status="pending"),
            UpdatePackage(guest_id=g.id, package_name="pkg-normal-applied",
                          severity="normal", status="applied"),
        ]
        db.session.add_all(pkgs)
        db.session.commit()
        gid = g.id

    yield gid

    with app.app_context():
        g = Guest.query.get(gid)
        if g:
            db.session.delete(g)
            db.session.commit()


class TestGuestHelpers:
    def test_pending_updates_count(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert len(g.pending_updates()) == 2

    def test_pending_updates_excludes_applied(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert all(u.status == "pending" for u in g.pending_updates())

    def test_security_updates_count(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert len(g.security_updates()) == 1

    def test_security_updates_are_critical(self, app, guest_with_updates):
        with app.app_context():
            g = Guest.query.get(guest_with_updates)
            assert all(u.severity == "critical" for u in g.security_updates())

    def test_no_updates(self, app):
        with app.app_context():
            g = Guest(name="_test-empty-guest", guest_type="vm")
            db.session.add(g)
            db.session.commit()
            assert g.pending_updates() == []
            assert g.security_updates() == []
            db.session.delete(g)
            db.session.commit()


class TestSettingModel:
    def test_get_returns_default_when_absent(self, app):
        with app.app_context():
            val = Setting.get("_nonexistent_key_xyz_", "mydefault")
            assert val == "mydefault"

    def test_get_returns_none_default_when_absent(self, app):
        with app.app_context():
            val = Setting.get("_nonexistent_key_xyz_")
            assert val is None

    def test_set_and_get(self, app):
        with app.app_context():
            Setting.set("_test_key_", "hello")
            assert Setting.get("_test_key_") == "hello"
            s = Setting.query.filter_by(key="_test_key_").first()
            db.session.delete(s)
            db.session.commit()

    def test_set_overwrites(self, app):
        with app.app_context():
            Setting.set("_test_overwrite_", "first")
            Setting.set("_test_overwrite_", "second")
            assert Setting.get("_test_overwrite_") == "second"
            s = Setting.query.filter_by(key="_test_overwrite_").first()
            db.session.delete(s)
            db.session.commit()
