"""Tests for guest list route and status filters."""
import pytest
from datetime import datetime, timezone
from models import db, Guest, UpdatePackage

_NOW = datetime.now(timezone.utc)


@pytest.fixture()
def filter_guests(app):
    """Seed a set of guests covering every filter case, clean up after."""
    ids = []
    with app.app_context():
        guests = [
            Guest(name="_filter-updates", guest_type="ct", status="updates-available", last_scan=_NOW),
            Guest(name="_filter-error", guest_type="ct", status="error", last_scan=_NOW),
            Guest(name="_filter-reboot", guest_type="ct", status="up-to-date", reboot_required=True, last_scan=_NOW),
            Guest(name="_filter-uptodate", guest_type="ct", status="up-to-date", last_scan=_NOW),
            Guest(name="_filter-never-scanned", guest_type="ct"),  # last_scan stays None
        ]
        for g in guests:
            db.session.add(g)
        db.session.flush()

        # Add a critical-severity pending package to the updates guest so
        # ?filter=security also matches it.
        sec_guest = next(g for g in guests if g.name == "_filter-updates")
        db.session.add(UpdatePackage(
            guest_id=sec_guest.id,
            package_name="libc6",
            severity="critical",
            status="pending",
        ))
        db.session.commit()
        ids = [g.id for g in guests]

    yield

    with app.app_context():
        for gid in ids:
            g = Guest.query.get(gid)
            if g:
                db.session.delete(g)
        db.session.commit()


class TestGuestList:
    def test_guest_list_returns_200(self, auth_client):
        resp = auth_client.get("/guests/")
        assert resp.status_code == 200

    def test_guest_list_unauthenticated_redirects(self, client):
        resp = client.get("/guests/", follow_redirects=False)
        assert resp.status_code == 302

    def test_unknown_filter_shows_all(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=bogus_value")
        assert resp.status_code == 200

    def test_filter_updates(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=updates")
        assert resp.status_code == 200
        assert b"_filter-updates" in resp.data
        assert b"_filter-uptodate" not in resp.data
        assert b"_filter-never-scanned" not in resp.data

    def test_filter_security(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=security")
        assert resp.status_code == 200
        assert b"_filter-updates" in resp.data
        assert b"_filter-uptodate" not in resp.data

    def test_filter_reboot(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=reboot")
        assert resp.status_code == 200
        assert b"_filter-reboot" in resp.data
        assert b"_filter-uptodate" not in resp.data

    def test_filter_never_scanned(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=never_scanned")
        assert resp.status_code == 200
        assert b"_filter-never-scanned" in resp.data
        assert b"_filter-updates" not in resp.data

    def test_filter_error(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=error")
        assert resp.status_code == 200
        assert b"_filter-error" in resp.data
        assert b"_filter-uptodate" not in resp.data

    def test_filter_up_to_date(self, auth_client, filter_guests):
        resp = auth_client.get("/guests/?filter=up_to_date")
        assert resp.status_code == 200
        assert b"_filter-uptodate" in resp.data
        assert b"_filter-updates" not in resp.data

    def test_active_filter_badge_shown(self, auth_client, filter_guests):
        """When a filter is active, the template shows the filter label."""
        resp = auth_client.get("/guests/?filter=updates")
        assert b"Pending Updates" in resp.data
        # There should be a way to clear the filter (link back to /guests/)
        assert b"/guests/" in resp.data
