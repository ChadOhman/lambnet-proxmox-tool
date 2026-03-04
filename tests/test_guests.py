"""Tests for guest list route and status filters."""
import json
import pytest
from datetime import datetime, timezone
from models import db, Guest, Tag, Setting, UpdatePackage

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


class TestGetTagBackupDefaults:
    """Tests for _get_tag_backup_defaults helper in routes/guests.py."""

    def test_returns_empty_when_no_setting(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            guest = Guest(name="test-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()
            assert _get_tag_backup_defaults(guest) == {}

    def test_returns_override_for_matching_tag(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            tag = Tag(name="production", color="#ff0000")
            guest = Guest(name="prod-guest", guest_type="ct")
            guest.tags.append(tag)
            db.session.add_all([tag, guest])
            db.session.commit()

            overrides = {"production": {"storage": "pbs-prod", "mode": "snapshot"}}
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            result = _get_tag_backup_defaults(guest)
            assert result["storage"] == "pbs-prod"
            assert result["mode"] == "snapshot"

    def test_returns_first_matching_tag(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            tag1 = Tag(name="alpha", color="#aaa")
            tag2 = Tag(name="beta", color="#bbb")
            guest = Guest(name="multi-tag-guest", guest_type="ct")
            guest.tags.extend([tag1, tag2])
            db.session.add_all([tag1, tag2, guest])
            db.session.commit()

            overrides = {
                "alpha": {"storage": "storage-a"},
                "beta": {"storage": "storage-b"},
            }
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            result = _get_tag_backup_defaults(guest)
            assert result["storage"] == "storage-a"

    def test_returns_empty_when_no_tag_matches(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            tag = Tag(name="staging", color="#ccc")
            guest = Guest(name="staging-guest", guest_type="ct")
            guest.tags.append(tag)
            db.session.add_all([tag, guest])
            db.session.commit()

            overrides = {"production": {"storage": "pbs-prod"}}
            Setting.set("backup_tag_defaults", json.dumps(overrides))

            assert _get_tag_backup_defaults(guest) == {}

    def test_handles_invalid_json(self, app):
        from routes.guests import _get_tag_backup_defaults
        with app.app_context():
            guest = Guest(name="bad-json-guest", guest_type="ct")
            db.session.add(guest)
            db.session.commit()

            Setting.set("backup_tag_defaults", "not-valid-json{")
            assert _get_tag_backup_defaults(guest) == {}
