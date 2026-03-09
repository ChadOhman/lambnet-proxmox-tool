"""Tests for the dashboard route."""

from models import Guest, db


class TestDashboard:
    def test_dashboard_authenticated_returns_200(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200

    def test_dashboard_contains_stat_cards(self, auth_client):
        resp = auth_client.get("/")
        assert b"Proxmox Hosts" in resp.data
        assert b"Pending Updates" in resp.data
        assert b"Security Updates" in resp.data
        assert b"Reboots Required" in resp.data

    def test_dashboard_cards_have_filter_links(self, app, auth_client):
        """Dashboard stat cards should link to filtered guest views."""
        with app.app_context():
            g = Guest(name="test-vm", guest_type="vm", last_scan=None)
            db.session.add(g)
            db.session.commit()
        try:
            resp = auth_client.get("/")
            assert b"filter=updates" in resp.data
            assert b"filter=security" in resp.data
            assert b"filter=reboot" in resp.data
            assert b"filter=never_scanned" in resp.data
        finally:
            with app.app_context():
                Guest.query.filter_by(name="test-vm").delete()
                db.session.commit()

    def test_dashboard_unauthenticated_redirects(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
