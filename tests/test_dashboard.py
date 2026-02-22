"""Tests for the dashboard route."""


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

    def test_dashboard_cards_have_filter_links(self, auth_client):
        """Dashboard stat cards should link to filtered guest views."""
        resp = auth_client.get("/")
        assert b"filter=updates" in resp.data
        assert b"filter=security" in resp.data
        assert b"filter=reboot" in resp.data
        assert b"filter=never_scanned" in resp.data

    def test_dashboard_unauthenticated_redirects(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
