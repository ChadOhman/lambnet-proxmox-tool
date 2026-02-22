"""Tests for auth routes and CSRF origin middleware."""
import pytest


class TestLogin:
    def test_get_login_page(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"login" in resp.data.lower()

    def test_valid_credentials_redirect(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_invalid_credentials_stays_on_login(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword"},
            follow_redirects=False,
        )
        # Either stays on login (200) or redirects back to login (302 to /login)
        assert resp.status_code in (200, 302)
        if resp.status_code == 302:
            assert "/login" in resp.headers.get("Location", "")

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestLogout:
    def test_get_logout_returns_405(self, auth_client):
        """Logout must be POST-only (PR #4)."""
        resp = auth_client.get("/logout")
        assert resp.status_code == 405

    def test_post_logout_succeeds(self, auth_client):
        resp = auth_client.post("/logout", follow_redirects=False)
        assert resp.status_code in (200, 302)


class TestCsrfOriginCheck:
    def test_post_without_origin_is_allowed(self, client):
        """Non-browser clients (no Origin/Referer) must not be blocked."""
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
        )
        # Should process the request (200 or redirect), not 403
        assert resp.status_code != 403

    def test_post_with_matching_origin_is_allowed(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
            headers={"Origin": "http://localhost"},
        )
        assert resp.status_code != 403

    def test_post_with_mismatched_origin_is_blocked(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 403
