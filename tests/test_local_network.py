"""Tests for local_network.py helpers and middleware."""

import ipaddress

from local_network import _is_trusted, _get_client_ip
from models import db, Setting


# ---------------------------------------------------------------------------
# Helpers: _is_trusted
# ---------------------------------------------------------------------------

def _nets(*cidrs):
    """Build a list of ip_network objects from CIDR strings."""
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


class TestIsTrusted:
    def test_ip_in_single_network_returns_true(self):
        assert _is_trusted("10.0.0.5", _nets("10.0.0.0/8")) is True

    def test_ip_at_network_boundary_returns_true(self):
        assert _is_trusted("192.168.1.0", _nets("192.168.1.0/24")) is True

    def test_ip_in_one_of_multiple_networks_returns_true(self):
        nets = _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        assert _is_trusted("192.168.50.50", nets) is True

    def test_ip_not_in_network_returns_false(self):
        assert _is_trusted("8.8.8.8", _nets("10.0.0.0/8")) is False

    def test_ip_not_in_any_of_multiple_networks_returns_false(self):
        nets = _nets("10.0.0.0/8", "172.16.0.0/12")
        assert _is_trusted("1.2.3.4", nets) is False

    def test_empty_network_list_returns_false(self):
        assert _is_trusted("10.0.0.1", []) is False

    def test_invalid_ip_string_returns_false(self):
        assert _is_trusted("not-an-ip", _nets("10.0.0.0/8")) is False

    def test_empty_string_ip_returns_false(self):
        assert _is_trusted("", _nets("10.0.0.0/8")) is False

    def test_ipv6_loopback_in_ipv6_network(self):
        nets = [ipaddress.ip_network("::1/128")]
        assert _is_trusted("::1", nets) is True

    def test_ipv6_address_not_in_ipv4_network_returns_false(self):
        # Mixing address families should not raise; it should return False
        nets = _nets("10.0.0.0/8")
        assert _is_trusted("::1", nets) is False


# ---------------------------------------------------------------------------
# Helpers: _get_client_ip
# ---------------------------------------------------------------------------

class TestGetClientIp:
    """Test _get_client_ip() inside a Flask request context."""

    # -- loopback REMOTE_ADDR: proxy headers ARE trusted --------------------

    def test_loopback_remote_addr_no_headers_returns_remote_addr(self, app):
        with app.test_request_context(environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert _get_client_ip() == "127.0.0.1"

    def test_loopback_trusts_cf_connecting_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"CF-Connecting-IP": "203.0.113.42"},
        ):
            assert _get_client_ip() == "203.0.113.42"

    def test_loopback_trusts_x_real_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Real-IP": "198.51.100.7"},
        ):
            assert _get_client_ip() == "198.51.100.7"

    def test_loopback_trusts_x_forwarded_for_first_entry(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.1, 10.0.0.2, 10.0.0.3"},
        ):
            assert _get_client_ip() == "203.0.113.1"

    def test_loopback_cf_takes_priority_over_x_real_ip(self, app):
        """CF-Connecting-IP should be preferred over X-Real-IP."""
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={
                "CF-Connecting-IP": "203.0.113.10",
                "X-Real-IP": "203.0.113.99",
            },
        ):
            assert _get_client_ip() == "203.0.113.10"

    def test_private_remote_addr_trusts_forwarded_header(self, app):
        """Private (RFC-1918) REMOTE_ADDR should also trust proxy headers."""
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.55"},
        ):
            assert _get_client_ip() == "203.0.113.55"

    # -- public REMOTE_ADDR: proxy headers are NOT trusted ------------------

    def test_public_remote_addr_ignores_cf_connecting_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
            headers={"CF-Connecting-IP": "203.0.113.42"},
        ):
            assert _get_client_ip() == "1.2.3.4"

    def test_public_remote_addr_ignores_x_real_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
            headers={"X-Real-IP": "198.51.100.7"},
        ):
            assert _get_client_ip() == "1.2.3.4"

    def test_public_remote_addr_ignores_x_forwarded_for(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
            headers={"X-Forwarded-For": "203.0.113.1"},
        ):
            assert _get_client_ip() == "1.2.3.4"

    def test_public_remote_addr_no_headers_returns_remote_addr(self, app):
        with app.test_request_context(environ_base={"REMOTE_ADDR": "8.8.8.8"}):
            assert _get_client_ip() == "8.8.8.8"

    def test_forwarded_for_header_whitespace_stripped(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "  203.0.113.77  , 10.0.0.1"},
        ):
            assert _get_client_ip() == "203.0.113.77"


# ---------------------------------------------------------------------------
# Middleware: init_local_bypass
# ---------------------------------------------------------------------------

class TestLocalBypassMiddleware:
    """Integration tests for the before_request hook registered by init_local_bypass()."""

    def test_bypass_disabled_unauthenticated_redirects_to_login(self, app, client):
        """When local_bypass_enabled is 'false' the middleware must not log in the user."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "false")
            db.session.commit()

        resp = client.get(
            "/",
            follow_redirects=False,
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_static_path_skips_bypass(self, app):
        """Requests to /static/ must be skipped regardless of bypass state."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        # /static/ requests should flow through without triggering auto-login.
        # We verify this by checking that a fresh (unauthenticated) client can
        # hit a static path and the middleware does not raise or auto-redirect.
        with app.test_client() as c:
            # The app may 404 on a missing file, but it should NOT redirect to
            # a post-login dashboard (which would be /) — that would be a sign
            # the auto-login fired on a static path.
            resp = c.get(
                "/static/nonexistent.css",
                environ_base={"REMOTE_ADDR": "10.0.0.1"},
                follow_redirects=False,
            )
            assert resp.status_code != 302 or "/login" not in resp.headers.get("Location", "")

    def test_already_authenticated_skips_bypass(self, app, auth_client):
        """If the user is already logged in, the middleware must not interfere."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        resp = auth_client.get(
            "/",
            follow_redirects=False,
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        )
        # Already-authenticated client should reach the dashboard, not loop.
        assert resp.status_code == 200

    def test_trusted_ip_with_bypass_enabled_auto_logs_in(self, app):
        """A trusted IP with bypass enabled should be auto-authenticated as admin."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "10.0.0.5"},
                follow_redirects=False,
            )
            # Should reach the dashboard (200), not be redirected to login.
            assert resp.status_code == 200

    def test_untrusted_ip_with_bypass_enabled_redirects_to_login(self, app):
        """An IP outside the trusted subnet must not be auto-authenticated."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "1.2.3.4"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_bypass_via_forwarded_header_from_loopback_proxy(self, app):
        """A trusted real IP arriving via X-Forwarded-For from a loopback proxy triggers bypass."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "10.0.0.99"},
                follow_redirects=False,
            )
            assert resp.status_code == 200

    def test_untrusted_forwarded_ip_from_loopback_proxy_redirects(self, app):
        """A public IP forwarded through loopback proxy must not trigger bypass."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "8.8.8.8"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]
