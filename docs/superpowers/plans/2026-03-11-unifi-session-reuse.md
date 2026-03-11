# UniFi Client Session Reuse Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cache a single `UniFiClient` instance to reuse its `requests.Session` (and auth cookies) across scheduler jobs and route handlers, eliminating redundant logins that trigger HTTP 429 rate limits.

**Architecture:** Add a `get_cached_client()` function to `clients/unifi_client.py` that returns a module-level cached `UniFiClient`. The cache is keyed by a hash of connection settings; when settings change, the old client is discarded and a new one is created. API methods gain 401-retry logic to handle expired sessions. All call sites switch to this function.

**Tech Stack:** Python 3.13, requests, threading, hashlib

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `clients/unifi_client.py` | Modify | Add `get_cached_client()`, 401-retry in `_api_get`/`_api_post`/`_api_post_data`, `invalidate_cached_client()` |
| `routes/unifi.py` | Modify | Replace `_get_unifi_client()` body to call `get_cached_client()` |
| `core/scheduler.py` | Modify | Replace inline `UniFiClient(...)` construction with `get_cached_client()` |
| `routes/settings.py` | Modify | Call `invalidate_cached_client()` after saving UniFi settings |
| `tests/test_unifi_client.py` | Modify | Add tests for caching, invalidation, and 401-retry |

---

## Task 1: Add cached client factory to `clients/unifi_client.py`

**Files:**
- Modify: `clients/unifi_client.py:1-7` (imports), append new functions after class
- Test: `tests/test_unifi_client.py`

- [ ] **Step 1: Write failing tests for `get_cached_client()`**

Add to `tests/test_unifi_client.py`:

```python
class TestCachedClient:
    """Tests for the module-level cached UniFi client."""

    def setup_method(self):
        """Clear cache before each test."""
        from clients import unifi_client
        unifi_client._cached_client = None
        unifi_client._cached_settings_hash = None

    def test_returns_client_instance(self):
        from clients.unifi_client import get_cached_client
        c = get_cached_client("https://example.com", "user", "pass")
        assert isinstance(c, UniFiClient)
        assert c.base_url == "https://example.com"

    def test_returns_same_instance_on_repeat_call(self):
        from clients.unifi_client import get_cached_client
        c1 = get_cached_client("https://example.com", "user", "pass")
        c2 = get_cached_client("https://example.com", "user", "pass")
        assert c1 is c2

    def test_returns_new_instance_when_settings_change(self):
        from clients.unifi_client import get_cached_client
        c1 = get_cached_client("https://example.com", "user", "pass")
        c2 = get_cached_client("https://example.com", "user", "newpass")
        assert c1 is not c2

    def test_invalidate_clears_cache(self):
        from clients.unifi_client import get_cached_client, invalidate_cached_client
        c1 = get_cached_client("https://example.com", "user", "pass")
        invalidate_cached_client()
        c2 = get_cached_client("https://example.com", "user", "pass")
        assert c1 is not c2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_unifi_client.py::TestCachedClient -v`
Expected: ImportError — `get_cached_client` does not exist

- [ ] **Step 3: Implement `get_cached_client()` and `invalidate_cached_client()`**

Add to `clients/unifi_client.py` — new imports at top:

```python
import hashlib
import threading
```

Add after the `UniFiClient` class (after all methods):

```python
_cached_client: "UniFiClient | None" = None
_cached_settings_hash: "str | None" = None
_client_lock = threading.Lock()


def _settings_hash(base_url, username, password, site, is_udm, verify_ssl):
    """Compute a hash of connection settings to detect changes."""
    key = f"{base_url}\0{username}\0{password}\0{site}\0{is_udm}\0{verify_ssl}"
    return hashlib.sha256(key.encode()).hexdigest()


def get_cached_client(base_url, username, password, site="default", is_udm=True, verify_ssl=False):
    """Return a cached UniFiClient, creating a new one if settings changed."""
    global _cached_client, _cached_settings_hash
    h = _settings_hash(base_url, username, password, site, is_udm, verify_ssl)
    if _cached_client is not None and _cached_settings_hash == h:
        return _cached_client
    with _client_lock:
        # Double-check after acquiring lock
        if _cached_client is not None and _cached_settings_hash == h:
            return _cached_client
        _cached_client = UniFiClient(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
        _cached_settings_hash = h
        return _cached_client


def invalidate_cached_client():
    """Discard the cached client (e.g. after settings change)."""
    global _cached_client, _cached_settings_hash
    with _client_lock:
        _cached_client = None
        _cached_settings_hash = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_unifi_client.py -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add clients/unifi_client.py tests/test_unifi_client.py
git commit -m "Add cached UniFi client factory with settings-hash invalidation"
```

---

## Task 2: Add 401-retry logic to API methods

**Files:**
- Modify: `clients/unifi_client.py:66-104` (`_api_get`, `_api_post`, `_api_post_data`)
- Test: `tests/test_unifi_client.py`

- [ ] **Step 1: Write failing test for 401 retry**

Add to `tests/test_unifi_client.py`:

```python
class TestSessionExpiry:
    """Test that API methods retry login on 401."""

    def _make_client(self):
        c = UniFiClient("https://example.com", "user", "pass")
        c._logged_in = True
        return c

    @patch.object(UniFiClient, "login", return_value=True)
    @patch("clients.unifi_client.requests.Session.get")
    def test_api_get_retries_on_401(self, mock_get, mock_login):
        c = self._make_client()
        # First call returns 401, second returns 200
        resp_401 = MagicMock(status_code=401)
        resp_200 = MagicMock(status_code=200)
        resp_200.json.return_value = {"data": [{"id": 1}]}
        mock_get.side_effect = [resp_401, resp_200]
        result = c._api_get("/test")
        assert result == [{"id": 1}]
        assert mock_login.called

    @patch.object(UniFiClient, "login", return_value=True)
    @patch("clients.unifi_client.requests.Session.get")
    def test_api_get_fails_after_retry_login_fails(self, mock_get, mock_login):
        c = self._make_client()
        mock_login.return_value = False
        resp_401 = MagicMock(status_code=401)
        mock_get.return_value = resp_401
        result = c._api_get("/test")
        assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_unifi_client.py::TestSessionExpiry -v`
Expected: FAIL — 401 is not retried, returns None on first try

- [ ] **Step 3: Add 401-retry to `_api_get`**

Replace `_api_get` in `clients/unifi_client.py`:

```python
    def _api_get(self, path):
        if not self._logged_in:
            if not self.login():
                return None
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 401:
                self._logged_in = False
                if not self.login():
                    return None
                resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", [])
            logger.warning("UniFi API GET %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("UniFi API error: %s", e)
            return None
```

Apply same pattern to `_api_post`:

```python
    def _api_post(self, path, payload):
        if not self._logged_in:
            if not self.login():
                return False, "Not authenticated"
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 401:
                self._logged_in = False
                if not self.login():
                    return False, "Not authenticated"
                resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return True, "OK"
            return False, f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            return False, str(e)
```

Apply same pattern to `_api_post_data`:

```python
    def _api_post_data(self, path, payload):
        """POST that returns the JSON ``data`` array (like ``_api_get``)."""
        if not self._logged_in:
            if not self.login():
                return None
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 401:
                self._logged_in = False
                if not self.login():
                    return None
                resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", [])
            logger.warning("UniFi API POST %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("UniFi API error: %s", e)
            return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_unifi_client.py -v`
Expected: All pass

- [ ] **Step 5: Lint check**

Run: `python -m ruff check clients/unifi_client.py`
Expected: All checks passed

- [ ] **Step 6: Commit**

```bash
git add clients/unifi_client.py tests/test_unifi_client.py
git commit -m "Add 401-retry logic to UniFi API methods for session expiry"
```

---

## Task 3: Switch all call sites to use `get_cached_client()`

**Files:**
- Modify: `routes/unifi.py:29-47`
- Modify: `core/scheduler.py:604-621, 856-867`
- Modify: `routes/settings.py:342-348`
- Test: `tests/test_settings.py`

- [ ] **Step 1: Update `routes/unifi.py::_get_unifi_client()`**

Replace the body of `_get_unifi_client()` (lines 29-47):

```python
def _get_unifi_client():
    """Return a cached UniFi client from saved settings."""
    from clients.unifi_client import get_cached_client

    base_url = Setting.get("unifi_base_url", "")
    username = Setting.get("unifi_username", "")
    encrypted_pw = Setting.get("unifi_password", "")
    site = Setting.get("unifi_site", "default")
    is_udm = Setting.get("unifi_is_udm", "true") == "true"
    verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"

    if not base_url or not username or not encrypted_pw:
        return None

    password = decrypt(encrypted_pw)
    if not password:
        return None

    return get_cached_client(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
```

- [ ] **Step 2: Update `core/scheduler.py::_poll_unifi_events()`**

Replace lines 604-621 (the import + client construction block) with:

```python
        from clients.unifi_client import get_cached_client

        base_url = Setting.get("unifi_base_url", "")
        username = Setting.get("unifi_username", "")
        encrypted_pw = Setting.get("unifi_password", "")
        site = Setting.get("unifi_site", "default")
        is_udm = Setting.get("unifi_is_udm", "true") == "true"
        verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"

        if not base_url or not username or not encrypted_pw:
            return

        password = decrypt(encrypted_pw)
        if not password:
            return

        client = get_cached_client(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
```

- [ ] **Step 3: Update `core/scheduler.py::_collect_prometheus_metrics()`**

Replace lines 856-867 (the `UniFiClient` import + construction block) with:

```python
                from clients.unifi_client import get_cached_client

                base_url = Setting.get("unifi_base_url", "")
                username = Setting.get("unifi_username", "")
                encrypted_pw = Setting.get("unifi_password", "")
                site = Setting.get("unifi_site", "default")
                is_udm = Setting.get("unifi_is_udm", "true") == "true"
                verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"
                if base_url and username and encrypted_pw:
                    password = decrypt(encrypted_pw)
                    if password:
                        uc = get_cached_client(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
```

- [ ] **Step 4: Invalidate cache on settings save in `routes/settings.py`**

In `save_unifi()`, add after `Setting.set("unifi_verify_ssl", ...)` and before `log_action(...)`:

```python
    from clients.unifi_client import invalidate_cached_client
    invalidate_cached_client()
```

- [ ] **Step 5: Run full test suite**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/ -v --tb=short`
Expected: All 1168+ tests pass

- [ ] **Step 6: Lint check**

Run: `python -m ruff check routes/unifi.py core/scheduler.py routes/settings.py`
Expected: All checks passed

- [ ] **Step 7: Commit**

```bash
git add routes/unifi.py core/scheduler.py routes/settings.py
git commit -m "Switch all UniFi call sites to cached client factory"
```

---

## Verification

1. **Unit tests:** `python -m pytest tests/test_unifi_client.py tests/test_settings.py -v` — all pass
2. **Full suite:** `python -m pytest tests/ -v --cov-fail-under=40` — all pass, coverage >= 40%
3. **Lint:** `python -m ruff check .` — clean
4. **Manual:** After deploy, check that the UniFi settings page "Test Connection" works, and that the app logs show only one `UniFi login` per session rather than one per minute
