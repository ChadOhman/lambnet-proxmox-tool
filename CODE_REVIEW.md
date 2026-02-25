# Code Review Findings

## Review 1 — 2026-02-22

### 1) Missing CSRF protection across state-changing forms (High)
- The Flask app initializes auth/session middleware but does not initialize CSRF protection middleware (for example, `flask_wtf.CSRFProtect`).
- Multiple privileged actions are handled via POST forms in templates without CSRF tokens.
- Impact: an authenticated admin user could be tricked into submitting a forged request that changes security settings, deletes users, or performs other state-changing actions.

Examples:
- `app.py` does not initialize any CSRF protection.
- `templates/security.html` contains privileged POST forms (for role and tag deletion) without CSRF fields.

**Mitigation in place:** `app.py` has an origin/referer check (`_csrf_origin_check`) that blocks cross-origin POSTs. This is not a full CSRF token implementation but provides meaningful protection for browser-based flows. Requests without any Origin/Referer header are still allowed (for API clients). Consider Flask-WTF tokens for the highest-value forms.

### 2) Logout endpoint uses GET instead of POST (Medium) — RESOLVED
- Fixed: `/logout` is now POST-only (`routes/auth.py`).

### 3) Unhandled form parsing errors can trigger 500 responses (Medium) — RESOLVED
- Fixed: `routes/security.py`, `routes/hosts.py`, `routes/guests.py` — unguarded `int()` conversions
  are now wrapped in try/except with user-facing validation messages.

### 4) Default local-network bypass auto-authenticates as admin (Medium)
- Local bypass defaults to enabled and trusted subnet default is `10.0.0.0/8`.
- Requests from trusted networks are auto-authenticated as the `admin` account.
- Impact: broad private addressing defaults may be too permissive in shared/internal networks and can lead to unintended administrative access.

Recommendation:
- Default this feature to disabled, or require explicit setup of narrow trusted CIDRs.
- Consider creating a dedicated low-privilege local bypass role instead of automatic admin login.

---

## Review 2 — 2026-02-25

### 5) No Content-Security-Policy (CSP) header — RESOLVED
- **File:** `app.py` (`_security_headers`)
- Added a CSP header allowing `'self'` for most resource types, `'unsafe-inline'` for scripts and
  styles (required for current inline JS/CSS usage), WebSocket connections via `ws:/wss:`, and
  blocking `object-src` and restricting `base-uri`. Inline scripts should be migrated to nonces
  or external files to enable a stricter policy in the future.

### 6) SESSION_COOKIE_SECURE not set — RESOLVED
- **File:** `config.py`
- Added `SESSION_COOKIE_SECURE = os.environ.get("FLASK_DEBUG", "0") != "1"` so session cookies
  are only sent over HTTPS in production.

### 7) Plaintext ad-hoc SSH credentials stored in session — RESOLVED
- **File:** `routes/terminal.py` (`connect_adhoc`, `_ws_primary`)
- Ad-hoc terminal passwords are now encrypted with Fernet before being stored in the Flask session
  and decrypted only at WebSocket connect time. Credentials are already popped from the session
  after first use (one-time use pattern preserved).

### 8) SSH terminal sessions had no audit trail — RESOLVED
- **File:** `routes/terminal.py` (`_ws_primary`)
- `guest_ssh_connect` was already logged. Added `guest_ssh_disconnect` in the `finally` block so
  both endpoints of every terminal session appear in the audit log.

### 9) Login/logout/failed login/password change not audit-logged — RESOLVED
- **File:** `routes/auth.py`
- Added `log_action` calls for: `login`, `login_failed`, `logout`, `password_change`.
  Failed login records include whether the failure was due to bad credentials vs. inactive account.

### 10) UniFi blueprint had no permission check beyond @login_required — RESOLVED
- **File:** `routes/unifi.py`
- Added `can_view_hosts` check to `_require_login()`. Viewers (who cannot see hosts) are now
  redirected. The destructive `restart` action already had a `can_restart_unifi` check.

### 11) X-Forwarded-For not handled for rate limiting — RESOLVED
- **Files:** `app.py`, `routes/auth.py`
- Added Werkzeug `ProxyFix` middleware (`x_for=1, x_proto=1, x_host=1, x_prefix=1`) so
  `request.remote_addr` reflects the real client IP behind a reverse proxy.
- Login rate limiting now prefers `CF-Connecting-IP` (set by Cloudflare) before falling back to
  `remote_addr`, so Cloudflare-fronted deployments rate-limit by real client IP.

### 12) Silent exception swallowing in multiple routes — RESOLVED
- **Files:** `routes/guests.py:214`, `routes/services.py:83`
- Replaced bare `except Exception: pass` with `except Exception as e: logger.warning(...)` so
  failures are visible in application logs without crashing the request.
- Added `logging` and a module-level `logger` to `routes/services.py`.

### 13) Terminal idle timeout missing — RESOLVED
- **File:** `routes/terminal.py` (`_ws_primary`)
- Added a 30-minute idle watchdog thread (`_IDLE_TIMEOUT = 1800`). If no keyboard input is
  received for 30 minutes, the watchdog closes the SSH channel, which gracefully terminates the
  session and sends a `timeout` control message to the client.

### 14) Collaboration system silently breaks in multi-worker deployments — RESOLVED
- **File:** `app.py`
- Added a startup `logger.warning()` that fires if `WEB_CONCURRENCY > 1`, explaining that the
  in-process collaboration state requires a single worker or threaded workers.

### 15) `int()` conversions on form input unguarded — RESOLVED
- **Files:** `routes/hosts.py:141`, `routes/guests.py:151,155,159,164`, `routes/mastodon.py:67,70`
- All direct `int()` calls on user-supplied or settings-sourced values are now wrapped in
  try/except with flash messages and redirects on invalid input.

---

## Open / Not Yet Addressed

| # | Finding | Severity | Notes |
|---|---------|----------|-------|
| 1 | No full CSRF token implementation | High | Origin/referer check is in place; Flask-WTF tokens would be more robust |
| 4 | Local bypass defaults to broad /8 subnet | Medium | Opt-in narrowing recommended |
| 16 | Session fixation after Cloudflare Access auth | Medium | `session.clear()` before `login_user()` in `cloudflare_access.py` |
| 17 | No pagination on guest/service lists | Low-Medium | Performance risk at 100+ guests |
| 18 | No bulk operations (bulk tag, bulk update) | Low | UX gap |
| 19 | Terminal session not persisted across restarts | Low | Loss of collaboration sessions on restart |
| 20 | No key rotation for Fernet encryption | Low | Low risk for single-tenant deployment; document |
| 21 | Test coverage ~5% of route surface area | Medium | No integration tests for Proxmox, SSH, UniFi |
| 22 | Raw exception strings returned in JSON API responses | Medium | Leaks internal details; return generic messages |
