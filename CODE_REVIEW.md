# Code Review Findings

Date: 2026-02-22

## 1) Missing CSRF protection across state-changing forms (High)
- The Flask app initializes auth/session middleware but does not initialize CSRF protection middleware (for example, `flask_wtf.CSRFProtect`).
- Multiple privileged actions are handled via POST forms in templates without CSRF tokens.
- Impact: an authenticated admin user could be tricked into submitting a forged request that changes security settings, deletes users, or performs other state-changing actions.

Examples:
- `app.py` does not initialize any CSRF protection.
- `templates/security.html` contains privileged POST forms (for role and tag deletion) without CSRF fields.

## 2) Logout endpoint uses GET instead of POST (Medium)
- `/logout` is implemented as a GET route.
- Impact: cross-site links/images can force user logout (session disruption/DoS-style annoyance), and this pattern weakens CSRF posture.

Recommendation:
- Change logout to POST only and include CSRF validation.

## 3) Unhandled form parsing errors can trigger 500 responses (Medium)
- In `routes/security.py`, several handlers cast request values directly using `int(...)` without validation.
- Examples include `role_id` and `tag_ids` handling during add/edit flows.
- Impact: malformed input can raise `ValueError` and return server errors rather than controlled validation responses.

Recommendation:
- Validate numeric fields before conversion, handle conversion errors, and return user-facing validation messages.

## 4) Default local-network bypass auto-authenticates as admin (Medium)
- Local bypass defaults to enabled and trusted subnet default is `10.0.0.0/8`.
- Requests from trusted networks are auto-authenticated as the `admin` account.
- Impact: broad private addressing defaults may be too permissive in shared/internal networks and can lead to unintended administrative access.

Recommendation:
- Default this feature to disabled, or require explicit setup of narrow trusted CIDRs.
- Consider creating a dedicated low-privilege local bypass role instead of automatic admin login.
