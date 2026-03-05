# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Flask-based Proxmox datacenter administration tool (Python 3.13). Manages VMs/LXCs across PVE/PBS hosts with web SSH terminal, service monitoring, Mastodon/Ghost/PeerTube upgrade automation, UniFi integration, and real-time collaboration via SSE + WebSocket.

## Commands

```bash
# Install dev dependencies
make install-dev

# Run full test suite (646 tests, in-memory SQLite)
make test

# Run a single test file
FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/lambnet-dev-test.db" LAMBNET_DATA_DIR=/tmp/lambnet-dev \
  pytest tests/test_auth.py -v

# Run a single test
FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/lambnet-dev-test.db" LAMBNET_DATA_DIR=/tmp/lambnet-dev \
  pytest tests/test_auth.py::TestLogin::test_valid_login -v

# Lint
make lint          # ruff check .
ruff check . --fix # auto-fix

# Security scan
make security      # bandit + pip-audit

# All checks
make all           # lint → security → test
```

## Architecture

**App factory:** `app.py::create_app()` — initializes DB, runs schema migrations, registers 16 blueprints, starts APScheduler, sets up auth middleware (Cloudflare Access + local network bypass), CSRF origin check, and security headers.

**Single-worker constraint:** The collaboration system (`collaboration.py`) uses in-process state for presence tracking and terminal sharing. Must run with gunicorn `-w 1` or `--worker-class gthread`. Multi-worker deployments silently break collaboration features.

**Blueprint layout** — one file per feature area in `routes/`:
- `auth.py` — login/logout/change-password
- `guests.py` — VM/CT CRUD with tag-based access filtering
- `hosts.py` — PVE/PBS host management
- `terminal.py` — WebSocket SSH terminal (Flask-Sock), 1800s idle timeout
- `security.py` — user/role/tag management, `_safe_int()` helper
- `services.py` — service monitoring (mastodon, sidekiq, postgres, redis)
- `mastodon.py`, `ghost.py`, `peertube.py` — application upgrade routes
- `api.py` — REST API endpoints
- `dashboard.py`, `credentials.py`, `settings.py`, `schedules.py`, `unifi.py`, `applications.py`

**Database:** SQLite via SQLAlchemy. Schema migrations run at startup in `_migrate_schema()` (ALTER TABLE for new columns since `create_all()` doesn't alter existing tables). Models in `models.py`.

**Auth layers:** Local login → Cloudflare Access JWT (`cloudflare_access.py`) → Local network auto-login (`local_network.py`, trusted CIDRs). Role-based permissions: super_admin > admin > operator > viewer with 13 permission flags on the `Role` model.

**Credentials:** Fernet symmetric encryption (`credential_store.py`), key at `/etc/lambnet/secret.key`. Fernet instance cached at module level with thread-safe double-checked locking.

**Frontend:** Jinja2 templates with Bootstrap 5.3.3 dark theme + htmx 2.0.4 + xterm.js, all from CDN. Single `static/style.css`.

## Key Patterns

- **Permission gate:** `@bp.before_request` + `@login_required` + check `current_user.can_*`
- **Audit logging:** `log_action("action", "resource_type", resource_id=..., resource_name=...)` then `db.session.commit()`
- **Settings cache:** `Setting.get()` caches per-request via `Flask g._settings_cache`; invalidated on `Setting.set()`
- **Accessible confirms:** All `confirm()` dialogs use Bootstrap modal (`#confirmModal` in `base.html`). Forms use `data-confirm="..."` attribute; JS intercepts submit.
- **SQLAlchemy filters:** `== True` comparisons are intentional (E712 is ignored in ruff) — required by SQLAlchemy filter syntax.

## Lint / Style

- Ruff: `line-length = 120`, `target-version = "py310"`
- Rules: E, F, W, B (bugbear), S (bandit/security)
- `routes/terminal.py` allows S602 (shell=True for SSH)
- `tests/**/*.py` allows S101 (assert)

## Testing

- Tests use in-memory SQLite and a session-scoped app fixture (`tests/conftest.py`)
- `auth_client` fixture provides a pre-authenticated admin client
- Credential store is redirected to a temp file — tests never touch `/etc/lambnet`
- No integration tests for Proxmox/SSH/UniFi — those modules are omitted from coverage
- CI coverage threshold: 40% (`--cov-fail-under=40`); local Makefile uses 18%