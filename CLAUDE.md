# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Flask-based Proxmox datacenter administration tool (Python 3.13). Manages VMs/LXCs across PVE/PBS hosts with web SSH terminal, service monitoring, Mastodon/Ghost/PeerTube upgrade automation, UniFi integration, and real-time collaboration via SSE + WebSocket.

## Commands

```bash
# Install dev dependencies
make install-dev

# Run full test suite (814 tests, in-memory SQLite)
make test

# Run a single test file
FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev \
  pytest tests/test_auth.py -v

# Run a single test
FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev \
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

**Single-worker constraint:** The collaboration system (`core/collaboration.py`) uses in-process state for presence tracking and terminal sharing. Must run with gunicorn `-w 1` or `--worker-class gthread`. Multi-worker deployments silently break collaboration features.

**Directory structure:**
```
(root)
├── app.py                  # Flask app factory
├── config.py               # Configuration (BASE_DIR, DATA_DIR, SECRET_KEY_PATH)
├── models.py               # SQLAlchemy models + DB instance
├── auth/                   # Authentication & security
│   ├── audit.py            # log_action() audit logging
│   ├── cloudflare_access.py # CF Access JWT validation
│   ├── local_network.py    # Local network auto-login bypass
│   └── credential_store.py # Fernet symmetric encryption
├── clients/                # External service clients
│   ├── ssh_client.py       # SSH wrapper (paramiko)
│   ├── proxmox_api.py      # Proxmox VE API client
│   ├── pbs_client.py       # Proxmox Backup Server client
│   ├── unifi_client.py     # UniFi network integration
│   └── unifi_geoip.py      # GeoIP lookup for UniFi
├── core/                   # Business logic
│   ├── scanner.py          # Guest/package scanning via SSH
│   ├── scheduler.py        # APScheduler background jobs
│   ├── collaboration.py    # Presence tracking, terminal sharing
│   └── notifier.py         # Webhook notifications
├── apps/                   # Application upgrade automation
│   ├── utils.py            # Shared helpers (_log_cmd_output, _validate_shell_param, _version_gt)
│   ├── mastodon.py         # Mastodon/glitch-soc upgrades
│   ├── ghost.py            # Ghost CMS upgrades
│   ├── peertube.py         # PeerTube upgrades
│   ├── elk.py              # Elk (Mastodon web client) upgrades
│   └── jitsi.py            # Jitsi Meet install/upgrades
├── routes/                 # Flask blueprints (one per feature)
├── templates/              # Jinja2 templates
├── static/                 # CSS (style.css)
├── scripts/                # Shell scripts (setup.sh, update.sh, create-ct.sh)
└── tests/                  # Test suite
```

**Blueprint layout** — one file per feature area in `routes/`:
- `auth.py` — login/logout/change-password
- `guests.py` — VM/CT CRUD with tag-based access filtering
- `hosts.py` — PVE/PBS host management
- `terminal.py` — WebSocket SSH terminal (Flask-Sock), 1800s idle timeout
- `security.py` — user/role/tag management, `_safe_int()` helper
- `services.py` — service monitoring (mastodon, sidekiq, postgres, redis)
- `mastodon.py`, `ghost.py`, `peertube.py`, `elk.py`, `jitsi.py` — application upgrade routes
- `api.py` — REST API endpoints
- `dashboard.py`, `credentials.py`, `settings.py`, `schedules.py`, `unifi.py`, `applications.py`

**Database:** SQLite via SQLAlchemy. Schema migrations run at startup in `_migrate_schema()` (ALTER TABLE for new columns since `create_all()` doesn't alter existing tables). Models in `models.py`.

**Auth layers:** Local login → Cloudflare Access JWT (`auth/cloudflare_access.py`) → Local network auto-login (`auth/local_network.py`, trusted CIDRs). Role-based permissions: super_admin > admin > operator > viewer with 13 permission flags on the `Role` model.

**Credentials:** Fernet symmetric encryption (`auth/credential_store.py`), key at `/etc/mstdnca/secret.key`. Fernet instance cached at module level with thread-safe double-checked locking.

**Frontend:** Jinja2 templates with Bootstrap 5.3.3 dark theme + htmx 2.0.4 + xterm.js, all from CDN. Single `static/style.css`.

## Key Patterns

- **Permission gate:** `@bp.before_request` + `@login_required` + check `current_user.can_*`
- **Audit logging:** `from auth.audit import log_action` → `log_action("action", "resource_type", resource_id=..., resource_name=...)` then `db.session.commit()`
- **Settings cache:** `Setting.get()` caches per-request via `Flask g._settings_cache`; invalidated on `Setting.set()`
- **Accessible confirms:** All `confirm()` dialogs use Bootstrap modal (`#confirmModal` in `base.html`). Forms use `data-confirm="..."` attribute; JS intercepts submit.
- **SQLAlchemy filters:** `== True` comparisons are intentional (E712 is ignored in ruff) — required by SQLAlchemy filter syntax.
- **Import conventions:** Core modules (`models`, `config`) are at root. Everything else uses package imports: `from auth.audit import log_action`, `from clients.ssh_client import SSHClient`, `from core.scanner import scan_guest`, `from apps.mastodon import check_mastodon_release`.

## Working Standards

- **Own all failures:** Never dismiss test failures as "pre-existing" without fixing them. Investigate the root cause and fix them in the same PR. Don't push broken CI.
- **CI must pass:** Every push must have a green CI. Take ownership of all failures on the branch, even if the root cause predates the current work.

## Lint / Style

- Ruff: `line-length = 120`, `target-version = "py310"`
- Rules: E, F, W, B (bugbear), S (bandit/security)
- `routes/terminal.py` allows S602 (shell=True for SSH)
- `tests/**/*.py` allows S101 (assert)

## Testing

- Tests use in-memory SQLite and a session-scoped app fixture (`tests/conftest.py`)
- `auth_client` fixture provides a pre-authenticated admin client
- Credential store is redirected to a temp file — tests never touch `/etc/mstdnca`
- No integration tests for Proxmox/SSH/UniFi — those modules are omitted from coverage
- Coverage threshold: 40% (`--cov-fail-under=40`) in both CI and local Makefile
