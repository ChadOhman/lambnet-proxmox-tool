# Key Patterns

## Permission Gate

`@bp.before_request` + `@login_required` + check `current_user.can_*`

## Audit Logging

```python
from auth.audit import log_action
log_action("action", "resource_type", resource_id=..., resource_name=...)
db.session.commit()
```

## Settings Cache

`Setting.get()` caches per-request via `Flask g._settings_cache`; invalidated on `Setting.set()`.

## Accessible Confirms

All `confirm()` dialogs use Bootstrap modal (`#confirmModal` in `base.html`). Forms use `data-confirm="..."` attribute; JS intercepts submit.

## SQLAlchemy Filters

`== True` comparisons are intentional (E712 is ignored in ruff) — required by SQLAlchemy filter syntax.

## Import Conventions

Core modules (`models`, `config`) are at root. Everything else uses package imports:
- `from auth.audit import log_action`
- `from clients.ssh_client import SSHClient`
- `from core.scanner import scan_guest`
- `from apps.mastodon import check_mastodon_release`