"""Shared helpers for application upgrade automation modules."""

import re


# Shell-safe value pattern: alphanumeric, hyphens, underscores, dots, forward slashes, colons
_SHELL_SAFE_RE = re.compile(r'^[\w.\-/:~]+$')


def _log_cmd_output(log, stdout, stderr, code, max_chars=2000):
    """Log combined stdout+stderr, showing start+end on failure (error before stack trace)."""
    combined = ((stdout or "") + ("\n" + stderr if stderr else "")).strip()
    if not combined:
        return
    if len(combined) <= max_chars:
        log(combined)
    elif code != 0:
        # On failure the actual error is near the top; stack trace fills the bottom.
        # Show first 1500 + last 500 so both error and context are visible.
        head = combined[:1500].strip()
        tail = combined[-500:].strip()
        log(head)
        log("[... output truncated ...]")
        log(tail)
    else:
        log(combined[-max_chars:].strip())


def _validate_shell_param(value, label):
    """Raise ValueError if a config value contains shell-unsafe characters."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _SHELL_SAFE_RE.match(value):
        raise ValueError(f"{label} contains unsafe characters: {value!r}")


def _version_gt(candidate: str, current: str) -> bool:
    """True if candidate semver is strictly greater than current.

    Strips build metadata (e.g. '+glitch') before comparing so that
    '4.5.7' and '4.6.0-alpha.5+glitch' are compared by their numeric
    components only.  A stable release (no pre-release tag) sorts higher
    than a pre-release with the same major.minor.patch.
    """
    def _parse(v):
        v = v.lstrip("v").split("+")[0]
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$", v)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))

    pa, pb = _parse(candidate), _parse(current)
    if pa is None or pb is None:
        return False
    if pa[:3] != pb[:3]:
        return pa[:3] > pb[:3]
    # Same major.minor.patch — stable (pre=None) sorts above any pre-release
    pre_a, pre_b = pa[3], pb[3]
    if pre_a is None and pre_b is None:
        return False
    if pre_a is None:
        return True   # candidate is stable, current is pre-release → newer
    if pre_b is None:
        return False  # candidate is pre-release, current is stable → older
    return pre_a > pre_b  # both pre-release: lexicographic comparison
