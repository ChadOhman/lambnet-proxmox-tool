"""Tests for config.py — _load_flask_secret() and Config class attributes."""

import os
import importlib

import pytest

import config as config_module
from config import _load_flask_secret


# ---------------------------------------------------------------------------
# _load_flask_secret — direct unit tests
# ---------------------------------------------------------------------------

class TestLoadFlaskSecret:
    """Tests for _load_flask_secret(), which has three resolution paths:
    1. FLASK_SECRET_KEY_FILE exists and is non-empty  → read from file
    2. FLASK_SECRET_KEY env var is set                → use env var value
    3. Neither                                        → generate and persist
    """

    def test_env_var_returned_when_set(self, monkeypatch, tmp_path):
        """FLASK_SECRET_KEY env var is returned when no key file exists."""
        # Point key-file to a path that does not exist so it is skipped.
        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(tmp_path / "no_such_file"))
        monkeypatch.setenv("FLASK_SECRET_KEY", "my-env-secret")

        result = _load_flask_secret()

        assert result == "my-env-secret"

    def test_key_file_takes_priority_over_env_var(self, monkeypatch, tmp_path):
        """When FLASK_SECRET_KEY_FILE exists and is non-empty it takes priority."""
        key_file = tmp_path / "flask_secret"
        key_file.write_text("file-based-secret\n")

        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.setenv("FLASK_SECRET_KEY", "env-secret-should-be-ignored")

        result = _load_flask_secret()

        assert result == "file-based-secret"

    def test_key_file_strips_trailing_newline(self, monkeypatch, tmp_path):
        """Content read from the key file must be stripped of surrounding whitespace."""
        key_file = tmp_path / "flask_secret"
        key_file.write_text("  secret-with-spaces  \n")

        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

        result = _load_flask_secret()

        assert result == "secret-with-spaces"

    def test_empty_key_file_falls_through_to_env_var(self, monkeypatch, tmp_path):
        """An empty key file must be ignored; the env var is used instead."""
        key_file = tmp_path / "flask_secret"
        key_file.write_text("   \n")  # whitespace-only → stripped → empty

        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.setenv("FLASK_SECRET_KEY", "fallback-env-secret")

        result = _load_flask_secret()

        assert result == "fallback-env-secret"

    def test_missing_key_file_and_env_var_generates_secret(self, monkeypatch, tmp_path):
        """When neither file nor env var is present a random secret is generated."""
        # Use a writable tmp dir so the generated key can be persisted without OSError.
        key_file = tmp_path / "generated_secret"
        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

        result = _load_flask_secret()

        assert isinstance(result, str)
        assert len(result) > 0

    def test_generated_secret_is_persisted_to_key_file(self, monkeypatch, tmp_path):
        """The generated key should be written to FLASK_SECRET_KEY_FILE when writable."""
        key_file = tmp_path / "generated_secret"
        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

        result = _load_flask_secret()

        assert key_file.exists()
        assert key_file.read_text().strip() == result

    def test_generated_secret_is_hex_string(self, monkeypatch, tmp_path):
        """Generated secret must be a valid hex string (64 chars = 32 bytes)."""
        key_file = tmp_path / "generated_secret"
        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

        result = _load_flask_secret()

        # secrets.token_hex(32) produces 64 lowercase hex characters.
        assert len(result) == 64
        int(result, 16)  # raises ValueError if not valid hex

    def test_missing_key_file_and_missing_env_var_still_returns_secret(self, monkeypatch, tmp_path):
        """Even when the file cannot be written, a secret string is still returned."""
        # Point to an unwritable directory by using a read-only parent.
        # On Windows permissions work differently so we use a non-existent deep path
        # and rely on the except OSError: pass branch in _load_flask_secret.
        bad_dir = tmp_path / "no_write" / "deep" / "path"
        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(bad_dir / "flask_secret"))
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

        # On Windows we cannot easily make dirs unwritable, so just confirm the
        # function does not raise and returns a non-empty string.
        result = _load_flask_secret()

        assert isinstance(result, str)
        assert len(result) > 0

    def test_env_var_empty_string_falls_through_to_generate(self, monkeypatch, tmp_path):
        """An empty FLASK_SECRET_KEY env var must be treated as absent."""
        key_file = tmp_path / "no_such_file"
        monkeypatch.setenv("FLASK_SECRET_KEY_FILE", str(key_file))
        monkeypatch.setenv("FLASK_SECRET_KEY", "")

        result = _load_flask_secret()

        # Should be a generated hex string, not an empty string.
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Config class attribute smoke tests
# ---------------------------------------------------------------------------

class TestConfigClass:
    """Sanity-check that Config attributes have the expected types / values."""

    def test_secret_key_is_non_empty_string(self):
        from config import Config
        assert isinstance(Config.SECRET_KEY, str)
        assert len(Config.SECRET_KEY) > 0

    def test_sqlalchemy_database_uri_is_string(self):
        from config import Config
        assert isinstance(Config.SQLALCHEMY_DATABASE_URI, str)

    def test_database_url_env_var_respected(self, monkeypatch):
        """DATABASE_URL env var should set SQLALCHEMY_DATABASE_URI."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///custom_test.db")
        # Reload the module so the class-level expression re-evaluates.
        importlib.reload(config_module)
        from config import Config
        assert Config.SQLALCHEMY_DATABASE_URI == "sqlite:///custom_test.db"
        # Restore original state for subsequent tests.
        importlib.reload(config_module)

    def test_session_cookie_httponly_is_true(self):
        from config import Config
        assert Config.SESSION_COOKIE_HTTPONLY is True

    def test_session_cookie_samesite_is_lax(self):
        from config import Config
        assert Config.SESSION_COOKIE_SAMESITE == "Lax"

    def test_sqlalchemy_track_modifications_is_false(self):
        from config import Config
        assert Config.SQLALCHEMY_TRACK_MODIFICATIONS is False

    def test_scan_interval_hours_default(self, monkeypatch):
        """SCAN_INTERVAL_HOURS defaults to 6 when env var is not set."""
        monkeypatch.delenv("SCAN_INTERVAL_HOURS", raising=False)
        importlib.reload(config_module)
        from config import Config
        assert Config.SCAN_INTERVAL_HOURS == 6
        importlib.reload(config_module)

    def test_scan_interval_hours_env_override(self, monkeypatch):
        """SCAN_INTERVAL_HOURS is taken from the SCAN_INTERVAL_HOURS env var."""
        monkeypatch.setenv("SCAN_INTERVAL_HOURS", "12")
        importlib.reload(config_module)
        from config import Config
        assert Config.SCAN_INTERVAL_HOURS == 12
        importlib.reload(config_module)

    def test_session_cookie_secure_true_when_not_debug(self, monkeypatch):
        """SESSION_COOKIE_SECURE should be True in non-debug mode by default."""
        monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
        monkeypatch.setenv("FLASK_DEBUG", "0")
        importlib.reload(config_module)
        from config import Config
        assert Config.SESSION_COOKIE_SECURE is True
        importlib.reload(config_module)

    def test_session_cookie_secure_false_in_debug_mode(self, monkeypatch):
        """SESSION_COOKIE_SECURE should default to False when FLASK_DEBUG=1."""
        monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
        monkeypatch.setenv("FLASK_DEBUG", "1")
        importlib.reload(config_module)
        from config import Config
        assert Config.SESSION_COOKIE_SECURE is False
        importlib.reload(config_module)

    def test_session_cookie_secure_overridden_by_env(self, monkeypatch):
        """SESSION_COOKIE_SECURE env var can force the value regardless of debug mode."""
        monkeypatch.setenv("SESSION_COOKIE_SECURE", "0")
        monkeypatch.setenv("FLASK_DEBUG", "0")
        importlib.reload(config_module)
        from config import Config
        assert Config.SESSION_COOKIE_SECURE is False
        importlib.reload(config_module)
