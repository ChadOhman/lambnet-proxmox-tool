import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LAMBNET_DATA_DIR", "/var/lib/lambnet")
SECRET_KEY_PATH = os.environ.get("LAMBNET_SECRET_KEY", "/etc/lambnet/secret.key")


def _load_flask_secret():
    """Load Flask secret key from file or environment, generating one if needed."""
    key_file = os.environ.get("FLASK_SECRET_KEY_FILE", "/etc/lambnet/flask_secret")
    if os.path.exists(key_file):
        with open(key_file) as f:
            key = f.read().strip()
            if key:
                return key

    env_key = os.environ.get("FLASK_SECRET_KEY", "")
    if env_key:
        return env_key

    # Generate and persist a secure random key
    import secrets
    generated = secrets.token_hex(32)
    try:
        key_dir = os.path.dirname(key_file)
        if key_dir and not os.path.exists(key_dir):
            os.makedirs(key_dir, mode=0o700, exist_ok=True)
        with open(key_file, "w") as f:
            f.write(generated)
        os.chmod(key_file, 0o600)
    except OSError:
        pass  # Dev/test environment without write access to /etc
    return generated


class Config:
    SECRET_KEY = _load_flask_secret()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'lambnet.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Default scan interval in hours
    SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", "6"))

    # Gmail defaults
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USE_TLS = True

    # App info
    VERSION_FILE = os.path.join(BASE_DIR, "VERSION")
    GITHUB_REPO = "ChadOhman/mstdnca-proxmox-tool"
