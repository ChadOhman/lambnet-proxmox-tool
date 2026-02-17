import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LAMBNET_DATA_DIR", "/var/lib/lambnet")
SECRET_KEY_PATH = os.environ.get("LAMBNET_SECRET_KEY", "/etc/lambnet/secret.key")


class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'lambnet.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Default scan interval in hours
    SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", "6"))

    # Gmail defaults
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USE_TLS = True

    # App info
    VERSION_FILE = os.path.join(BASE_DIR, "VERSION")
    GITHUB_REPO = "ChadOhman/lambnet-proxmox-tool"
