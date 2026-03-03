import os
import tempfile

import pytest
from app import create_app
from models import db as _db, User

_TEST_ADMIN_PASSWORD = "TestPass123!"

_TEST_CONFIG = {
    "TESTING": True,
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SECRET_KEY": "test-secret-key",
    "WTF_CSRF_ENABLED": False,
}


@pytest.fixture(autouse=True, scope="session")
def _isolate_credential_store():
    """Redirect credential_store key to a temp file so tests never touch /etc/lambnet."""
    import config as cfg
    import credential_store

    tmp_dir = tempfile.mkdtemp(prefix="lambnet-test-")
    key_path = os.path.join(tmp_dir, "secret.key")
    original_path = cfg.SECRET_KEY_PATH
    original_fernet = credential_store._fernet

    cfg.SECRET_KEY_PATH = key_path
    os.environ["LAMBNET_SECRET_KEY"] = key_path
    credential_store._fernet = None

    yield

    cfg.SECRET_KEY_PATH = original_path
    os.environ.pop("LAMBNET_SECRET_KEY", None)
    credential_store._fernet = original_fernet

    # Clean up temp key file
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(tmp_dir):
        os.rmdir(tmp_dir)


@pytest.fixture(scope="session")
def app():
    application = create_app(_TEST_CONFIG)
    with application.app_context():
        admin = User.query.filter_by(username="admin").first()
        if admin:
            admin.set_password(_TEST_ADMIN_PASSWORD)
            _db.session.commit()
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(app):
    """A test client pre-authenticated as the admin user."""
    with app.test_client() as c:
        c.post(
            "/login",
            data={"username": "admin", "password": _TEST_ADMIN_PASSWORD},
            follow_redirects=False,
        )
        yield c
