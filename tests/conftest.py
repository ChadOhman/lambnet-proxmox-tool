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
