import os
from flask import Flask
from flask_login import LoginManager
from config import Config, BASE_DIR, DATA_DIR
from models import db, User


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    db.init_app(app)

    # Setup Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        _ensure_default_admin()

    # Read version
    version = "unknown"
    if os.path.exists(Config.VERSION_FILE):
        with open(Config.VERSION_FILE) as f:
            version = f.read().strip()
    app.config["APP_VERSION"] = version

    # Register blueprints
    from routes.auth import bp as auth_bp
    from routes.dashboard import bp as dashboard_bp
    from routes.hosts import bp as hosts_bp
    from routes.guests import bp as guests_bp
    from routes.credentials import bp as credentials_bp
    from routes.settings import bp as settings_bp
    from routes.schedules import bp as schedules_bp
    from routes.users import bp as users_bp
    from routes.terminal import bp as terminal_bp
    from routes.api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(hosts_bp, url_prefix="/hosts")
    app.register_blueprint(guests_bp, url_prefix="/guests")
    app.register_blueprint(credentials_bp, url_prefix="/credentials")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(schedules_bp, url_prefix="/schedules")
    app.register_blueprint(users_bp, url_prefix="/users")
    app.register_blueprint(terminal_bp, url_prefix="/terminal")
    app.register_blueprint(api_bp, url_prefix="/api")

    # Initialize WebSocket for terminal
    from routes.terminal import init_websocket
    init_websocket(app)

    # Local network bypass (must run before CF Access so local IPs are already authed)
    from local_network import init_local_bypass
    init_local_bypass(app)

    # Initialize Cloudflare Zero Trust integration
    from cloudflare_access import init_cf_access
    init_cf_access(app)

    # Security headers
    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not app.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    return app


def _ensure_default_admin():
    """Create default admin user if no users exist."""
    if User.query.count() == 0:
        admin = User(
            username="admin",
            display_name="Administrator",
            is_admin=True,
            can_ssh=True,
            can_update=True,
        )
        admin.set_password("admin")
        db.session.add(admin)
        db.session.commit()


if __name__ == "__main__":
    app = create_app()

    # Start scheduler
    from scheduler import init_scheduler
    init_scheduler(app)

    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
