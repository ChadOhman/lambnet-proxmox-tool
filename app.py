import os
import logging
from urllib.parse import urlparse
from flask import Flask
from flask_login import LoginManager
from config import Config, BASE_DIR, DATA_DIR
from models import db, User, Role, DEFAULT_ROLES

logger = logging.getLogger(__name__)


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

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
        return User.query.options(db.joinedload(User.role_obj)).get(int(user_id))

    with app.app_context():
        db.create_all()
        _migrate_schema()
        _migrate_roles()
        _seed_roles()
        _migrate_users_to_role_fk()
        _ensure_default_admin()

    # Read version from file
    file_version = "unknown"
    if os.path.exists(Config.VERSION_FILE):
        with open(Config.VERSION_FILE) as f:
            file_version = f.read().strip()

    # Read git info for branch-based deployments
    import subprocess
    git_commit = ""
    git_branch = ""
    version_matches_tag = False
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BASE_DIR, stderr=subprocess.DEVNULL
        ).decode().strip()
        git_branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=BASE_DIR, stderr=subprocess.DEVNULL
        ).decode().strip()
        # Check if current commit is tagged with the VERSION file's version
        if file_version != "unknown":
            try:
                tag_commit = subprocess.check_output(
                    ["git", "rev-parse", "--short", f"v{file_version}"],
                    cwd=BASE_DIR, stderr=subprocess.DEVNULL
                ).decode().strip()
                version_matches_tag = (tag_commit == git_commit)
            except Exception:
                version_matches_tag = False
    except Exception:
        pass

    # If current commit doesn't match the VERSION tag, we're ahead of the release
    if version_matches_tag:
        app.config["APP_VERSION"] = file_version
    else:
        app.config["APP_VERSION"] = file_version  # keep for reference
        app.config["APP_VERSION_STALE"] = True
    app.config["GIT_COMMIT"] = git_commit
    app.config["GIT_BRANCH"] = git_branch

    # Register blueprints
    from routes.auth import bp as auth_bp
    from routes.dashboard import bp as dashboard_bp
    from routes.hosts import bp as hosts_bp
    from routes.guests import bp as guests_bp
    from routes.credentials import bp as credentials_bp
    from routes.settings import bp as settings_bp
    from routes.schedules import bp as schedules_bp
    from routes.security import bp as security_bp
    from routes.terminal import bp as terminal_bp
    from routes.mastodon import bp as mastodon_bp
    from routes.api import bp as api_bp
    from routes.services import bp as services_bp
    from routes.unifi import bp as unifi_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(hosts_bp, url_prefix="/hosts")
    app.register_blueprint(guests_bp, url_prefix="/guests")
    app.register_blueprint(credentials_bp, url_prefix="/credentials")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(schedules_bp, url_prefix="/schedules")
    app.register_blueprint(security_bp, url_prefix="/security")
    app.register_blueprint(terminal_bp, url_prefix="/terminal")
    app.register_blueprint(mastodon_bp, url_prefix="/mastodon")
    app.register_blueprint(services_bp, url_prefix="/services")
    app.register_blueprint(unifi_bp, url_prefix="/unifi")
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

    # Custom Jinja filters
    from datetime import datetime, timezone as tz

    @app.template_filter("timestamp_to_datetime")
    def timestamp_to_datetime(epoch):
        """Convert a Unix epoch timestamp to a formatted datetime string."""
        try:
            return datetime.fromtimestamp(int(epoch), tz=tz.utc).strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError, OSError):
            return ""

    # Security headers
    @app.before_request
    def _csrf_origin_check():
        """Basic CSRF defense for state-changing browser requests.

        Accept only same-origin requests for unsafe HTTP methods.
        """
        from flask import request, abort

        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        if request.path.startswith("/static/"):
            return

        # Prefer Origin; fallback to Referer for older browser/form behavior.
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if not source:
            return  # No origin header -- non-browser client; allow

        src = urlparse(source)
        req = urlparse(request.host_url)
        if (src.scheme, src.netloc) != (req.scheme, req.netloc):
            abort(403, description="Cross-site request blocked")

    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not app.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.context_processor
    def inject_safety_mode():
        from flask import session
        from flask_login import current_user
        if current_user.is_authenticated:
            return {"safety_mode": session.get("safety_mode", False)}
        return {"safety_mode": False}

    @app.route("/toggle-safety-mode", methods=["POST"])
    def toggle_safety_mode():
        from flask import session, redirect, request
        from flask_login import current_user
        if not current_user.is_authenticated:
            from flask import abort
            abort(403)
        session["safety_mode"] = not session.get("safety_mode", False)
        return redirect(request.referrer or "/")

    return app


def _migrate_schema():
    """Add any missing columns to existing tables (SQLAlchemy create_all doesn't alter tables)."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()

    if "guests" in table_names:
        guest_columns = [c["name"] for c in inspector.get_columns("guests")]
        if "replication_target" not in guest_columns:
            logger.info("Adding replication_target column to guests table...")
            db.session.execute(text("ALTER TABLE guests ADD COLUMN replication_target VARCHAR(128)"))
            db.session.commit()
        if "mac_address" not in guest_columns:
            logger.info("Adding mac_address column to guests table...")
            db.session.execute(text("ALTER TABLE guests ADD COLUMN mac_address VARCHAR(17)"))
            db.session.commit()
        if "power_state" not in guest_columns:
            logger.info("Adding power_state column to guests table...")
            db.session.execute(text("ALTER TABLE guests ADD COLUMN power_state VARCHAR(16) DEFAULT 'unknown'"))
            db.session.commit()
        if "require_snapshot" not in guest_columns:
            logger.info("Adding require_snapshot column to guests table...")
            db.session.execute(text("ALTER TABLE guests ADD COLUMN require_snapshot VARCHAR(16) DEFAULT 'inherit'"))
            db.session.commit()
        if "reboot_required" not in guest_columns:
            logger.info("Adding reboot_required column to guests table...")
            db.session.execute(text("ALTER TABLE guests ADD COLUMN reboot_required BOOLEAN DEFAULT 0"))
            db.session.commit()

    if "users" in table_names:
        user_columns = [c["name"] for c in inspector.get_columns("users")]
        if "created_via" not in user_columns:
            logger.info("Adding created_via column to users table...")
            db.session.execute(text("ALTER TABLE users ADD COLUMN created_via VARCHAR(32) DEFAULT 'local'"))
            db.session.commit()

    if "roles" in table_names:
        role_columns = [c["name"] for c in inspector.get_columns("roles")]
        if "can_view_hosts" not in role_columns:
            logger.info("Adding can_view_hosts column to roles table...")
            db.session.execute(text("ALTER TABLE roles ADD COLUMN can_view_hosts BOOLEAN DEFAULT 0"))
            db.session.execute(text("UPDATE roles SET can_view_hosts = 1 WHERE level >= 2"))
            db.session.commit()

    if "credentials" in table_names:
        cred_columns = [c["name"] for c in inspector.get_columns("credentials")]
        if "encrypted_sudo_password" not in cred_columns:
            logger.info("Adding encrypted_sudo_password column to credentials table...")
            db.session.execute(text("ALTER TABLE credentials ADD COLUMN encrypted_sudo_password TEXT"))
            db.session.commit()

    if "proxmox_hosts" in table_names:
        host_columns = [c["name"] for c in inspector.get_columns("proxmox_hosts")]
        if "host_type" not in host_columns:
            logger.info("Adding host_type column to proxmox_hosts table...")
            db.session.execute(text("ALTER TABLE proxmox_hosts ADD COLUMN host_type VARCHAR(16) DEFAULT 'pve'"))
            db.session.commit()


def _migrate_roles():
    """Migrate from old boolean permission columns to role-based model."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    columns = [c["name"] for c in inspector.get_columns("users")]

    if "is_admin" not in columns:
        return  # Already migrated

    logger.info("Migrating user permissions to role-based model...")

    # Read old data
    rows = db.session.execute(
        text("SELECT id, is_admin, can_ssh, can_update FROM users ORDER BY id")
    ).fetchall()

    # Add role column if it doesn't exist
    if "role" not in columns:
        db.session.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(16) DEFAULT 'viewer'"))
        db.session.commit()

    # Assign roles: first admin becomes super_admin, rest admin, etc.
    first_admin_set = False
    for row in rows:
        user_id, is_admin, can_ssh, can_update = row
        if is_admin and not first_admin_set:
            role = "super_admin"
            first_admin_set = True
        elif is_admin:
            role = "admin"
        elif can_ssh or can_update:
            role = "operator"
        else:
            role = "viewer"
        db.session.execute(
            text("UPDATE users SET role = :role WHERE id = :id"),
            {"role": role, "id": user_id},
        )

    db.session.commit()

    # Drop old columns (SQLite requires table recreation)
    db.session.execute(text("""
        CREATE TABLE users_new (
            id INTEGER PRIMARY KEY,
            username VARCHAR(64) UNIQUE NOT NULL,
            display_name VARCHAR(128),
            password_hash VARCHAR(256) NOT NULL,
            role VARCHAR(16) NOT NULL DEFAULT 'viewer',
            is_active_user BOOLEAN DEFAULT 1,
            created_at DATETIME
        )
    """))
    db.session.execute(text("""
        INSERT INTO users_new (id, username, display_name, password_hash, role, is_active_user, created_at)
        SELECT id, username, display_name, password_hash, role, is_active_user, created_at FROM users
    """))
    db.session.execute(text("DROP TABLE users"))
    db.session.execute(text("ALTER TABLE users_new RENAME TO users"))
    db.session.commit()
    logger.info("Role migration complete.")


def _seed_roles():
    """Seed the default roles if the roles table is empty."""
    if Role.query.count() > 0:
        return
    logger.info("Seeding default roles...")
    for role_data in DEFAULT_ROLES:
        role = Role(**role_data)
        db.session.add(role)
    db.session.commit()
    logger.info(f"Seeded {len(DEFAULT_ROLES)} default roles.")


def _migrate_users_to_role_fk():
    """Migrate users from role VARCHAR column to role_id FK."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    if "users" not in inspector.get_table_names():
        return

    columns = [c["name"] for c in inspector.get_columns("users")]

    # Already migrated if role_id exists
    if "role_id" in columns:
        return

    # Need the old "role" string column to migrate from
    if "role" not in columns:
        return

    logger.info("Migrating users table from role string to role_id FK...")

    # Read old user data
    rows = db.session.execute(
        text("SELECT id, username, display_name, password_hash, role, is_active_user, created_at FROM users")
    ).fetchall()

    # Preserve user_tags data
    tag_rows = []
    if "user_tags" in inspector.get_table_names():
        tag_rows = db.session.execute(text("SELECT user_id, tag_id FROM user_tags")).fetchall()
        db.session.execute(text("DROP TABLE user_tags"))
        db.session.commit()

    # Build role name -> id mapping
    role_map = {}
    for r in Role.query.all():
        role_map[r.name] = r.id

    # Default fallback to viewer role
    viewer_id = role_map.get("viewer", 1)

    # Recreate users table with role_id
    db.session.execute(text("DROP TABLE users"))
    db.session.execute(text("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username VARCHAR(64) UNIQUE NOT NULL,
            display_name VARCHAR(128),
            password_hash VARCHAR(256) NOT NULL,
            role_id INTEGER NOT NULL REFERENCES roles(id),
            is_active_user BOOLEAN DEFAULT 1,
            created_at DATETIME
        )
    """))

    for row in rows:
        uid, username, display_name, password_hash, role_str, is_active, created_at = row
        role_id = role_map.get(role_str, viewer_id)
        db.session.execute(
            text("""INSERT INTO users (id, username, display_name, password_hash, role_id, is_active_user, created_at)
                    VALUES (:id, :username, :display_name, :password_hash, :role_id, :is_active, :created_at)"""),
            {"id": uid, "username": username, "display_name": display_name,
             "password_hash": password_hash, "role_id": role_id,
             "is_active": is_active, "created_at": created_at},
        )

    # Restore user_tags
    db.session.execute(text("""
        CREATE TABLE user_tags (
            user_id INTEGER REFERENCES users(id),
            tag_id INTEGER REFERENCES tags(id),
            PRIMARY KEY (user_id, tag_id)
        )
    """))
    for tr in tag_rows:
        db.session.execute(
            text("INSERT INTO user_tags (user_id, tag_id) VALUES (:uid, :tid)"),
            {"uid": tr[0], "tid": tr[1]},
        )

    db.session.commit()
    logger.info("User role FK migration complete.")


def _ensure_default_admin():
    """Create default admin user if no users exist."""
    if User.query.count() == 0:
        sa_role = Role.query.filter_by(name="super_admin").first()
        if not sa_role:
            return
        import secrets
        default_password = secrets.token_urlsafe(16)
        admin = User(
            username="admin",
            display_name="Administrator",
            role_id=sa_role.id,
        )
        admin.set_password(default_password)
        db.session.add(admin)
        db.session.commit()
        logger.warning("=" * 60)
        logger.warning("  DEFAULT ADMIN ACCOUNT CREATED")
        logger.warning("  Username: admin")
        logger.warning("  Password: %s", default_password)
        logger.warning("  Please change this password immediately!")
        logger.warning("=" * 60)
        print("=" * 60)
        print("  DEFAULT ADMIN ACCOUNT CREATED")
        print("  Username: admin")
        print(f"  Password: {default_password}")
        print("  Please change this password immediately!")
        print("=" * 60)


if __name__ == "__main__":
    app = create_app()

    # Start scheduler
    from scheduler import init_scheduler
    init_scheduler(app)

    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
