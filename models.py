from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Association table: which tags a user has access to
user_tags = db.Table(
    "user_tags",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"), primary_key=True),
)

# Association table: which tags a guest has
guest_tags = db.Table(
    "guest_tags",
    db.Column("guest_id", db.Integer, db.ForeignKey("guests.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    ROLE_LEVELS = {
        "super_admin": 4,
        "admin": 3,
        "operator": 2,
        "viewer": 1,
    }

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128))
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="viewer")
    is_active_user = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Tags this user has access to
    allowed_tags = db.relationship("Tag", secondary=user_tags, backref="users")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_user

    @property
    def role_level(self):
        return self.ROLE_LEVELS.get(self.role, 1)

    @property
    def is_super_admin(self):
        return self.role == "super_admin"

    @property
    def is_admin(self):
        return self.role in ("super_admin", "admin")

    @property
    def can_ssh(self):
        return self.role in ("super_admin", "admin", "operator")

    @property
    def can_update(self):
        return self.role in ("super_admin", "admin", "operator")

    @property
    def can_manage_users(self):
        return self.role in ("super_admin", "admin")

    @property
    def can_manage_settings(self):
        return self.role == "super_admin"

    @property
    def can_manage_credentials(self):
        return self.role == "super_admin"

    @property
    def can_manage_hosts(self):
        return self.role in ("super_admin", "admin")

    @property
    def can_restart_unifi(self):
        return self.role in ("super_admin", "admin")

    @property
    def role_display(self):
        return self.role.replace("_", " ").title()

    def can_access_guest(self, guest):
        """Check if user can access a guest based on tag permissions."""
        if self.is_admin:
            return True
        if not guest.tags:
            return False  # untagged guests are admin-only
        user_tag_ids = {t.id for t in self.allowed_tags}
        guest_tag_ids = {t.id for t in guest.tags}
        return bool(user_tag_ids & guest_tag_ids)

    def accessible_guests(self):
        """Return list of guests this user can access."""
        if self.is_admin:
            return Guest.query.filter_by(enabled=True).all()
        user_tag_ids = [t.id for t in self.allowed_tags]
        if not user_tag_ids:
            return []
        return (
            Guest.query.filter_by(enabled=True)
            .filter(Guest.tags.any(Tag.id.in_(user_tag_ids)))
            .all()
        )

    def can_edit_user(self, other_user):
        """Check if this user can edit another user."""
        if self.id == other_user.id:
            return True
        return self.role_level > other_user.role_level

    def __repr__(self):
        return f"<User {self.username}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    color = db.Column(db.String(7), default="#6c757d")  # hex color for UI
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Tag {self.name}>"


class ProxmoxHost(db.Model):
    __tablename__ = "proxmox_hosts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    hostname = db.Column(db.String(256), nullable=False)
    port = db.Column(db.Integer, default=8006)
    auth_type = db.Column(db.String(32), default="token")  # token or password
    username = db.Column(db.String(128))  # e.g. root@pam
    encrypted_password = db.Column(db.Text)
    api_token_id = db.Column(db.String(128))
    api_token_secret = db.Column(db.Text)  # encrypted
    verify_ssl = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="proxmox_host", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ProxmoxHost {self.name} ({self.hostname})>"


class Credential(db.Model):
    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(128), nullable=False, default="root")
    auth_type = db.Column(db.String(32), default="password")  # password or key
    encrypted_value = db.Column(db.Text, nullable=False)  # encrypted password or private key
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="credential", lazy=True)

    def __repr__(self):
        return f"<Credential {self.name}>"


class MaintenanceWindow(db.Model):
    __tablename__ = "maintenance_windows"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    day_of_week = db.Column(db.String(32), nullable=False)  # e.g. "monday" or "daily"
    start_time = db.Column(db.String(8), nullable=False)  # HH:MM
    end_time = db.Column(db.String(8), nullable=False)  # HH:MM
    update_type = db.Column(db.String(32), default="upgrade")  # upgrade or dist-upgrade
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="maintenance_window", lazy=True)

    def __repr__(self):
        return f"<MaintenanceWindow {self.name}>"


class Guest(db.Model):
    __tablename__ = "guests"

    id = db.Column(db.Integer, primary_key=True)
    proxmox_host_id = db.Column(db.Integer, db.ForeignKey("proxmox_hosts.id"), nullable=True)
    vmid = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(128), nullable=False)
    guest_type = db.Column(db.String(16), nullable=False)  # vm or ct
    ip_address = db.Column(db.String(64))
    connection_method = db.Column(db.String(16), default="ssh")  # ssh, agent, or auto
    credential_id = db.Column(db.Integer, db.ForeignKey("credentials.id"), nullable=True)
    auto_update = db.Column(db.Boolean, default=False)
    maintenance_window_id = db.Column(db.Integer, db.ForeignKey("maintenance_windows.id"), nullable=True)
    last_scan = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="unknown")  # unknown, up-to-date, updates-available, error
    enabled = db.Column(db.Boolean, default=True)
    replication_target = db.Column(db.String(128), nullable=True)  # node name if replicated
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    updates = db.relationship("UpdatePackage", backref="guest", lazy=True, cascade="all, delete-orphan")
    scan_results = db.relationship("ScanResult", backref="guest", lazy=True, cascade="all, delete-orphan")
    tags = db.relationship("Tag", secondary=guest_tags, backref="guests")

    def pending_updates(self):
        return [u for u in self.updates if u.status == "pending"]

    def security_updates(self):
        return [u for u in self.updates if u.status == "pending" and u.severity == "critical"]

    def __repr__(self):
        return f"<Guest {self.name} ({self.guest_type})>"


class UpdatePackage(db.Model):
    __tablename__ = "update_packages"

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False)
    package_name = db.Column(db.String(256), nullable=False)
    current_version = db.Column(db.String(128))
    available_version = db.Column(db.String(128))
    severity = db.Column(db.String(32), default="normal")  # critical, important, normal
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    applied_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="pending")  # pending, applied, skipped

    def __repr__(self):
        return f"<UpdatePackage {self.package_name} on guest {self.guest_id}>"


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False)
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    total_updates = db.Column(db.Integer, default=0)
    security_updates = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default="success")  # success, error
    error_message = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<ScanResult guest={self.guest_id} total={self.total_updates}>"


class Setting(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key, default=None):
        s = Setting.query.filter_by(key=key).first()
        return s.value if s else default

    @staticmethod
    def set(key, value):
        s = Setting.query.filter_by(key=key).first()
        if s:
            s.value = value
        else:
            s = Setting(key=key, value=value)
            db.session.add(s)
        db.session.commit()
        return s
