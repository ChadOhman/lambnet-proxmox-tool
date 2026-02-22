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


class Role(db.Model):
    __tablename__ = "roles"

    PERMISSION_FIELDS = [
        "can_ssh", "can_update", "can_manage_users", "can_manage_settings",
        "can_manage_credentials", "can_view_hosts", "can_manage_hosts",
        "can_manage_guests", "can_restart_unifi", "can_view_audit_log",
    ]

    PERMISSION_LABELS = {
        "can_ssh": "SSH Terminal Access",
        "can_update": "Apply Updates",
        "can_manage_users": "Manage Users",
        "can_manage_settings": "Manage Settings",
        "can_manage_credentials": "Manage Credentials",
        "can_view_hosts": "View Host Statistics",
        "can_manage_hosts": "Manage Hosts",
        "can_manage_guests": "Manage Guests",
        "can_restart_unifi": "Restart UniFi Devices",
        "can_view_audit_log": "View Audit Log",
    }

    BASE_TIER_LEVELS = {"viewer": 1, "operator": 2, "admin": 3}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128), nullable=False)
    level = db.Column(db.Integer, nullable=False, default=1)
    is_builtin = db.Column(db.Boolean, default=False)
    base_tier = db.Column(db.String(16), nullable=True)

    # Permission flags
    can_ssh = db.Column(db.Boolean, default=False)
    can_update = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)
    can_manage_settings = db.Column(db.Boolean, default=False)
    can_manage_credentials = db.Column(db.Boolean, default=False)
    can_view_hosts = db.Column(db.Boolean, default=False)
    can_manage_hosts = db.Column(db.Boolean, default=False)
    can_manage_guests = db.Column(db.Boolean, default=False)
    can_restart_unifi = db.Column(db.Boolean, default=False)
    can_view_audit_log = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users = db.relationship("User", backref="role_obj", lazy=True)

    def __getitem__(self, key):
        """Allow dict-style access for Jinja templates (e.g. role[perm])."""
        return getattr(self, key)

    def __repr__(self):
        return f"<Role {self.name}>"


# Default role definitions for seeding
DEFAULT_ROLES = [
    {"name": "super_admin", "display_name": "Super Admin", "level": 4, "is_builtin": True,
     "can_ssh": True, "can_update": True, "can_manage_users": True,
     "can_manage_settings": True, "can_manage_credentials": True,
     "can_view_hosts": True, "can_manage_hosts": True, "can_manage_guests": True,
     "can_restart_unifi": True, "can_view_audit_log": True},
    {"name": "admin", "display_name": "Admin", "level": 3, "is_builtin": True,
     "can_ssh": True, "can_update": True, "can_manage_users": True,
     "can_manage_settings": False, "can_manage_credentials": False,
     "can_view_hosts": True, "can_manage_hosts": True, "can_manage_guests": True,
     "can_restart_unifi": True, "can_view_audit_log": True},
    {"name": "operator", "display_name": "Operator", "level": 2, "is_builtin": True,
     "can_ssh": True, "can_update": True, "can_manage_users": False,
     "can_manage_settings": False, "can_manage_credentials": False,
     "can_view_hosts": True, "can_manage_hosts": False, "can_manage_guests": False,
     "can_restart_unifi": False, "can_view_audit_log": False},
    {"name": "viewer", "display_name": "Viewer", "level": 1, "is_builtin": True,
     "can_ssh": False, "can_update": False, "can_manage_users": False,
     "can_manage_settings": False, "can_manage_credentials": False,
     "can_view_hosts": False, "can_manage_hosts": False, "can_manage_guests": False,
     "can_restart_unifi": False, "can_view_audit_log": False},
]


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128))
    password_hash = db.Column(db.String(256), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    created_via = db.Column(db.String(32), default="local")  # local, cloudflare, local_bypass
    is_active_user = db.Column(db.Boolean, default=True)
    timezone = db.Column(db.String(64), nullable=True)  # IANA tz name, e.g. "America/Chicago"; None = browser auto-detect
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
    def role(self):
        """Backward-compatible: returns the role name string."""
        return self.role_obj.name if self.role_obj else "viewer"

    @property
    def role_level(self):
        return self.role_obj.level if self.role_obj else 1

    @property
    def is_super_admin(self):
        return self.role_obj.name == "super_admin" if self.role_obj else False

    @property
    def is_admin(self):
        return self.role_level >= 3

    @property
    def can_ssh(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_ssh if self.role_obj else False

    @property
    def can_update(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_update if self.role_obj else False

    @property
    def can_manage_users(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_users if self.role_obj else False

    @property
    def can_manage_settings(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_settings if self.role_obj else False

    @property
    def can_manage_credentials(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_credentials if self.role_obj else False

    @property
    def can_view_hosts(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_hosts if self.role_obj else False

    @property
    def can_manage_hosts(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_hosts if self.role_obj else False

    @property
    def can_manage_guests(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_guests if self.role_obj else False

    @property
    def can_restart_unifi(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_restart_unifi if self.role_obj else False

    @property
    def can_view_audit_log(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_audit_log if self.role_obj else False

    @property
    def role_display(self):
        return self.role_obj.display_name if self.role_obj else "Viewer"

    def can_access_guest(self, guest):
        """Check if user can access a guest based on tag permissions."""
        if self.is_super_admin:
            return True
        if not guest.tags:
            return False  # untagged guests are admin-only
        user_tag_ids = {t.id for t in self.allowed_tags}
        guest_tag_ids = {t.id for t in guest.tags}
        return bool(user_tag_ids & guest_tag_ids)

    def accessible_guests(self):
        """Return list of guests this user can access."""
        if self.is_super_admin:
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
        if self.is_super_admin:
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
    host_type = db.Column(db.String(16), default="pve")  # "pve" or "pbs"
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="proxmox_host", lazy=True, cascade="all, delete-orphan")

    @property
    def is_pbs(self):
        return self.host_type == "pbs"

    def __repr__(self):
        return f"<ProxmoxHost {self.name} ({self.hostname}) [{self.host_type}]>"


class Credential(db.Model):
    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(128), nullable=False, default="root")
    auth_type = db.Column(db.String(32), default="password")  # password or key
    encrypted_value = db.Column(db.Text, nullable=False)  # encrypted password or private key
    encrypted_sudo_password = db.Column(db.Text, nullable=True)  # optional sudo password
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
    mac_address = db.Column(db.String(17), nullable=True)  # MAC from Proxmox config (for UniFi matching)
    power_state = db.Column(db.String(16), default="unknown")  # running, stopped, paused, unknown
    reboot_required = db.Column(db.Boolean, default=False)
    require_snapshot = db.Column(db.String(16), default="inherit")  # inherit, yes, no
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    updates = db.relationship("UpdatePackage", backref="guest", lazy=True, cascade="all, delete-orphan")
    scan_results = db.relationship("ScanResult", backref="guest", lazy=True, cascade="all, delete-orphan")
    services = db.relationship("GuestService", backref="guest", lazy=True, cascade="all, delete-orphan")
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


class GuestService(db.Model):
    __tablename__ = "guest_services"

    # Known service definitions: (display_name, unit_name, default_port)
    KNOWN_SERVICES = {
        "elasticsearch": ("Elasticsearch", "elasticsearch.service", 9200),
        "postgresql": ("PostgreSQL", "postgresql.service", 5432),
        "redis": ("Redis", "redis-server.service", 6379),
        "libretranslate": ("LibreTranslate", "libretranslate.service", 5000),
        "puma": ("Puma", "mastodon-web.service", 3000),
        "sidekiq": ("Sidekiq", "mastodon-sidekiq*.service", None),
    }

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False)
    service_name = db.Column(db.String(64), nullable=False)  # e.g. "elasticsearch"
    unit_name = db.Column(db.String(128), nullable=False)  # e.g. "elasticsearch.service"
    port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(32), default="unknown")  # running, stopped, failed, unknown
    last_checked = db.Column(db.DateTime, nullable=True)
    auto_detected = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<GuestService {self.service_name} on guest {self.guest_id}>"


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


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    user          = db.relationship("User", backref="audit_logs")
    action        = db.Column(db.String(64),  nullable=False, index=True)
    resource_type = db.Column(db.String(32),  nullable=False, index=True)
    resource_id   = db.Column(db.Integer,     nullable=True,  index=True)
    resource_name = db.Column(db.String(256), nullable=True)
    details       = db.Column(db.JSON,        nullable=True)
    ip_address    = db.Column(db.String(45),  nullable=True)

    def __repr__(self):
        return f"<AuditLog {self.action} by user_id={self.user_id}>"
