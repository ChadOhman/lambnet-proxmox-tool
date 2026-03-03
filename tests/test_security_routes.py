"""Tests for security blueprint POST routes (user, role, tag, and access management)."""
import pytest
from models import db, User, Role, Tag, Setting


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _viewer_role(app):
    """Return the built-in viewer Role object (within an active app context)."""
    with app.app_context():
        return Role.query.filter_by(name="viewer").first()


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

class TestAddUser:
    def test_add_user_happy_path(self, app, auth_client):
        """POST /security/users/add creates a new user and redirects."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            role_id = viewer.id

        resp = auth_client.post(
            "/security/users/add",
            data={
                "username": "_test_newuser",
                "display_name": "Test New User",
                "password": "ValidPass1!",
                "role_id": str(role_id),
            },
            follow_redirects=False,
        )
        try:
            assert resp.status_code == 302
            with app.app_context():
                user = User.query.filter_by(username="_test_newuser").first()
                assert user is not None
                assert user.display_name == "Test New User"
        finally:
            with app.app_context():
                user = User.query.filter_by(username="_test_newuser").first()
                if user:
                    db.session.delete(user)
                    db.session.commit()

    def test_add_user_username_taken(self, app, auth_client):
        """POST /security/users/add with a duplicate username flashes an error."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            viewer_id = viewer.id
            existing = User(
                username="_test_taken",
                display_name="Taken",
                role_id=viewer_id,
            )
            existing.set_password("SomePass1!")
            db.session.add(existing)
            db.session.commit()
            existing_id = existing.id

        try:
            resp = auth_client.post(
                "/security/users/add",
                data={
                    "username": "_test_taken",
                    "password": "AnotherPass1!",
                    "role_id": str(viewer_id),
                },
                follow_redirects=True,
            )
            assert resp.status_code == 200
            assert b"already exists" in resp.data
        finally:
            with app.app_context():
                user = User.query.get(existing_id)
                if user:
                    db.session.delete(user)
                    db.session.commit()

    def test_add_user_password_too_short(self, app, auth_client):
        """POST /security/users/add with a short password flashes an error."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            role_id = viewer.id

        resp = auth_client.post(
            "/security/users/add",
            data={
                "username": "_test_shortpw",
                "password": "short",
                "role_id": str(role_id),
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"at least 8 characters" in resp.data

        with app.app_context():
            assert User.query.filter_by(username="_test_shortpw").first() is None


class TestEditUser:
    def test_edit_user_change_display_name(self, app, auth_client):
        """POST /security/users/<id>/edit updates the display name."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_test_editdn",
                display_name="Old Name",
                role_id=viewer.id,
            )
            user.set_password("SomePass1!")
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        try:
            resp = auth_client.post(
                f"/security/users/{user_id}/edit",
                data={"display_name": "New Name"},
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                updated = User.query.get(user_id)
                assert updated.display_name == "New Name"
        finally:
            with app.app_context():
                u = User.query.get(user_id)
                if u:
                    db.session.delete(u)
                    db.session.commit()

    def test_edit_user_change_role(self, app, auth_client):
        """POST /security/users/<id>/edit changes the user's role."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            operator = Role.query.filter_by(name="operator").first()
            user = User(
                username="_test_editrole",
                display_name="Edit Role Test",
                role_id=viewer.id,
            )
            user.set_password("SomePass1!")
            db.session.add(user)
            db.session.commit()
            user_id = user.id
            operator_id = operator.id

        try:
            resp = auth_client.post(
                f"/security/users/{user_id}/edit",
                data={
                    "display_name": "Edit Role Test",
                    "role_id": str(operator_id),
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                updated = User.query.get(user_id)
                assert updated.role_id == operator_id
        finally:
            with app.app_context():
                u = User.query.get(user_id)
                if u:
                    db.session.delete(u)
                    db.session.commit()


class TestDeleteUser:
    def test_delete_user_happy_path(self, app, auth_client):
        """POST /security/users/<id>/delete removes the user from the database."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_test_deluser",
                display_name="To Be Deleted",
                role_id=viewer.id,
            )
            user.set_password("SomePass1!")
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        try:
            resp = auth_client.post(
                f"/security/users/{user_id}/delete",
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                assert User.query.get(user_id) is None
        finally:
            with app.app_context():
                u = User.query.get(user_id)
                if u:
                    db.session.delete(u)
                    db.session.commit()

    def test_delete_user_cannot_delete_self(self, app, auth_client):
        """POST /security/users/<id>/delete rejects deletion of the current user."""
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            admin_id = admin.id

        resp = auth_client.post(
            f"/security/users/{admin_id}/delete",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"cannot delete your own account" in resp.data

        with app.app_context():
            assert User.query.get(admin_id) is not None


# ---------------------------------------------------------------------------
# Role management
# ---------------------------------------------------------------------------

class TestAddRole:
    def test_add_role_happy_path(self, app, auth_client):
        """POST /security/roles/add creates a new custom role."""
        resp = auth_client.post(
            "/security/roles/add",
            data={
                "name": "_test_role_new",
                "display_name": "Test Role New",
                "base_tier": "operator",
            },
            follow_redirects=False,
        )
        try:
            assert resp.status_code == 302
            with app.app_context():
                role = Role.query.filter_by(name="_test_role_new").first()
                assert role is not None
                assert role.display_name == "Test Role New"
                assert role.is_builtin is False
        finally:
            with app.app_context():
                role = Role.query.filter_by(name="_test_role_new").first()
                if role:
                    db.session.delete(role)
                    db.session.commit()

    def test_add_role_duplicate_name(self, app, auth_client):
        """POST /security/roles/add with a duplicate name flashes an error."""
        with app.app_context():
            existing = Role(
                name="_test_role_dup",
                display_name="Duplicate Role",
                level=1,
                is_builtin=False,
            )
            db.session.add(existing)
            db.session.commit()
            existing_id = existing.id

        try:
            resp = auth_client.post(
                "/security/roles/add",
                data={
                    "name": "_test_role_dup",
                    "display_name": "Another Duplicate",
                    "base_tier": "viewer",
                },
                follow_redirects=True,
            )
            assert resp.status_code == 200
            assert b"already exists" in resp.data
        finally:
            with app.app_context():
                role = Role.query.get(existing_id)
                if role:
                    db.session.delete(role)
                    db.session.commit()


class TestEditRole:
    def test_edit_role_change_permissions(self, app, auth_client):
        """POST /security/roles/<id>/edit updates permission flags on a custom role."""
        with app.app_context():
            role = Role(
                name="_test_role_edit",
                display_name="Edit Perms Role",
                level=1,
                is_builtin=False,
                base_tier="viewer",
                can_ssh=False,
                can_view_hosts=False,
            )
            db.session.add(role)
            db.session.commit()
            role_id = role.id

        try:
            resp = auth_client.post(
                f"/security/roles/{role_id}/edit",
                data={
                    "display_name": "Edit Perms Role",
                    # Sending can_ssh in form simulates checkbox checked
                    "can_ssh": "on",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                updated = Role.query.get(role_id)
                assert updated.can_ssh is True
                assert updated.can_view_hosts is False
        finally:
            with app.app_context():
                r = Role.query.get(role_id)
                if r:
                    db.session.delete(r)
                    db.session.commit()


class TestDeleteRole:
    def test_delete_role_happy_path(self, app, auth_client):
        """POST /security/roles/<id>/delete removes a custom role with no users."""
        with app.app_context():
            role = Role(
                name="_test_role_del",
                display_name="Delete Me Role",
                level=1,
                is_builtin=False,
            )
            db.session.add(role)
            db.session.commit()
            role_id = role.id

        resp = auth_client.post(
            f"/security/roles/{role_id}/delete",
            follow_redirects=False,
        )
        try:
            assert resp.status_code == 302
            with app.app_context():
                assert Role.query.get(role_id) is None
        finally:
            with app.app_context():
                r = Role.query.get(role_id)
                if r:
                    db.session.delete(r)
                    db.session.commit()

    def test_delete_builtin_role_rejected(self, app, auth_client):
        """POST /security/roles/<id>/delete rejects deletion of built-in roles."""
        with app.app_context():
            viewer = Role.query.filter_by(name="viewer").first()
            viewer_id = viewer.id

        resp = auth_client.post(
            f"/security/roles/{viewer_id}/delete",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Built-in roles cannot be deleted" in resp.data

        with app.app_context():
            assert Role.query.get(viewer_id) is not None


# ---------------------------------------------------------------------------
# Tag management
# ---------------------------------------------------------------------------

class TestAddTag:
    def test_add_tag_happy_path(self, app, auth_client):
        """POST /security/tags/add creates a new tag."""
        resp = auth_client.post(
            "/security/tags/add",
            data={"name": "_test_tag_new", "color": "#ff0000"},
            follow_redirects=False,
        )
        try:
            assert resp.status_code == 302
            with app.app_context():
                tag = Tag.query.filter_by(name="_test_tag_new").first()
                assert tag is not None
                assert tag.color == "#ff0000"
        finally:
            with app.app_context():
                tag = Tag.query.filter_by(name="_test_tag_new").first()
                if tag:
                    db.session.delete(tag)
                    db.session.commit()


class TestDeleteTag:
    def test_delete_tag_happy_path(self, app, auth_client):
        """POST /security/tags/<id>/delete removes the tag."""
        with app.app_context():
            tag = Tag(name="_test_tag_del", color="#aabbcc")
            db.session.add(tag)
            db.session.commit()
            tag_id = tag.id

        resp = auth_client.post(
            f"/security/tags/{tag_id}/delete",
            follow_redirects=False,
        )
        try:
            assert resp.status_code == 302
            with app.app_context():
                assert Tag.query.get(tag_id) is None
        finally:
            with app.app_context():
                t = Tag.query.get(tag_id)
                if t:
                    db.session.delete(t)
                    db.session.commit()


# ---------------------------------------------------------------------------
# Access settings
# ---------------------------------------------------------------------------

class TestLocalBypass:
    def test_local_bypass_valid_subnet(self, app, auth_client):
        """POST /security/access/local-bypass with a valid subnet saves the setting."""
        resp = auth_client.post(
            "/security/access/local-bypass",
            data={
                "local_bypass_enabled": "on",
                "trusted_subnets": "192.168.1.0/24",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("trusted_subnets") == "192.168.1.0/24"
            assert Setting.get("local_bypass_enabled") == "true"

    def test_local_bypass_invalid_subnet(self, app, auth_client):
        """POST /security/access/local-bypass with a bad subnet flashes an error."""
        resp = auth_client.post(
            "/security/access/local-bypass",
            data={
                "trusted_subnets": "not-a-subnet",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid subnet" in resp.data

    def test_local_bypass_multiple_valid_subnets(self, app, auth_client):
        """POST /security/access/local-bypass accepts a comma-separated list of subnets."""
        resp = auth_client.post(
            "/security/access/local-bypass",
            data={
                "trusted_subnets": "10.0.0.0/8, 172.16.0.0/12",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_local_bypass_mixed_valid_invalid(self, app, auth_client):
        """POST /security/access/local-bypass rejects lists containing any invalid entry."""
        resp = auth_client.post(
            "/security/access/local-bypass",
            data={
                "trusted_subnets": "10.0.0.0/8, bad-entry",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid subnet" in resp.data


class TestSnapshotSettings:
    def test_snapshot_toggle_on(self, app, auth_client):
        """POST /security/access/snapshots with the checkbox saves require=true."""
        resp = auth_client.post(
            "/security/access/snapshots",
            data={"require_snapshot_before_action": "on"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("require_snapshot_before_action") == "true"

    def test_snapshot_toggle_off(self, app, auth_client):
        """POST /security/access/snapshots without the checkbox saves require=false."""
        resp = auth_client.post(
            "/security/access/snapshots",
            data={},  # checkbox absent → off
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("require_snapshot_before_action") == "false"

    def test_snapshot_flash_message(self, app, auth_client):
        """POST /security/access/snapshots shows a success flash after save."""
        resp = auth_client.post(
            "/security/access/snapshots",
            data={"require_snapshot_before_action": "on"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Snapshot settings saved" in resp.data
