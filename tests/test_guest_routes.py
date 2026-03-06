"""Tests for guests blueprint CRUD operations (no Proxmox API calls required)."""
import pytest
from models import db, Guest, Tag, Credential


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def guest(app):
    """Seed a single Guest with no Proxmox host; clean up after each test."""
    guest_id = None
    with app.app_context():
        g = Guest(name="_test-guest", guest_type="vm")
        db.session.add(g)
        db.session.commit()
        guest_id = g.id

    yield guest_id

    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


@pytest.fixture()
def guest_ct(app):
    """Seed a container-type Guest; clean up after each test."""
    guest_id = None
    with app.app_context():
        g = Guest(
            name="_test-ct-guest",
            guest_type="ct",
            ip_address="192.168.1.50",
            connection_method="agent",
            auto_update=False,
        )
        db.session.add(g)
        db.session.commit()
        guest_id = g.id

    yield guest_id

    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


@pytest.fixture()
def test_tag(app):
    """Seed a Tag for use in assignment tests; clean up after each test."""
    tag_id = None
    with app.app_context():
        t = Tag(name="_test-tag", color="#123456")
        db.session.add(t)
        db.session.commit()
        tag_id = t.id

    yield tag_id

    with app.app_context():
        t = Tag.query.get(tag_id)
        if t:
            db.session.delete(t)
            db.session.commit()


@pytest.fixture()
def test_credential(app):
    """Seed a Credential for use in guest tests; clean up after each test."""
    cred_id = None
    with app.app_context():
        import auth.credential_store as credential_store
        cred = Credential(
            name="_test-guest-cred",
            username="ubuntu",
            auth_type="password",
            encrypted_value=credential_store.encrypt("testpass"),
            is_default=False,
        )
        db.session.add(cred)
        db.session.commit()
        cred_id = cred.id

    yield cred_id

    with app.app_context():
        c = Credential.query.get(cred_id)
        if c:
            db.session.delete(c)
            db.session.commit()


# ---------------------------------------------------------------------------
# Guest Add — POST /guests/add
# ---------------------------------------------------------------------------


class TestGuestAdd:
    def test_add_happy_path(self, app, auth_client):
        """POST /guests/add with a name creates the guest and redirects."""
        guest_id = None
        try:
            resp = auth_client.post(
                "/guests/add",
                data={
                    "name": "_test-add-vm",
                    "guest_type": "vm",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.filter_by(name="_test-add-vm").first()
                assert g is not None
                assert g.guest_type == "vm"
                assert g.proxmox_host_id is None
                assert g.vmid is None
                guest_id = g.id
        finally:
            if guest_id is not None:
                with app.app_context():
                    g = Guest.query.get(guest_id)
                    if g:
                        db.session.delete(g)
                        db.session.commit()

    def test_add_with_credential_and_connection_method(self, app, auth_client, test_credential):
        """POST /guests/add stores credential_id and connection_method."""
        guest_id = None
        try:
            resp = auth_client.post(
                "/guests/add",
                data={
                    "name": "_test-add-with-cred",
                    "guest_type": "ct",
                    "connection_method": "agent",
                    "credential_id": str(test_credential),
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.filter_by(name="_test-add-with-cred").first()
                assert g is not None
                assert g.guest_type == "ct"
                assert g.connection_method == "agent"
                assert g.credential_id == test_credential
                guest_id = g.id
        finally:
            if guest_id is not None:
                with app.app_context():
                    g = Guest.query.get(guest_id)
                    if g:
                        db.session.delete(g)
                        db.session.commit()

    def test_add_with_tags(self, app, auth_client, test_tag):
        """POST /guests/add with tag_ids assigns tags to the new guest."""
        guest_id = None
        try:
            resp = auth_client.post(
                "/guests/add",
                data={
                    "name": "_test-add-with-tags",
                    "guest_type": "vm",
                    "tag_ids": [str(test_tag)],
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.filter_by(name="_test-add-with-tags").first()
                assert g is not None
                assert any(t.id == test_tag for t in g.tags)
                guest_id = g.id
        finally:
            if guest_id is not None:
                with app.app_context():
                    g = Guest.query.get(guest_id)
                    if g:
                        db.session.delete(g)
                        db.session.commit()

    def test_add_missing_name_redirects_with_flash(self, app, auth_client):
        """POST /guests/add with no name flashes an error and does not create a guest."""
        resp = auth_client.post(
            "/guests/add",
            data={"name": "", "guest_type": "vm"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Name is required" in resp.data

        with app.app_context():
            assert Guest.query.filter_by(name="").count() == 0

    def test_add_with_auto_update_enabled(self, app, auth_client):
        """POST /guests/add does not set auto_update (that field is edit-only)."""
        # auto_update is not part of the add form — only connection_method, creds, tags, name.
        # This test confirms the default value (False) after add.
        guest_id = None
        try:
            resp = auth_client.post(
                "/guests/add",
                data={
                    "name": "_test-add-autoupdate",
                    "guest_type": "vm",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.filter_by(name="_test-add-autoupdate").first()
                assert g is not None
                assert g.auto_update is False  # default — auto_update only settable via edit
                guest_id = g.id
        finally:
            if guest_id is not None:
                with app.app_context():
                    g = Guest.query.get(guest_id)
                    if g:
                        db.session.delete(g)
                        db.session.commit()

    def test_add_unauthenticated_redirects(self, client):
        """POST /guests/add without auth redirects to login."""
        resp = client.post(
            "/guests/add",
            data={"name": "_test-unauth", "guest_type": "vm"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Guest Detail — GET /guests/<id>
# ---------------------------------------------------------------------------


class TestGuestDetail:
    def test_detail_no_proxmox_host_returns_200(self, auth_client, guest):
        """GET /guests/<id> for a guest with no Proxmox host renders without API call."""
        resp = auth_client.get(f"/guests/{guest}")
        assert resp.status_code == 200

    def test_detail_shows_guest_name(self, app, auth_client, guest):
        """GET /guests/<id> renders the guest's name in the response body."""
        with app.app_context():
            g = Guest.query.get(guest)
            name_bytes = g.name.encode()

        resp = auth_client.get(f"/guests/{guest}")
        assert resp.status_code == 200
        assert name_bytes in resp.data

    def test_detail_nonexistent_guest_returns_404(self, auth_client):
        """GET /guests/999999 returns 404 for a nonexistent guest."""
        resp = auth_client.get("/guests/999999")
        assert resp.status_code == 404

    def test_detail_ct_guest_returns_200(self, auth_client, guest_ct):
        """GET /guests/<id> works for a container-type guest with ip_address set."""
        resp = auth_client.get(f"/guests/{guest_ct}")
        assert resp.status_code == 200

    def test_detail_unauthenticated_redirects(self, client, guest):
        """GET /guests/<id> without auth redirects to login."""
        resp = client.get(f"/guests/{guest}", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Guest Edit — POST /guests/<id>/edit
# ---------------------------------------------------------------------------


class TestGuestEdit:
    def test_edit_connection_method(self, app, auth_client, guest):
        """POST /guests/<id>/edit updates connection_method."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "agent",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.connection_method == "agent"

    def test_edit_toggle_auto_update_on(self, app, auth_client, guest):
        """POST /guests/<id>/edit with auto_update checkbox enables auto_update."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "ssh",
                "auto_update": "on",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.auto_update is True

    def test_edit_toggle_auto_update_off(self, app, auth_client, guest):
        """POST /guests/<id>/edit without auto_update checkbox disables auto_update."""
        # First enable it
        with app.app_context():
            g = Guest.query.get(guest)
            g.auto_update = True
            db.session.commit()

        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "ssh",
                # auto_update absent from form → False
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.auto_update is False

    def test_edit_change_connection_method_to_auto(self, app, auth_client, guest):
        """POST /guests/<id>/edit can set connection_method to 'auto'."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={"connection_method": "auto"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.connection_method == "auto"

    def test_edit_clears_tags_when_none_submitted(self, app, auth_client, guest, test_tag):
        """POST /guests/<id>/edit with no tag_ids clears all tags from the guest."""
        # First assign a tag
        with app.app_context():
            g = Guest.query.get(guest)
            t = Tag.query.get(test_tag)
            g.tags = [t]
            db.session.commit()

        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "ssh",
                # tag_ids absent → tags cleared
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.tags == []

    def test_edit_nonexistent_guest_returns_404(self, auth_client):
        """POST /guests/999999/edit returns 404 for a nonexistent guest."""
        resp = auth_client.post(
            "/guests/999999/edit",
            data={"connection_method": "ssh"},
        )
        assert resp.status_code == 404

    def test_edit_sets_require_snapshot(self, app, auth_client, guest):
        """POST /guests/<id>/edit can set require_snapshot to 'yes'."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "ssh",
                "require_snapshot": "yes",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.require_snapshot == "yes"

    def test_edit_assigns_credential(self, app, auth_client, guest, test_credential):
        """POST /guests/<id>/edit can assign a credential to a guest."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "ssh",
                "credential_id": str(test_credential),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.credential_id == test_credential

    def test_edit_redirects_to_detail_page(self, auth_client, guest):
        """POST /guests/<id>/edit redirects to the guest detail page."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={"connection_method": "ssh"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert f"/guests/{guest}" in resp.headers["Location"]

    def test_edit_unauthenticated_redirects(self, client, guest):
        """POST /guests/<id>/edit without auth redirects to login."""
        resp = client.post(
            f"/guests/{guest}/edit",
            data={"connection_method": "ssh"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Guest Delete — POST /guests/<id>/delete
# ---------------------------------------------------------------------------


class TestGuestDelete:
    def test_delete_happy_path(self, app, auth_client):
        """POST /guests/<id>/delete removes the guest and redirects."""
        with app.app_context():
            g = Guest(name="_test-delete-me", guest_type="vm")
            db.session.add(g)
            db.session.commit()
            guest_id = g.id

        try:
            resp = auth_client.post(
                f"/guests/{guest_id}/delete",
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                assert Guest.query.get(guest_id) is None
        finally:
            with app.app_context():
                g = Guest.query.get(guest_id)
                if g:
                    db.session.delete(g)
                    db.session.commit()

    def test_delete_nonexistent_guest_returns_404(self, auth_client):
        """POST /guests/999999/delete returns 404 for a nonexistent guest."""
        resp = auth_client.post("/guests/999999/delete")
        assert resp.status_code == 404

    def test_delete_redirects_to_index(self, app, auth_client):
        """POST /guests/<id>/delete redirects to /guests/ after deletion."""
        with app.app_context():
            g = Guest(name="_test-delete-redirect", guest_type="ct")
            db.session.add(g)
            db.session.commit()
            guest_id = g.id

        try:
            resp = auth_client.post(
                f"/guests/{guest_id}/delete",
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/guests/" in resp.headers["Location"]
        finally:
            with app.app_context():
                g = Guest.query.get(guest_id)
                if g:
                    db.session.delete(g)
                    db.session.commit()

    def test_delete_flash_message_contains_name(self, app, auth_client):
        """POST /guests/<id>/delete shows the deleted guest's name in the flash message."""
        with app.app_context():
            g = Guest(name="_test-delete-flash", guest_type="vm")
            db.session.add(g)
            db.session.commit()
            guest_id = g.id

        try:
            resp = auth_client.post(
                f"/guests/{guest_id}/delete",
                follow_redirects=True,
            )
            assert resp.status_code == 200
            assert b"_test-delete-flash" in resp.data
        finally:
            with app.app_context():
                g = Guest.query.get(guest_id)
                if g:
                    db.session.delete(g)
                    db.session.commit()

    def test_delete_unauthenticated_redirects(self, client, guest):
        """POST /guests/<id>/delete without auth redirects to login."""
        resp = client.post(
            f"/guests/{guest}/delete",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Guest Tags — tag assignment via POST /guests/<id>/edit
# ---------------------------------------------------------------------------


class TestGuestTagAssignment:
    def test_assign_tag_to_guest_via_edit(self, app, auth_client, guest, test_tag):
        """POST /guests/<id>/edit with tag_ids assigns the tags to the guest."""
        resp = auth_client.post(
            f"/guests/{guest}/edit",
            data={
                "connection_method": "ssh",
                "tag_ids": [str(test_tag)],
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert any(t.id == test_tag for t in g.tags)

    def test_assign_multiple_tags_to_guest(self, app, auth_client, guest):
        """POST /guests/<id>/edit with multiple tag_ids assigns all tags."""
        tag_ids = []
        with app.app_context():
            t1 = Tag(name="_test-tag-multi-1", color="#aaaaaa")
            t2 = Tag(name="_test-tag-multi-2", color="#bbbbbb")
            db.session.add_all([t1, t2])
            db.session.commit()
            tag_ids = [t1.id, t2.id]

        try:
            resp = auth_client.post(
                f"/guests/{guest}/edit",
                data={
                    "connection_method": "ssh",
                    "tag_ids": [str(tid) for tid in tag_ids],
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.get(guest)
                assigned_ids = {t.id for t in g.tags}
                assert set(tag_ids).issubset(assigned_ids)
        finally:
            with app.app_context():
                for tid in tag_ids:
                    t = Tag.query.get(tid)
                    if t:
                        db.session.delete(t)
                db.session.commit()

    def test_replace_tags_on_edit(self, app, auth_client, guest, test_tag):
        """POST /guests/<id>/edit replaces existing tags with the newly submitted set."""
        with app.app_context():
            old_tag = Tag(name="_test-tag-old", color="#cccccc")
            db.session.add(old_tag)
            db.session.flush()
            g = Guest.query.get(guest)
            g.tags = [old_tag]
            db.session.commit()
            old_tag_id = old_tag.id

        try:
            resp = auth_client.post(
                f"/guests/{guest}/edit",
                data={
                    "connection_method": "ssh",
                    "tag_ids": [str(test_tag)],
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.get(guest)
                assigned_ids = {t.id for t in g.tags}
                # New tag present, old tag gone
                assert test_tag in assigned_ids
                assert old_tag_id not in assigned_ids
        finally:
            with app.app_context():
                t = Tag.query.get(old_tag_id)
                if t:
                    db.session.delete(t)
                    db.session.commit()

    def test_add_guest_with_tag_on_creation(self, app, auth_client, test_tag):
        """POST /guests/add with tag_ids assigns tags at creation time."""
        guest_id = None
        try:
            resp = auth_client.post(
                "/guests/add",
                data={
                    "name": "_test-tag-at-create",
                    "guest_type": "vm",
                    "tag_ids": [str(test_tag)],
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                g = Guest.query.filter_by(name="_test-tag-at-create").first()
                assert g is not None
                assert any(t.id == test_tag for t in g.tags)
                guest_id = g.id
        finally:
            if guest_id is not None:
                with app.app_context():
                    g = Guest.query.get(guest_id)
                    if g:
                        db.session.delete(g)
                        db.session.commit()
