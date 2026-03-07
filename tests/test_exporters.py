"""Tests for the Prometheus exporter management system."""

from models import db, Guest, ExporterInstance, ProxmoxHost


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_host(app):
    """Create a minimal host for guest FK."""
    host = ProxmoxHost.query.first()
    if host:
        return host
    host = ProxmoxHost(
        name="pve-test",
        hostname="10.0.0.1",
        host_type="pve",
    )
    db.session.add(host)
    db.session.commit()
    return host


def _create_guest(app, name="test-guest", ip="10.0.0.50"):
    """Create a minimal guest for exporter tests."""
    host = _create_host(app)
    guest = Guest(
        name=name,
        vmid=100,
        guest_type="lxc",
        proxmox_host_id=host.id,
        ip_address=ip,
    )
    db.session.add(guest)
    db.session.commit()
    return guest


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestExporterModel:

    def test_create_exporter_instance(self, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-model-test", ip="10.0.0.60")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()

            fetched = ExporterInstance.query.filter_by(guest_id=guest.id).first()
            assert fetched is not None
            assert fetched.exporter_type == "node_exporter"
            assert fetched.port == 9100
            assert fetched.status == "pending"
            assert fetched.version is None

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_guest_exporters_relationship(self, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-rel-test", ip="10.0.0.61")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
            )
            db.session.add(exp)
            db.session.commit()

            assert len(guest.exporters) == 1
            assert guest.exporters[0].exporter_type == "node_exporter"

            db.session.delete(exp)
            db.session.delete(guest)
            db.session.commit()

    def test_cascade_delete_with_guest(self, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-cascade-test", ip="10.0.0.62")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id

            db.session.delete(guest)
            db.session.commit()

            assert ExporterInstance.query.get(exp_id) is None


# ---------------------------------------------------------------------------
# Logic tests (apps/exporters.py)
# ---------------------------------------------------------------------------

class TestExporterLogic:

    def test_known_exporters_registry(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert "node_exporter" in KNOWN_EXPORTERS
        assert "postgres_exporter" in KNOWN_EXPORTERS
        assert "redis_exporter" in KNOWN_EXPORTERS
        assert KNOWN_EXPORTERS["node_exporter"]["default_port"] == 9100

    def test_systemd_unit_generation(self):
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit("node_exporter", 9100)
        assert "ExecStart=/usr/local/bin/node_exporter" in unit
        assert ":9100" in unit
        assert "User=node_exporter" in unit
        assert "[Install]" in unit

    def test_systemd_unit_with_env_file(self):
        from apps.exporters import _generate_exporter_systemd_unit
        unit = _generate_exporter_systemd_unit("postgres_exporter", 9187, env_file="/etc/default/postgres_exporter")
        assert "EnvironmentFile=/etc/default/postgres_exporter" in unit
        assert ":9187" in unit

    def test_check_exporter_release_unknown_type(self):
        from apps.exporters import check_exporter_release
        version, err = check_exporter_release("unknown_exporter")
        assert version is None
        assert "Unknown exporter type" in err

    def test_detect_exporter_version_unknown_type(self, app):
        from apps.exporters import detect_exporter_version
        with app.app_context():
            guest = _create_guest(app, name="exp-ver-test", ip="10.0.0.63")
            version, err = detect_exporter_version(guest, "unknown_exporter")
            assert version is None
            assert "Unknown exporter type" in err

            db.session.delete(guest)
            db.session.commit()

    def test_detect_exporter_version_no_credential(self, app):
        from apps.exporters import detect_exporter_version
        with app.app_context():
            guest = _create_guest(app, name="exp-nocred-test", ip="10.0.0.64")
            version, err = detect_exporter_version(guest, "node_exporter")
            assert version is None
            assert "credential" in err.lower()

            db.session.delete(guest)
            db.session.commit()


# ---------------------------------------------------------------------------
# Prometheus YML generation tests
# ---------------------------------------------------------------------------

class TestPrometheusYmlGeneration:

    def test_yml_without_extra_configs(self):
        from apps.prometheus_app import _generate_prometheus_yml
        yml = _generate_prometheus_yml("10.0.0.10:5000")
        assert 'job_name: "prometheus"' in yml
        assert 'job_name: "lambnet"' in yml
        assert "10.0.0.10:5000" in yml

    def test_yml_with_extra_configs(self):
        from apps.prometheus_app import _generate_prometheus_yml
        extra = """

  - job_name: "node"
    static_configs:
      - targets: ["10.0.0.50:9100"]"""
        yml = _generate_prometheus_yml("10.0.0.10:5000", extra_scrape_configs=extra)
        assert 'job_name: "node"' in yml
        assert "10.0.0.50:9100" in yml

    def test_yml_with_auth_token(self):
        from apps.prometheus_app import _generate_prometheus_yml
        yml = _generate_prometheus_yml("10.0.0.10:5000", auth_token="secret123")
        assert "Bearer" in yml
        assert "secret123" in yml

    def test_yml_without_lambnet_url(self):
        from apps.prometheus_app import _generate_prometheus_yml
        yml = _generate_prometheus_yml("")
        assert 'job_name: "prometheus"' in yml
        assert "lambnet" not in yml


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------

class TestExporterRoutes:

    def test_exporters_list_requires_auth(self, client):
        resp = client.get("/prometheus/exporters")
        assert resp.status_code in (302, 401)

    def test_exporters_list(self, auth_client):
        resp = auth_client.get("/prometheus/exporters")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "exporters" in data

    def test_exporter_add_invalid_type(self, auth_client):
        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": "1",
            "exporter_type": "invalid_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_exporter_add_missing_guest(self, auth_client):
        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": "",
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_exporter_add_success(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-add", ip="10.0.0.70")
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.filter_by(guest_id=guest_id).first()
            assert exp is not None
            assert exp.exporter_type == "node_exporter"
            assert exp.port == 9100
            assert exp.status == "pending"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_add_duplicate(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-dup", ip="10.0.0.71")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            count = ExporterInstance.query.filter_by(
                guest_id=guest_id, exporter_type="node_exporter"
            ).count()
            assert count == 1

            for e in ExporterInstance.query.filter_by(guest_id=guest_id).all():
                db.session.delete(e)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_delete_pending(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-del", ip="10.0.0.72")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/delete", follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            assert ExporterInstance.query.get(exp_id) is None
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
                db.session.commit()

    def test_exporter_delete_installed_blocked(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-deli", ip="10.0.0.73")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="installed",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/delete", follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            # Should NOT be deleted
            assert ExporterInstance.query.get(exp_id) is not None

            for e in ExporterInstance.query.filter_by(guest_id=guest_id).all():
                db.session.delete(e)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_install_status(self, auth_client):
        resp = auth_client.get("/prometheus/exporters/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "log" in data

    def test_exporter_uninstall_status(self, auth_client):
        resp = auth_client.get("/prometheus/exporters/uninstall/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "log" in data

    def test_exporter_install_conflict(self, auth_client, app):
        """Test that install returns 409 when another operation is running."""
        from routes import prometheus_app as route_mod
        with app.app_context():
            guest = _create_guest(app, name="exp-route-conflict", ip="10.0.0.74")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        route_mod._exporter_install_job["running"] = True
        try:
            resp = auth_client.post(f"/prometheus/exporters/{exp_id}/install")
            assert resp.status_code == 409
        finally:
            route_mod._exporter_install_job["running"] = False

        with app.app_context():
            for e in ExporterInstance.query.filter_by(guest_id=guest_id).all():
                db.session.delete(e)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_delete_not_found(self, auth_client):
        resp = auth_client.post("/prometheus/exporters/99999/delete")
        assert resp.status_code == 404

    def test_exporter_add_with_config(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-cfg", ip="10.0.0.80")
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "postgres_exporter",
            "port": "9187",
            "config_DATA_SOURCE_NAME": "postgresql://user:pass@localhost/db?sslmode=disable",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.filter_by(guest_id=guest_id).first()
            assert exp is not None
            assert exp.exporter_type == "postgres_exporter"
            assert exp.config is not None
            assert exp.config["DATA_SOURCE_NAME"] == "postgresql://user:pass@localhost/db?sslmode=disable"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_add_without_config(self, auth_client, app):
        """Exporters that don't require config should have config=None."""
        with app.app_context():
            guest = _create_guest(app, name="exp-route-nocfg", ip="10.0.0.81")
            guest_id = guest.id

        resp = auth_client.post("/prometheus/exporters/add", data={
            "guest_id": str(guest_id),
            "exporter_type": "node_exporter",
            "port": "9100",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.filter_by(guest_id=guest_id).first()
            assert exp is not None
            assert exp.config is None

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_update_config(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-ucfg", ip="10.0.0.82")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="redis_exporter",
                port=9121,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/config", data={
            "config_REDIS_ADDR": "redis://localhost:6379",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.get(exp_id)
            assert exp.config is not None
            assert exp.config["REDIS_ADDR"] == "redis://localhost:6379"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_update_config_installed_blocked(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-ucfgi", ip="10.0.0.83")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="postgres_exporter",
                port=9187,
                status="installed",
                config={"DATA_SOURCE_NAME": "old"},
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/config", data={
            "config_DATA_SOURCE_NAME": "new",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            exp = ExporterInstance.query.get(exp_id)
            # Config should NOT be changed
            assert exp.config["DATA_SOURCE_NAME"] == "old"

            db.session.delete(exp)
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()

    def test_exporter_update_config_no_config_required(self, auth_client, app):
        with app.app_context():
            guest = _create_guest(app, name="exp-route-ucfgn", ip="10.0.0.84")
            exp = ExporterInstance(
                guest_id=guest.id,
                exporter_type="node_exporter",
                port=9100,
                status="pending",
            )
            db.session.add(exp)
            db.session.commit()
            exp_id = exp.id
            guest_id = guest.id

        resp = auth_client.post(f"/prometheus/exporters/{exp_id}/config", data={}, follow_redirects=False)
        assert resp.status_code in (302, 303)

        with app.app_context():
            db.session.delete(ExporterInstance.query.get(exp_id))
            guest = Guest.query.get(guest_id)
            if guest:
                db.session.delete(guest)
            db.session.commit()
