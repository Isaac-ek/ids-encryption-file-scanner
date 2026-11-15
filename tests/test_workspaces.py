import hashlib
import json
import pytest
from werkzeug.security import generate_password_hash
from api.database import SessionLocal
from api.models import DBWorkspace, DBUser, DBRule, DBThreatAlert, DBScanRun, DBFileCheck
from api.auth import create_access_token, decode_access_token
from api.tenancy import storage_root
from api.websocket_manager import ConnectionManager
from api import file_checks

TOKEN = "second-customer-sensor-token-with-at-least-32-characters"


def customer(client):
    with SessionLocal() as db:
        db.add(DBWorkspace(id=2, slug="customer-two", name="Customer Two", worker_token_hash=hashlib.sha256(TOKEN.encode()).hexdigest()))
        db.add(DBUser(username="second-owner", name="Second owner", role="admin", workspace_id=2, password=generate_password_hash("second-owner-password")))
        db.commit()
    result = client.post("/api/auth/login", data={"username": "second-owner", "password": "second-owner-password"}).json()
    return {"Authorization": "Bearer " + result["access_token"]}


def test_customer_lists_totals_exports_and_audit_are_isolated(client, auth, monkeypatch):
    other = customer(client)
    monkeypatch.setattr(file_checks.shutil, "which", lambda name: None)
    with SessionLocal() as db:
        db.add_all([DBThreatAlert(workspace_id=2, timestamp="2026-11-15T12:00:00Z", alert_type="Probe", origin="sensor", source_ip="private-other-source", destination_ip="other-target"),
                    DBScanRun(workspace_id=2, target="https://other.invalid", requested_by="second-owner", created_at="today", status="completed", findings_json="[]")]); db.commit()
    check = client.post("/api/file-checks/run", headers=other, files={"file": ("other-private-file.txt", b"fixture")}).json()
    rule = client.post("/api/alerts/rules", headers=other, json={"name": "Other private rule", "type": "ip", "value": "192.0.2.9"}).json()
    for path in ["/api/alerts/rules", "/api/alerts/threat-alerts", "/api/scans", "/api/file-checks"]:
        assert client.get(path, headers=auth).json() == []
        assert len(client.get(path, headers=other).json()) == 1
    assert client.get("/api/workspace/events", headers=auth).json()["total"] == 0
    summary = client.get("/api/workspace/overview", headers=auth).json()
    assert summary["total_events"] == summary["website_checks"] == summary["file_checks"] == 0
    assert client.get("/api/workspace/overview", headers=other).json()["total_events"] == 1
    assert "private-other-source" not in client.get("/api/workspace/events/export", headers=auth).text
    assert "private-other-source" in client.get("/api/workspace/events/export", headers=other).text
    assert [row["username"] for row in client.get("/api/auth/users", headers=other).json()] == ["second-owner"]
    assert "second-owner" not in client.get("/api/auth/users", headers=auth).text
    assert client.put("/api/auth/users/second-owner", headers=auth, json={"name": "hijack"}).status_code == 404
    assert client.delete("/api/auth/users/second-owner", headers=auth).status_code == 404
    body = {"name": "hijack", "type": "ip", "value": "other"}
    assert client.put(f"/api/alerts/rules/{rule['id']}", headers=auth, json=body).status_code == 404
    assert client.delete(f"/api/alerts/rules/{rule['id']}", headers=auth).status_code == 404
    audit = client.get("/api/alerts/audit-logs", headers=other).json()
    assert audit["is_valid"] and len(audit["logs"]) == 2
    assert client.get("/api/alerts/audit-logs", headers=auth).json()["logs"] == []
    assert client.get("/api/auth/me", headers=other).json()["workspace_name"] == "Customer Two"
    # Neither JSON fields nor forged signed claims may change the bound account workspace.
    created = client.post("/api/auth/users", headers=other, json={"username": "second-member", "name": "Member", "role": "user", "password": "second-member-password", "workspace_id": 1})
    assert created.json()["workspace_id"] == 2
    payload = decode_access_token(other["Authorization"].split()[1]); payload["workspace_id"] = 1
    forged = {"Authorization": "Bearer " + create_access_token(payload)}
    assert client.get("/api/auth/me", headers=forged).status_code == 401


def test_same_filenames_have_separate_storage_and_encryption_keys(client, auth):
    other = customer(client)
    name = "customer-isolation.txt"
    for headers, content in [(auth, b"first private bytes"), (other, b"second private bytes")]:
        assert client.post("/api/encryption/upload", headers=headers, files={"file": (name, content)}).status_code == 200
        assert client.post("/api/encryption/encrypt", headers=headers, data={"filename": name}).status_code == 200
        assert client.post("/api/encryption/decrypt", headers=headers, data={"filename": name+".enc"}).status_code == 200
        assert client.get("/api/encryption/download", headers=headers, params={"type": "sensitive", "filename": name}).content == content
    assert storage_root(1) != storage_root(2)
    # Moving a customer's ciphertext into another storage root cannot decrypt it.
    foreign = (storage_root(2)/"encrypted"/(name+".enc")).read_bytes()
    (storage_root(1)/"encrypted"/"foreign-copy.enc").write_bytes(foreign)
    assert client.post("/api/encryption/decrypt", headers=auth, data={"filename": "foreign-copy.enc"}).status_code == 422
    assert not (storage_root(1)/"files"/"foreign-copy").exists()


def test_worker_tokens_bind_to_customer_and_ignore_spoofed_workspace(client, auth):
    other = customer(client)
    body = {"timestamp": "2026-11-15T12:00:00Z", "alert_type": "Probe", "source_ip": "sensor", "destination_ip": "target", "workspace_id": 1}
    assert client.post("/api/alerts/broadcast", headers={"X-Worker-Token": TOKEN}, json=body).status_code == 200
    assert client.get("/api/workspace/events", headers=auth).json()["total"] == 0
    assert client.get("/api/workspace/events", headers=other).json()["total"] == 1
    assert client.post("/api/alerts/broadcast", headers={"X-Worker-Token": "x"*48}, json=body).status_code == 403


def test_websocket_fanout_only_delivers_to_matching_customer():
    class Socket:
        def __init__(self): self.messages = []
        async def send_json(self, message): self.messages.append(message)
    manager = ConnectionManager(); first = Socket(); second = Socket()
    manager.register(first, 1); manager.register(second, 2)
    import asyncio
    asyncio.run(manager.broadcast({"private": "second"}, workspace_id=2))
    assert first.messages == [] and second.messages == [{"private": "second"}]
    manager.disconnect(second)
    assert second not in manager.workspaces


def test_customer_cannot_use_another_customers_scan_allowlist(client, auth, monkeypatch):
    other = customer(client)
    monkeypatch.setenv("SCAN_ALLOWED_HOSTS", "127.0.0.1")
    response = client.post("/api/scans/run", headers=other, json={"url":"http://127.0.0.1", "authorized":True})
    assert response.status_code == 400 and "hostname" in response.json()["detail"]


def test_orm_scope_rejects_cross_customer_writes(client):
    customer(client)
    with SessionLocal() as db:
        db.info["workspace_id"] = 2
        db.add(DBRule(workspace_id=1, name="spoof", type="ip", value="bad"))
        with pytest.raises(ValueError, match="Cross-workspace"):
            db.commit()
        db.rollback()


def test_new_customer_audit_tampering_does_not_invalidate_another_chain(client, auth):
    other = customer(client)
    client.post("/api/alerts/rules", headers=other, json={"name":"Audited", "type":"ip", "value":"example"})
    from api.models import DBAuditLog
    with SessionLocal() as db:
        row = db.query(DBAuditLog).filter(DBAuditLog.workspace_id == 2).first()
        row.details = "tampered"; db.commit()
    assert not client.get("/api/alerts/audit-logs", headers=other).json()["is_valid"]
    assert client.get("/api/alerts/audit-logs", headers=auth).json()["is_valid"]


def test_additive_migration_preserves_existing_user_and_is_idempotent(tmp_path):
    from sqlalchemy import create_engine, text, inspect
    from api.tenancy import initialize_database
    from api.database import Base
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR, name VARCHAR, password VARCHAR, role VARCHAR)"))
        connection.execute(text("INSERT INTO users VALUES (1,'existing','Existing','preserved-hash','admin')"))
    initialize_database(engine, Base); initialize_database(engine, Base)
    with engine.connect() as connection:
        row = connection.execute(text("SELECT username, password, workspace_id FROM users")).one()
        assert tuple(row) == ("existing", "preserved-hash", 1)
        assert connection.execute(text("SELECT COUNT(*) FROM workspaces")).scalar() == 1
    engine.dispose()
