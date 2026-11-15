"""Durable-file contract: transaction rollback, isolation, tamper and key handling."""
import base64
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.database import SessionLocal, engine
from api.models import DBStoredFile, DBWorkspaceKey
from tests.test_workspaces import customer


@pytest.fixture
def cloud(client, monkeypatch):
    monkeypatch.setenv("KEY_ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    from api.cloud_files import router
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as result:
        yield result


def test_durable_roundtrip_survives_new_connections_and_is_at_rest_encrypted(cloud, auth, client):
    content = b"private-customer-document-unique-fixture"
    assert cloud.post('/api/encryption/upload', headers=auth, files={'file': ('note.txt', content)}).status_code == 200
    with SessionLocal() as db:
        row = db.query(DBStoredFile).one()
        assert content not in row.payload
        assert len(db.query(DBWorkspaceKey).one().wrapped_key) == 60
    engine.dispose()
    assert cloud.get('/api/encryption/download', headers=auth, params={'type':'sensitive','filename':'note.txt'}).content == content
    assert cloud.post('/api/encryption/encrypt', headers=auth, data={'filename':'note.txt'}).status_code == 200
    assert cloud.get('/api/encryption/files', headers=auth).json()['sensitive_files'] == []
    assert cloud.post('/api/encryption/decrypt', headers=auth, data={'filename':'note.txt.enc'}).status_code == 200
    assert cloud.get('/api/encryption/download', headers=auth, params={'type':'sensitive','filename':'note.txt'}).content == content
    assert cloud.post('/api/encryption/decrypt', headers=auth, data={'filename':'note.txt.enc'}).status_code == 409
    assert client.get('/api/alerts/audit-logs', headers=auth).json()['is_valid']


def test_cloud_files_and_keys_are_isolated_even_with_same_names(cloud, auth, client):
    other = customer(client)
    for headers, content in [(auth,b'first'),(other,b'second')]:
        assert cloud.post('/api/encryption/upload', headers=headers, files={'file':('same.txt',content)}).status_code == 200
        assert cloud.post('/api/encryption/encrypt', headers=headers, data={'filename':'same.txt'}).status_code == 200
    with SessionLocal() as db:
        keys = db.query(DBWorkspaceKey).all()
        assert len(keys) == 2 and keys[0].wrapped_key != keys[1].wrapped_key
        first = db.query(DBStoredFile).filter_by(workspace_id=1).one()
        second = db.query(DBStoredFile).filter_by(workspace_id=2).one()
        first.payload = second.payload
        db.commit()
    assert cloud.post('/api/encryption/decrypt',headers=auth,data={'filename':'same.txt.enc'}).status_code == 422
    assert cloud.post('/api/encryption/decrypt',headers=other,data={'filename':'same.txt.enc'}).status_code == 200
    assert cloud.get('/api/encryption/download', headers=other, params={'type':'sensitive','filename':'same.txt'}).content == b'second'
    assert cloud.get('/api/encryption/download', headers=auth, params={'type':'sensitive','filename':'same.txt'}).status_code == 404


def test_cloud_failed_replacement_rolls_back_original_and_audit(cloud, auth, client, monkeypatch):
    from api import cloud_files
    assert cloud.post('/api/encryption/upload', headers=auth, files={'file':('source.txt',b'keep me')}).status_code == 200
    logs = len(client.get('/api/alerts/audit-logs',headers=auth).json()['logs'])
    monkeypatch.setattr(cloud_files,'MAX_WORKSPACE_BYTES',1)
    assert cloud.post('/api/encryption/encrypt', headers=auth, data={'filename':'source.txt'}).status_code == 413
    assert cloud.get('/api/encryption/download',headers=auth,params={'type':'sensitive','filename':'source.txt'}).content == b'keep me'
    assert cloud.get('/api/encryption/files',headers=auth).json()['encrypted_files'] == []
    assert len(client.get('/api/alerts/audit-logs',headers=auth).json()['logs']) == logs


def test_cloud_upload_limits_names_and_wrong_wrapping_key_fail_closed(cloud, auth, monkeypatch):
    from api import cloud_files
    assert cloud.post('/api/encryption/upload',headers=auth,files={'file':('../bad',b'bad')}).status_code == 400
    monkeypatch.setattr(cloud_files,'MAX_UPLOAD_BYTES',4)
    assert cloud.post('/api/encryption/upload',headers=auth,files={'file':('large',b'12345')}).status_code == 413
    assert cloud.post('/api/encryption/upload',headers=auth,files={'file':('ok',b'1234')}).status_code == 200
    assert cloud.post('/api/encryption/upload',headers=auth,files={'file':('ok',b'new')}).status_code == 409
    monkeypatch.setenv('KEY_ENCRYPTION_KEY',base64.urlsafe_b64encode(os.urandom(32)).decode())
    assert cloud.get('/api/encryption/download',headers=auth,params={'type':'sensitive','filename':'ok'}).status_code == 503
