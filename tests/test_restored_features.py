import hashlib
import json
import os
from types import SimpleNamespace
from api.settings import DATA_ROOT
from api import file_checks


def login(client, username, password):
    response = client.post('/api/auth/login', data={'username': username, 'password': password})
    assert response.status_code == 200, response.text
    return {'Authorization': 'Bearer ' + response.json()['access_token']}


def test_admin_can_provision_edit_reset_and_remove_member_accounts(client, auth):
    viewer = login(client, 'viewer', 'fixture-password')
    assert client.get('/api/auth/users', headers=viewer).status_code == 403
    body = {'username': 'new-member', 'name': 'New Member', 'role': 'user', 'password': 'initial-member-password'}
    assert client.post('/api/auth/users', headers=viewer, json=body).status_code == 403
    created = client.post('/api/auth/users', headers=auth, json=body)
    assert created.status_code == 200
    assert 'password' not in created.json()
    previous = login(client, 'new-member', body['password'])
    assert client.put('/api/auth/users/new-member', headers=auth, json={'name': 'Updated Member', 'role': 'admin', 'password': 'reset-member-password'}).status_code == 200
    assert client.get('/api/auth/me', headers=previous).status_code == 401
    updated = login(client, 'new-member', 'reset-member-password')
    assert client.get('/api/auth/users', headers=updated).status_code == 200
    assert client.put('/api/auth/users/owner', headers=auth, json={'role': 'user'}).status_code == 409
    assert client.delete('/api/auth/users/owner', headers=auth).status_code == 409
    assert client.post('/api/auth/users', headers=auth, json={**body, 'role': 'anything'}).status_code == 422
    assert client.post('/api/auth/users', headers=auth, json={**body, 'password': 'short'}).status_code == 422
    assert client.delete('/api/auth/users/new-member', headers=auth).status_code == 200
    assert client.get('/api/auth/me', headers=updated).status_code == 401
    audit = client.get('/api/alerts/audit-logs', headers=auth).json()
    assert audit['is_valid']
    assert {'add_user', 'edit_user', 'delete_user'} <= {entry['action'] for entry in audit['logs']}
    assert 'reset-member-password' not in json.dumps(audit)


def test_members_can_change_their_password_and_revoke_previous_sessions(client):
    previous = login(client, 'viewer', 'fixture-password')
    assert client.post('/api/auth/password', headers=previous, json={'current_password': 'wrong', 'new_password': 'new-member-password'}).status_code == 400
    response = client.post('/api/auth/password', headers=previous, json={'current_password': 'fixture-password', 'new_password': 'new-member-password'})
    assert response.status_code == 200
    new = {'Authorization': 'Bearer ' + response.json()['access_token']}
    assert client.get('/api/auth/me', headers=previous).status_code == 401
    assert client.get('/api/auth/me', headers=new).status_code == 200
    assert client.post('/api/auth/login', data={'username': 'viewer', 'password': 'fixture-password'}).status_code == 400
    login(client, 'viewer', 'new-member-password')


def test_event_filters_pagination_exports_and_real_totals(client, auth):
    worker = {'X-Worker-Token': os.environ['WORKER_TOKEN']}
    for index in range(3):
        response = client.post('/api/alerts/broadcast', headers=worker, json={'timestamp': '2026-11-15T12:00:00Z', 'alert_type': 'Probe' if index == 0 else 'DoS', 'origin': 'sensor' if index == 0 else 'sensor-simulation', 'source_ip': '=2+2' if index == 0 else 'fixture-source', 'destination_ip': 'fixture-target'})
        assert response.status_code == 200
    filtered = client.get('/api/workspace/events', headers=auth, params={'alert_type': 'Probe', 'date': '2026-11-15', 'src': '=2+2'}).json()
    assert filtered['total'] == 1 and filtered['items'][0]['alert_type'] == 'Probe'
    page = client.get('/api/workspace/events', headers=auth, params={'per_page': 2, 'page': 2}).json()
    assert page['total'] == 3 and len(page['items']) == 1
    csv = client.get('/api/workspace/events/export?format=csv&alert_type=Probe', headers=auth)
    assert csv.status_code == 200 and "'=2+2" in csv.text
    json_export = client.get('/api/workspace/events/export?format=json&origin=sensor-simulation', headers=auth).json()
    assert len(json_export) == 2
    assert client.get('/api/workspace/events/export').status_code == 401
    summary = client.get('/api/workspace/overview', headers=auth).json()
    assert summary['total_events'] == 3 and summary['origins']['sensor-simulation'] == 2


def test_file_checks_are_limited_without_av_and_empty_files_are_not_malware(client, auth, monkeypatch):
    monkeypatch.setattr(file_checks.shutil, 'which', lambda name: None)
    assert not client.get('/api/file-checks/status', headers=auth).json()['clamav_available']
    result = client.post('/api/file-checks/run', headers=auth, files={'file': ('../empty.txt', b'')})
    assert result.status_code == 200
    assert result.json()['filename'] == 'empty.txt'
    assert result.json()['status'] == 'limited'
    assert result.json()['sha256'] == hashlib.sha256(b'').hexdigest()
    assert client.get('/api/file-checks', headers=auth).json()[0]['id'] == result.json()['id']
    assert client.post('/api/file-checks/run', files={'file': ('fixture.txt', b'data')}).status_code == 401


def test_signature_and_pattern_findings_are_distinguished_and_audited(client, auth, monkeypatch):
    monkeypatch.setattr(file_checks.shutil, 'which', lambda name: None)
    eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    assert hashlib.md5(eicar).hexdigest() == file_checks.EICAR_MD5
    result = client.post('/api/file-checks/run', headers=auth, files={'file': ('eicar-test.txt', eicar)}).json()
    assert result['status'] == 'detected'
    review = client.post('/api/file-checks/run', headers=auth, files={'file': ('code-example.txt', b'eval(example)')}).json()
    assert review['status'] == 'review'
    audit = client.get('/api/alerts/audit-logs', headers=auth).json()
    assert audit['is_valid'] and 'file_check' in {entry['action'] for entry in audit['logs']}


def test_clamav_result_is_reported_and_temporary_upload_is_removed(client, auth, monkeypatch):
    monkeypatch.setattr(file_checks.shutil, 'which', lambda name: '/test/clamscan')
    seen = []
    def scan(args, **kwargs):
        from pathlib import Path
        path = Path(args[-1]); assert path.read_bytes() == b'fixture'
        seen.append(path)
        return SimpleNamespace(returncode=1, stdout='Fixture FOUND', stderr='')
    monkeypatch.setattr(file_checks.subprocess, 'run', scan)
    result = client.post('/api/file-checks/run', headers=auth, files={'file': ('fixture.txt', b'fixture')}).json()
    assert result['status'] == 'detected'
    assert seen and not seen[0].exists()
