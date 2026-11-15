import pytest
from api.scans import normalize_scope_host
from tests.test_workspaces import customer


def test_admin_can_approve_websites_and_members_cannot_change_scope(client, auth):
    response=client.put('/api/scans/scope',headers=auth,json={'hostnames':['https://EXAMPLE.COM/path','www.example.com','example.com.'],'authorized':True})
    assert response.status_code==200
    assert response.json()['hostnames']==['example.com','www.example.com']
    assert client.get('/api/scans/scope',headers=auth).json()['hostnames']==['example.com','www.example.com']
    token=client.post('/api/auth/login',data={'username':'viewer','password':'fixture-password'}).json()['access_token']
    member={'Authorization':'Bearer '+token}
    assert client.get('/api/scans/scope',headers=member).status_code==200
    assert client.put('/api/scans/scope',headers=member,json={'hostnames':[],'authorized':True}).status_code==403
    assert client.put('/api/scans/scope',headers=auth,json={'hostnames':['example.org']}).status_code==422
    assert client.get('/api/scans/scope').status_code==401
    audit=client.get('/api/alerts/audit-logs',headers=auth).json()
    assert audit['is_valid'] and audit['logs'][0]['action']=='update_scan_scope'


def test_scope_changes_only_apply_to_current_customer(client, auth):
    other=customer(client)
    assert client.put('/api/scans/scope',headers=other,json={'hostnames':['other.example'],'authorized':True}).status_code==200
    assert client.get('/api/scans/scope',headers=auth).json()['hostnames']==[]
    assert client.get('/api/scans/scope',headers=other).json()['effective_hostnames']==['other.example']
    assert client.put('/api/scans/scope',headers=auth,json={'hostnames':['mine.example'],'authorized':True}).status_code==200
    assert client.get('/api/scans/scope',headers=other).json()['hostnames']==['other.example']


@pytest.mark.parametrize('value',['*.example.com','https://user:pass@example.com','https://example.com:8080','169.254.169.254','10.0.0.1','224.0.0.1','[::1]','http://','https://bad_host.example'])
def test_invalid_or_internal_scope_is_rejected(value, monkeypatch):
    monkeypatch.setenv('SCAN_ALLOW_LOCALHOST','false')
    from fastapi import HTTPException
    with pytest.raises(HTTPException): normalize_scope_host(value)


def test_approving_a_hostname_keeps_dns_private_address_checks(client, auth, monkeypatch):
    assert client.put('/api/scans/scope',headers=auth,json={'hostnames':['private.example'],'authorized':True}).status_code==200
    import web_scanner.requester as requester
    monkeypatch.setattr(requester.socket,'getaddrinfo',lambda *args,**kwargs:[(2,1,6,'',('10.0.0.2',443))])
    response=client.post('/api/scans/run',headers=auth,json={'url':'https://private.example','authorized':True})
    assert response.status_code==400 and 'Private' in response.json()['detail']
