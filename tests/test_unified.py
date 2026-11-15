import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import pytest
from starlette.websockets import WebSocketDisconnect
from api.settings import DATA_ROOT,ROOT
from api.encryption import PLAIN,ENCRYPTED
from web_scanner.requester import resolve_target,TargetDenied


def test_file_round_trip_audit_and_traversal(client,auth):
    original=b'Fictional integration sample\x00\xff\n'
    assert client.get('/api/encryption/files').status_code==401
    for name in ['../outside.txt','/tmp/escape.txt','..\\escape.txt']:
        assert client.post('/api/encryption/upload',headers=auth,files={'file':(name,original)}).status_code==400
    response=client.post('/api/encryption/upload',headers=auth,files={'file':('proof.txt',original)})
    assert response.status_code==200
    digest=hashlib.sha256(original).hexdigest()
    assert response.json()['sha256']==digest
    assert client.post('/api/encryption/upload',headers=auth,files={'file':('proof.txt',b'overwrite')}).status_code==409
    assert client.post('/api/encryption/encrypt',headers=auth,data={'filename':'proof.txt'}).status_code==200
    assert not (PLAIN/'proof.txt').exists()
    assert (ENCRYPTED/'proof.txt.enc').read_bytes()!=original
    assert client.post('/api/encryption/decrypt',headers=auth,data={'filename':'proof.txt.enc'}).json()['sha256']==digest
    assert (PLAIN/'proof.txt').read_bytes()==original
    assert (ENCRYPTED/'proof.txt.enc').exists()
    for route in ['preview','download']:
        assert client.get(f'/api/encryption/{route}',headers=auth,params={'type':'sensitive','filename':'../security.db'}).status_code==400
    outside=DATA_ROOT/'outside.txt';outside.write_text('outside fixture')
    (PLAIN/'link.txt').symlink_to(outside)
    assert client.get('/api/encryption/download',headers=auth,params={'type':'sensitive','filename':'link.txt'}).status_code==400
    (PLAIN/'link.txt').unlink()
    audit=client.get('/api/alerts/audit-logs',headers=auth).json()
    assert audit['is_valid'] is True
    assert {'upload_file','encrypt_file','decrypt_file'} <= {row['action'] for row in audit['logs']}


def test_tampering_does_not_restore_plaintext(client,auth):
    client.post('/api/encryption/upload',headers=auth,files={'file':('tamper.txt',b'fixture')})
    client.post('/api/encryption/encrypt',headers=auth,data={'filename':'tamper.txt'})
    path=ENCRYPTED/'tamper.txt.enc';content=bytearray(path.read_bytes());content[-1]^=1;path.write_bytes(content)
    assert client.post('/api/encryption/decrypt',headers=auth,data={'filename':'tamper.txt.enc'}).status_code==422
    assert not (PLAIN/'tamper.txt').exists()


def test_worker_and_socket_authentication(client,auth):
    payload={'timestamp':'2026-11-15T12:00:00Z','alert_type':'Probe','source_ip':'sample-source','destination_ip':'sample-target'}
    assert client.post('/api/alerts/broadcast',json=payload).status_code==403
    assert client.post('/api/alerts/broadcast',json=payload,headers=auth).status_code==403
    assert client.post('/api/alerts/broadcast',json=payload,headers={'X-Worker-Token':os.environ['WORKER_TOKEN']}).status_code==200
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/api/ws/alerts') as ws:
            ws.send_json({'token':'invalid'});ws.receive_json()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/api/ws/alerts') as ws:
            ws.send_json([]); ws.receive_json()
    token=auth['Authorization'].removeprefix('Bearer ')
    with client.websocket_connect('/api/ws/alerts') as ws:
        ws.send_json({'token':token})
        assert ws.receive_json()['type']=='ready'
        assert client.post('/api/alerts/broadcast',json=payload,headers={'X-Worker-Token':os.environ['WORKER_TOKEN']}).status_code==200
        assert ws.receive_json()['data']['origin']=='sensor'


def test_existing_model_prediction_persists_a_real_result(client,auth):
    status=client.get('/api/detector/status',headers=auth).json()
    assert status['available'],status
    assert status['model_type']=='XGBClassifier'
    sample=client.get('/api/detector/sample',headers=auth).json()
    result=client.post('/api/detector/predict',headers=auth,json={'features':sample['features']})
    assert result.status_code==200,result.text
    event=client.get('/api/alerts/threat-alerts',headers=auth).json()[0]
    assert event['origin']=='model-replay'
    assert event['alert_type']==result.json()['label']
    assert client.post('/api/detector/predict',headers=auth,json={'features':{}}).status_code==422
    incomplete = dict(sample['features']); incomplete.pop('src_bytes')
    assert client.post('/api/detector/predict',headers=auth,json={'features':incomplete}).status_code==422


def test_website_scan_is_authenticated_scoped_saved_and_audited(client,auth):
    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(b'<html><body>Local owned test fixture</body></html>')
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Fixture)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        target=f'http://127.0.0.1:{server.server_port}'
        assert client.post('/api/scans/run',json={'url':target,'authorized':True}).status_code==401
        assert client.post('/api/scans/run',headers=auth,json={'url':target}).status_code==422
        assert client.post('/api/scans/run',headers=auth,json={'url':'http://169.254.169.254','authorized':True}).status_code==400
        result=client.post('/api/scans/run',headers=auth,json={'url':target,'authorized':True})
        assert result.status_code==200,result.text
        assert result.json()['findings']
        assert result.json()['target']==target
        assert client.get('/api/scans',headers=auth).json()[0]['id']==result.json()['id']
        assert 'website_scan' in {row['action'] for row in client.get('/api/alerts/audit-logs',headers=auth).json()['logs']}
        viewer=client.post('/api/auth/login',data={'username':'viewer','password':'fixture-password'}).json()['access_token']
        assert client.post('/api/scans/run',headers={'Authorization':f'Bearer {viewer}'},json={'url':target,'authorized':True}).status_code==403
    finally: server.shutdown();server.server_close();thread.join()


def test_scope_rejects_private_targets_even_when_allowlisted(monkeypatch):
    monkeypatch.setenv('SCAN_ALLOWED_HOSTS','169.254.169.254,10.0.0.1,224.0.0.1,8.8.8.8')
    for target in ['http://169.254.169.254','http://10.0.0.1','http://224.0.0.1','http://8.8.8.8:8181']:
        with pytest.raises(TargetDenied):resolve_target(target)


def test_redirect_cannot_escape_to_a_private_address(monkeypatch):
    from web_scanner.requester import fetch
    monkeypatch.setenv('SCAN_ALLOWED_HOSTS','127.0.0.1,169.254.169.254')
    class RedirectFixture(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302); self.send_header('Location','http://169.254.169.254/latest/meta-data'); self.end_headers()
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),RedirectFixture)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        with pytest.raises(TargetDenied): fetch(f'http://127.0.0.1:{server.server_port}')
    finally: server.shutdown();server.server_close();thread.join()


@pytest.mark.parametrize('simulated', [True, False])
def test_sensor_labels_origin_and_emits_one_alert_without_encryption(monkeypatch,simulated):
    import sys
    import numpy as np
    sys.path.insert(0,str(ROOT/'legacy'))
    import network_monitor as sensor
    class IntrusionModel:
        def predict(self, values): return np.array([1])
    monkeypatch.setattr(sensor,'model',IntrusionModel())
    monkeypatch.setenv('IDS_AUTO_ENCRYPT','true' if simulated else 'false')
    emitted=[]
    monkeypatch.setattr(sensor.socketio,'emit',lambda event,data:emitted.append((event,data)))
    def forbidden(*args,**kwargs): raise AssertionError('Sample processing must not encrypt files')
    monkeypatch.setattr(sensor.aes_encryptor,'encrypt_directory',forbidden)
    features=json.loads((ROOT/'examples/connection.json').read_text())['features']
    features.update(src_ip='test-source',dst_ip='test-destination')
    sensor.process_features(features,simulated=simulated)
    assert len(emitted)==1
    assert emitted[0][1]['origin']==('sensor-simulation' if simulated else 'sensor')
    assert emitted[0][1]['source_ip']=='test-source'
