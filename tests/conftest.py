import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
TEST_ROOT=tempfile.TemporaryDirectory(prefix='securestream-test-')
os.environ['SECURITY_DATA_DIR']=TEST_ROOT.name
os.environ['DATABASE_URL']=f"sqlite:///{TEST_ROOT.name}/test.db"
os.environ['JWT_SECRET']='isolated-test-signing-secret-not-for-production-12345'
os.environ['WORKER_TOKEN']='isolated-test-worker-secret-not-for-production-12345'
os.environ['SCAN_ALLOWED_HOSTS']='127.0.0.1'
os.environ['SCAN_ALLOW_LOCALHOST']='true'

import pytest
from fastapi.testclient import TestClient
from werkzeug.security import generate_password_hash
from api.main import app
from api.database import Base,engine,SessionLocal
from api.models import DBUser

@pytest.fixture
def client():
    Base.metadata.drop_all(engine);Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add_all([DBUser(username='owner',name='Test owner',password=generate_password_hash('fixture-password'),role='admin'),DBUser(username='viewer',name='Test viewer',password=generate_password_hash('fixture-password'),role='user')]);db.commit()
    with TestClient(app) as client: yield client

@pytest.fixture
def auth(client):
    token=client.post('/api/auth/login',data={'username':'owner','password':'fixture-password'}).json()['access_token']
    return {'Authorization':f'Bearer {token}'}
