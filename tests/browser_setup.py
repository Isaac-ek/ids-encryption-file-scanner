"""Provision two isolated fictional customers for browser checks only."""
import os, runpy
from pathlib import Path
root = Path(__file__).resolve().parents[1]
runpy.run_path(str(root / "scripts/create_admin.py"), run_name="__main__")
os.environ.update(BOOTSTRAP_USERNAME="other-customer", BOOTSTRAP_PASSWORD="isolated-other-password", BOOTSTRAP_WORKSPACE="other-customer", BOOTSTRAP_WORKSPACE_NAME="Other customer workspace")
runpy.run_path(str(root / "scripts/create_admin.py"), run_name="__main__")

# An isolated account/link for real browser -> API -> database recovery tests.
from api.database import SessionLocal
from api.models import DBUser, DBPasswordReset
from api.recovery import recovery_stamp
from werkzeug.security import generate_password_hash
import hashlib, time
with SessionLocal() as db:
    user = DBUser(username="reset-fixture", name="Recovery fixture", workspace_id=1, role="user", email="fixture@example.com", password=generate_password_hash("isolated-old-password"))
    db.add(user); db.flush()
    token = "isolated-browser-reset-token-never-for-production-123456"
    db.add(DBPasswordReset(token_hash=hashlib.sha256(token.encode()).hexdigest(),user_id=user.id,workspace_id=1,auth_stamp=recovery_stamp(user),expires_at=int(time.time())+1200))
    db.commit()
