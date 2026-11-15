"""Create a local administrator without an open first-run signup endpoint."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from werkzeug.security import generate_password_hash
from api.database import Base, engine, SessionLocal
from api.models import DBUser, DBScanRun, DBRule, DBAuditLog, DBThreatAlert

if __name__ == "__main__":
    password = os.environ.get("BOOTSTRAP_PASSWORD", "")
    username = os.environ.get("BOOTSTRAP_USERNAME", "admin")
    if len(password) < 12:
        raise SystemExit("Set BOOTSTRAP_PASSWORD to at least 12 characters")
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.query(DBUser).filter(DBUser.username == username).first():
            raise SystemExit("User already exists; no changes made")
        db.add(DBUser(username=username, name="Security operator", password=generate_password_hash(password), role="admin"))
        db.commit()
    print("Administrator created")
