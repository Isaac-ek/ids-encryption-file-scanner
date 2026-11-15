"""Create a local administrator without an open first-run signup endpoint."""
import os
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from werkzeug.security import generate_password_hash
from api.database import Base, engine, SessionLocal
from api.models import DBWorkspace, DBUser, DBScanRun, DBRule, DBAuditLog, DBThreatAlert

if __name__ == "__main__":
    password = os.environ.get("BOOTSTRAP_PASSWORD", "")
    username = os.environ.get("BOOTSTRAP_USERNAME", "admin")
    if len(password) < 12:
        raise SystemExit("Set BOOTSTRAP_PASSWORD to at least 12 characters")
    from api.tenancy import initialize_database
    initialize_database(engine, Base)
    with SessionLocal() as db:
        if db.query(DBUser).filter(DBUser.username == username).first():
            raise SystemExit("User already exists; no changes made")
        slug = os.getenv("BOOTSTRAP_WORKSPACE", "main")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", slug):
            raise SystemExit("Workspace slug must use lowercase letters, digits and hyphens")
        workspace = db.query(DBWorkspace).filter(DBWorkspace.slug == slug).first()
        if workspace is None:
            workspace = DBWorkspace(slug=slug, name=os.getenv("BOOTSTRAP_WORKSPACE_NAME", slug))
            db.add(workspace); db.flush()
        if os.getenv("BOOTSTRAP_SCAN_ALLOWED_HOSTS"):
            workspace.scan_allowed_hosts = os.environ["BOOTSTRAP_SCAN_ALLOWED_HOSTS"]
        db.add(DBUser(workspace_id=workspace.id,username=username, name="Security operator", password=generate_password_hash(password), role="admin"))
        db.commit()
    print("Administrator created")
