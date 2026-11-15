"""Operator-only: bind a new sensor token to exactly one customer workspace."""
import argparse, hashlib, secrets, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.database import SessionLocal
from api.models import DBWorkspace
from api import tenancy
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()
    with SessionLocal() as db:
        workspace = db.query(DBWorkspace).filter(DBWorkspace.slug == args.workspace).first()
        if not workspace:
            raise SystemExit("Workspace not found; provision its administrator first")
        token = secrets.token_urlsafe(48)
        workspace.worker_token_hash = hashlib.sha256(token.encode()).hexdigest()
        db.commit()
    print(token)  # Intentionally shown once to the operator; only the hash is stored.
