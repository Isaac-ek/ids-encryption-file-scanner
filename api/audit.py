import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from api.models import DBAuditLog
from sqlalchemy import text
import threading
audit_lock = threading.RLock()

def log_audit(db: Session, admin: Optional[str], action: str, target_user: Optional[str], details: Optional[dict] = None) -> DBAuditLog:
    with audit_lock:
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(8372601)"))
        # Get last entry from database to get its hash
        last_entry = db.query(DBAuditLog).order_by(DBAuditLog.id.desc()).first()
        prev_hash = last_entry.entry_hash if last_entry else '0'

        timestamp = datetime.now(timezone.utc).isoformat()
        details_str = json.dumps(details or {}, sort_keys=True)

        # Prepare data for hashing (excluding id and entry_hash)
        entry_dict = {
            'timestamp': timestamp,
            'admin': admin,
            'action': action,
            'target_user': target_user,
            'details': details_str,
            'prev_hash': prev_hash
        }

        if db.info.get("workspace_id", 1) != 1:
            entry_dict["workspace_id"] = db.info["workspace_id"]
        entry_str = json.dumps(entry_dict, sort_keys=True)
        entry_hash = hashlib.sha256((entry_str + prev_hash).encode('utf-8')).hexdigest()

        db_log = DBAuditLog(
            timestamp=timestamp,
            admin=admin,
            action=action,
            target_user=target_user,
            details=details_str,
            prev_hash=prev_hash,
            entry_hash=entry_hash
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)

        # Optional: we can emit the alert via WebSockets here if needed
        return db_log

def verify_audit_log(db: Session) -> Tuple[bool, Optional[int]]:
    """
    Verifies the integrity of the audit log in the database.
    Returns (is_valid, tamper_index_id)
    """
    entries = db.query(DBAuditLog).order_by(DBAuditLog.id.asc()).all()
    prev_hash = '0'
    for entry in entries:
        entry_dict = {
            'timestamp': entry.timestamp,
            'admin': entry.admin,
            'action': entry.action,
            'target_user': entry.target_user,
            'details': entry.details,
            'prev_hash': entry.prev_hash
        }
        if entry.workspace_id != 1:
            entry_dict["workspace_id"] = entry.workspace_id
        entry_str = json.dumps(entry_dict, sort_keys=True)
        expected_hash = hashlib.sha256((entry_str + prev_hash).encode('utf-8')).hexdigest()

        if entry.entry_hash != expected_hash or entry.prev_hash != prev_hash:
            return False, entry.id
        prev_hash = entry.entry_hash
    return True, None
