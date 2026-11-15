import json
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from api.auth import DBUser, require_admin, get_current_user
from api.database import get_db
from api.models import DBScanRun, DBWorkspace
from api.audit import log_audit
from web_scanner import scanner
from web_scanner.reporter import Reporter
from web_scanner.requester import resolve_target, budget, TargetDenied

router = APIRouter(prefix="/api/scans", tags=["Authorized website checks"])
scan_slot = threading.BoundedSemaphore(1)

class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    authorized: bool = False
    ports: bool = False
    paths: bool = False
    reflected_input: bool = False
    keywords: str = Field(default="", max_length=300)

def serialize(run):
    return {"id": run.id, "target": run.target, "requested_by": run.requested_by, "created_at": run.created_at, "status": run.status, "findings": json.loads(run.findings_json)}

@router.get("")
def history(db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    return [serialize(run) for run in db.query(DBScanRun).order_by(DBScanRun.id.desc()).limit(30)]

def _run_scan(payload: ScanRequest, db: Session, user: DBUser):
    if not payload.authorized: raise HTTPException(422, "Confirm you are authorized to check this target")
    try: target, address, port = resolve_target(payload.url)
    except (ValueError, OSError) as error: raise HTTPException(400, str(error))
    if not scan_slot.acquire(blocking=False): raise HTTPException(409, "Another scan is running; try again shortly")
    token = budget.set(time.monotonic() + 25)
    report = Reporter()
    try:
        scanner.analyze_headers(payload.url, report)
        scanner.check_cors(payload.url, report)
        scanner.check_open_redirect(payload.url, report)
        scanner.scan_sensitive_strings(payload.url, report, [x.strip() for x in payload.keywords.split(',') if x.strip()])
        scanner.scan_mixed_content(payload.url, report)
        if payload.paths: scanner.scan_common_paths(payload.url, report)
        if payload.reflected_input: scanner.test_xss(payload.url, report)
        if payload.ports:
            # Resolve and validate immediately before the TCP checks, then connect to that IP only.
            _, pinned_ip, _ = resolve_target(payload.url)
            report.info("TCP connection checks on nine common ports; not a complete port inventory")
            for checked_port in map(int, scanner.PORTS.split(',')):
                if time.monotonic() >= budget.get():
                    report.error("Scan time budget exhausted"); break
                try:
                    with socket.create_connection((pinned_ip, checked_port), timeout=.3):
                        report.warn(f"Port {checked_port}/tcp accepts connections")
                except OSError: pass
        if target.scheme == "https":
            try:
                _, pinned_ip, _ = resolve_target(payload.url)
                with socket.create_connection((pinned_ip, port), timeout=3) as raw:
                    with ssl.create_default_context().wrap_socket(raw, server_hostname=target.hostname) as secured:
                        cert = secured.getpeercert()
                        report.info(f"TLS {secured.version()}; certificate expiry {cert.get('notAfter', 'unavailable')}")
            except Exception as error: report.error(f"TLS verification failed: {type(error).__name__}")
        state = "completed_with_errors" if any(item["level"] == "error" for item in report.entries) else "completed"
        run = DBScanRun(target=payload.url, requested_by=user.username, created_at=datetime.now(timezone.utc).isoformat(), status=state, findings_json=json.dumps(report.entries))
        db.add(run); db.commit(); db.refresh(run)
        log_audit(db, user.username, "website_scan", None, {"scan_id": run.id, "target": payload.url, "status": state})
        return serialize(run)
    finally:
        budget.reset(token); scan_slot.release()


@router.post("/run")
def run_scan(payload: ScanRequest, db: Session = Depends(get_db), user: DBUser = Depends(require_admin)):
    from web_scanner.requester import allowed_hosts
    import os
    workspace = db.query(DBWorkspace).filter(DBWorkspace.id == user.workspace_id).one()
    hosts = workspace.scan_allowed_hosts or ""
    if user.workspace_id == 1:
        hosts += "," + os.getenv("SCAN_ALLOWED_HOSTS", "")
    token = allowed_hosts.set(hosts)
    try:
        return _run_scan(payload, db, user)
    finally:
        allowed_hosts.reset(token)
