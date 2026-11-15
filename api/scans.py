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
from sqlalchemy import text
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


class ScanScope(BaseModel):
    hostnames: list[str] = Field(default_factory=list, max_length=30)
    authorized: bool = False


def configured_hosts(workspace, user):
    import os
    hosts = {h.strip() for h in (workspace.scan_allowed_hosts or "").split(",") if h.strip()}
    if user.workspace_id == 1:
        hosts.update(h.strip() for h in os.getenv("SCAN_ALLOWED_HOSTS", "").split(",") if h.strip())
    return sorted(hosts)


def normalize_scope_host(value):
    import ipaddress
    import os
    import re
    from urllib.parse import urlsplit
    value = value.strip()
    if not value or len(value) > 2000:
        raise HTTPException(422, "Enter a hostname or an HTTP/HTTPS website URL")
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or not parsed.hostname or parsed.port not in {None, 80, 443}:
            raise ValueError()
        host = parsed.hostname.rstrip(".").encode("idna").decode().lower()
        fixture = os.getenv("SCAN_ALLOW_LOCALHOST") == "true" and host in {"localhost", "127.0.0.1", "::1"}
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")) or ("." not in host and not fixture):
                raise ValueError()
        else:
            if (not address.is_global or address.is_multicast) and not fixture:
                raise ValueError()
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Use a public hostname or website URL without credentials, wildcards, or custom ports") from None
    return host


@router.get("/scope")
def get_scope(db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    workspace = db.query(DBWorkspace).filter(DBWorkspace.id == user.workspace_id).one()
    return {"hostnames": sorted(h for h in (workspace.scan_allowed_hosts or "").split(",") if h), "effective_hostnames": configured_hosts(workspace, user)}


@router.put("/scope")
def set_scope(payload: ScanScope, db: Session = Depends(get_db), user: DBUser = Depends(require_admin)):
    if not payload.authorized:
        raise HTTPException(422, "Confirm you own or have permission to assess these sites")
    hosts = sorted({normalize_scope_host(value) for value in payload.hostnames})
    workspace = db.query(DBWorkspace).filter(DBWorkspace.id == user.workspace_id).one()
    previous = workspace.scan_allowed_hosts
    workspace.scan_allowed_hosts = ",".join(hosts)
    log_audit(db, user.username, "update_scan_scope", None, {"previous": previous.split(",") if previous else [], "hostnames": hosts})
    return {"hostnames": hosts, "effective_hostnames": configured_hosts(workspace, user)}

def _run_scan(payload: ScanRequest, db: Session, user: DBUser):
    if not payload.authorized: raise HTTPException(422, "Confirm you are authorized to check this target")
    try: target, address, port = resolve_target(payload.url)
    except (ValueError, OSError) as error: raise HTTPException(400, str(error))
    if db.bind.dialect.name == "postgresql" and not db.execute(text("SELECT pg_try_advisory_xact_lock(8372603, :workspace)"), {"workspace": user.workspace_id}).scalar():
        raise HTTPException(409, "Another scan is running in this workspace; try again shortly")
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
