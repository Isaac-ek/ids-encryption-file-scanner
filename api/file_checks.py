"""Bounded local file inspection; untrusted uploads are never executed."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from api.auth import get_current_user, DBUser
from api.audit import log_audit
from api.database import get_db
from api.models import DBFileCheck
from api.tenancy import storage_root
from api.settings import DATA_ROOT, MAX_UPLOAD_BYTES

router = APIRouter(prefix='/api/file-checks', tags=['File inspection'])
PATTERNS = [
    ('Dynamic code execution', rb'(?i)\b(?:eval|exec|shell_exec|passthru)\s*\('),
    ('Shell invocation', rb'(?i)(?:cmd\.exe|bash\s+-c)'),
    ('Remote download command', rb'(?i)\b(?:curl|wget)\s+https?://'),
    ('Encoded code or script injection', rb'(?i)(?:base64_decode|document\.write\s*\(|String\.fromCharCode)'),
]
EICAR_MD5 = '44d88612fea8a8f36de82e1278abb02f'

def serialize(row):
    return {'id': row.id, 'filename': row.filename, 'sha256': row.sha256, 'status': row.status, 'requested_by': row.requested_by, 'created_at': row.created_at, **json.loads(row.report_json)}

@router.get('/status')
def status(user: DBUser = Depends(get_current_user)):
    return {'clamav_available': shutil.which('clamscan') is not None, 'pattern_checks': len(PATTERNS), 'known_test_signatures': 1, 'max_upload_bytes': MAX_UPLOAD_BYTES, 'note': 'Pattern matches are review hints. Without ClamAV, a scan cannot establish that a file is free of malware.'}

@router.get('')
def history(db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    return [serialize(row) for row in db.query(DBFileCheck).order_by(DBFileCheck.id.desc()).limit(50)]

@router.post('/run')
def inspect_file(file: UploadFile = File(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    content = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES: raise HTTPException(413, 'Maximum upload size is 8 MB')
    filename = (file.filename or 'uploaded-file').replace('\\', '/').rsplit('/', 1)[-1][:200]
    digest = hashlib.sha256(content).hexdigest()
    signature = hashlib.md5(content).hexdigest() == EICAR_MD5
    matches = [name for name, pattern in PATTERNS if re.search(pattern, content)]
    checks = [
        {'name': 'Known test signature', 'status': 'detected' if signature else 'no_match', 'detail': 'EICAR antivirus test signature detected.' if signature else 'No EICAR test signature match. This is not a complete signature database.'},
        {'name': 'Code-pattern inspection', 'status': 'review' if matches else 'no_match', 'detail': '; '.join(matches) if matches else 'No configured patterns matched.'},
    ]
    executable = shutil.which('clamscan'); av_status = 'unavailable'
    if executable:
        scans = storage_root(user.workspace_id) / 'file-check-temp'; scans.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=scans) as directory:
            path = Path(directory) / 'upload.bin'; path.write_bytes(content); path.chmod(0o600)
            try:
                result = subprocess.run([executable, '--no-summary', str(path)], capture_output=True, text=True, timeout=30)
                av_status = {0: 'no_findings', 1: 'detected'}.get(result.returncode, 'error')
                detail = 'ClamAV reported no findings.' if result.returncode == 0 else 'ClamAV detected a signature.' if result.returncode == 1 else 'ClamAV could not complete the scan; check the local engine and definitions.'
            except (subprocess.SubprocessError, OSError):
                av_status = 'error'; detail = 'ClamAV was unavailable or exceeded the 30-second time limit.'
    else: detail = 'ClamAV is not installed on this host. Only the limited checks above ran.'
    checks.append({'name': 'ClamAV', 'status': av_status, 'detail': detail})
    state = 'detected' if signature or av_status == 'detected' else 'review' if matches else 'no_findings' if av_status == 'no_findings' else 'limited'
    report = {'bytes': len(content), 'checks': checks, 'note': 'The temporary upload was discarded after inspection. Findings do not prove exploitability or guarantee safety.'}
    row = DBFileCheck(filename=filename, sha256=digest, status=state, requested_by=user.username, created_at=datetime.now(timezone.utc).isoformat(), report_json=json.dumps(report))
    db.add(row); db.commit(); db.refresh(row)
    log_audit(db, user.username, 'file_check', None, {'check_id': row.id, 'filename': filename, 'sha256': digest, 'status': state})
    return serialize(row)
