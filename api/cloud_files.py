"""Transactional, workspace-scoped file storage for stateless hosts.

Small, bounded files live encrypted in PostgreSQL alongside their audit records.
The per-workspace AES key is wrapped by a separately backed-up deployment secret.
"""
import base64
import hashlib
import os
import threading
from contextlib import contextmanager
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from api.audit import log_audit
from api.auth import DBUser, get_current_user
from api.database import get_db
from api.models import DBStoredFile, DBWorkspaceKey
from api.settings import MAX_UPLOAD_BYTES

router = APIRouter(prefix="/api/encryption", tags=["File protection"])
MAX_WORKSPACE_BYTES = 100 * 1024 * 1024
MAX_WORKSPACE_FILES = 500
local_lock = threading.RLock()


def wrapping_cipher():
    try:
        raw = base64.b64decode(os.environ["KEY_ENCRYPTION_KEY"], altchars=b"-_", validate=True)
        if len(raw) != 32:
            raise ValueError()
    except (KeyError, ValueError):
        raise RuntimeError("KEY_ENCRYPTION_KEY must be a stable base64-encoded 32-byte key") from None
    return AESGCM(raw)


# Fail closed at startup, before accepting any customer files.
wrapping_cipher()


def filename_only(filename):
    if not filename or len(filename) > 200 or filename in {".", ".."} or any(c in "/\\" or ord(c) < 32 or ord(c) == 127 for c in filename):
        raise HTTPException(400, "Use a filename without folders or path segments (maximum 200 characters)")
    return filename


def seal(cipher, content, aad):
    nonce = os.urandom(12)
    return nonce + cipher.encrypt(nonce, content, aad)


def unseal(cipher, payload, aad):
    return cipher.decrypt(payload[:12], payload[12:], aad)


@contextmanager
def operation(db, user):
    # Advisory transaction locks coordinate concurrent function instances; SQLite
    # uses this process lock only in isolated local tests.
    with local_lock:
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(8372602, :workspace)"), {"workspace": user.workspace_id})
        yield


def workspace_cipher(db, user, create=False):
    row = db.query(DBWorkspaceKey).filter(DBWorkspaceKey.workspace_id == user.workspace_id).first()
    aad = f"workspace-key:{user.workspace_id}".encode()
    if row is None:
        if not create or db.query(DBStoredFile.id).first() is not None:
            raise HTTPException(503, "The workspace encryption key is unavailable; contact the operator")
        raw = AESGCM.generate_key(bit_length=256)
        row = DBWorkspaceKey(wrapped_key=seal(wrapping_cipher(), raw, aad))
        db.add(row)
        db.flush()
        return AESGCM(raw)
    try:
        return AESGCM(unseal(wrapping_cipher(), row.wrapped_key, aad))
    except (InvalidTag, ValueError):
        raise HTTPException(503, "The workspace encryption key could not be opened; contact the operator") from None


def storage_aad(user, kind, filename):
    return f"stored-file:{user.workspace_id}:{kind}:{filename}".encode()


def find(db, kind, filename):
    if kind not in {"sensitive", "encrypted"}:
        raise HTTPException(400, "Invalid file type")
    filename_only(filename)
    return db.query(DBStoredFile).filter(DBStoredFile.kind == kind, DBStoredFile.filename == filename).first()


def read(db, user, kind, filename):
    row = find(db, kind, filename)
    if row is None:
        raise HTTPException(404, "File not found")
    try:
        return unseal(workspace_cipher(db, user), row.payload, storage_aad(user, kind, filename))
    except (InvalidTag, ValueError):
        raise HTTPException(422, "Stored file authentication failed; no file was changed") from None


def put(db, user, kind, filename, content, cipher):
    filename_only(filename)
    if find(db, kind, filename):
        raise HTTPException(409, "A file with this name already exists; it will not be overwritten")
    size, count = db.query(func.coalesce(func.sum(DBStoredFile.size), 0), func.count(DBStoredFile.id)).one()
    if size + len(content) > MAX_WORKSPACE_BYTES or count >= MAX_WORKSPACE_FILES:
        raise HTTPException(413, "Workspace storage limit reached (100 MB or 500 files)")
    db.add(DBStoredFile(kind=kind, filename=filename, size=len(content), payload=seal(cipher, content, storage_aad(user, kind, filename))))
    db.flush()


@router.get("/files")
def list_files(db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    rows = db.query(DBStoredFile.kind, DBStoredFile.filename).all()
    return {"sensitive_files": sorted(name for kind, name in rows if kind == "sensitive"), "encrypted_files": sorted(name for kind, name in rows if kind == "encrypted"), "max_upload_bytes": MAX_UPLOAD_BYTES, "storage": "database"}


@router.post("/upload")
def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    filename = filename_only(file.filename or "")
    content = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Maximum upload size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    with operation(db, user):
        put(db, user, "sensitive", filename, content, workspace_cipher(db, user, create=True))
        log_audit(db, user.username, "upload_file", None, {"filename": filename, "bytes": len(content)})
    return {"message": "File uploaded", "filename": filename, "sha256": hashlib.sha256(content).hexdigest()}


@router.post("/encrypt")
def encrypt_file(filename: str = Form(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    with operation(db, user):
        content = read(db, user, "sensitive", filename)
        cipher = workspace_cipher(db, user)
        payload = seal(cipher, content, f"protected-file:{user.workspace_id}".encode())
        db.delete(find(db, "sensitive", filename))
        db.flush()
        put(db, user, "encrypted", filename + ".enc", payload, cipher)
        # The replacement and audit entry commit together; failures keep the original.
        log_audit(db, user.username, "encrypt_file", None, {"filename": filename, "algorithm": "AES-256-GCM"})
    return {"message": "Encrypted copy saved; original removed from plaintext storage"}


@router.post("/decrypt")
def decrypt_file(filename: str = Form(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    if not filename.endswith(".enc"):
        raise HTTPException(400, "Choose an .enc file")
    with operation(db, user):
        payload = read(db, user, "encrypted", filename)
        cipher = workspace_cipher(db, user)
        try:
            content = unseal(cipher, payload, f"protected-file:{user.workspace_id}".encode())
        except (InvalidTag, ValueError):
            raise HTTPException(422, "Ciphertext authentication failed; nothing was restored") from None
        put(db, user, "sensitive", filename[:-4], content, cipher)
        digest = hashlib.sha256(content).hexdigest()
        log_audit(db, user.username, "decrypt_file", None, {"filename": filename[:-4], "sha256": digest})
    return {"message": "File restored; encrypted backup retained", "sha256": digest}


@router.get("/preview")
def preview(type: str = Query(...), filename: str = Query(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    content = read(db, user, type, filename)
    return {"is_image": False, "content": content[:256].hex() if type == "encrypted" else content[:10000].decode("utf-8", errors="replace")}


@router.get("/download")
def download(type: str = Query(...), filename: str = Query(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    content = read(db, user, type, filename)
    return Response(content, media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}", "Cache-Control": "private, no-store"})
