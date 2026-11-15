"""Explicit file protection inside a private storage root; no arbitrary server paths."""
import base64
import hashlib
import os
import threading
import fcntl
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from api.settings import DATA_ROOT, MAX_UPLOAD_BYTES
from api.auth import get_current_user, DBUser
from api.database import get_db
from api.audit import log_audit
from legacy import aes_encryptor
from api.tenancy import storage_root

router = APIRouter(prefix="/api/encryption", tags=["File protection"])
PLAIN = DATA_ROOT / "files"
ENCRYPTED = DATA_ROOT / "encrypted"
KEYS = DATA_ROOT / "keys"
for directory in [PLAIN, ENCRYPTED, KEYS]:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
aes_encryptor.KEYS_DIR = str(KEYS)
aes_encryptor.RSA_PRIV_PATH = str(KEYS / "rsa_private.pem")
aes_encryptor.RSA_PUB_PATH = str(KEYS / "rsa_public.pem")
aes_encryptor.AES_KEY_PATH = str(KEYS / "aes_gcm_key.bin.enc")
thread_lock = threading.RLock()

@contextmanager
def operation_lock(workspace_id=1):
    with thread_lock, (storage_root(workspace_id) / "file-operations.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)

def checked_path(root: Path, filename: str):
    if not filename or len(filename) > 200 or filename in {".", ".."} or any(c in filename for c in ['/', '\\', '\x00', '\r', '\n']) or Path(filename).is_absolute():
        raise HTTPException(400, "Use a filename without folders or path segments")
    path = root / filename
    if path.is_symlink() or path.resolve().parent != root.resolve():
        raise HTTPException(400, "File is outside the storage directory")
    return path

def existing(root, filename):
    path = checked_path(root, filename)
    if not path.is_file():
        raise HTTPException(404, "File not found")
    return path

def workspace_paths(user):
    root = storage_root(user.workspace_id)
    paths = [root / name for name in ("files", "encrypted", "keys")]
    for directory in paths:
        if directory.is_symlink():
            raise HTTPException(400, "Invalid storage directory")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return paths

def cipher(user):
    _, _, keys = workspace_paths(user)
    if user.workspace_id != 1:
        path = checked_path(keys, "aes_gcm_key.bin")
        if not path.exists():
            with path.open("xb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(AESGCM.generate_key(bit_length=256))
                output.flush(); os.fsync(output.fileno())
        return AESGCM(path.read_bytes())
    result = AESGCM(aes_encryptor.load_or_generate_key())
    for path in KEYS.iterdir():
        if path.is_file(): path.chmod(0o600)
    return result

@router.get("/files")
def list_files(user: DBUser = Depends(get_current_user)):
    PLAIN, ENCRYPTED, _ = workspace_paths(user)
    with operation_lock(user.workspace_id):
        return {"sensitive_files": sorted(p.name for p in PLAIN.iterdir() if p.is_file() and not p.is_symlink()), "encrypted_files": sorted(p.name for p in ENCRYPTED.iterdir() if p.is_file() and p.name.endswith(".enc") and not p.is_symlink()), "max_upload_bytes": MAX_UPLOAD_BYTES}

@router.post("/upload")
def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    PLAIN, ENCRYPTED, _ = workspace_paths(user)
    with operation_lock(user.workspace_id):
        path = checked_path(PLAIN, file.filename or "")
        try:
            with path.open("xb") as output:
                total = 0
                while chunk := file.file.read(64 * 1024):
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES: raise HTTPException(413, "Maximum upload size is 8 MB")
                    output.write(chunk)
                output.flush(); os.fsync(output.fileno())
            path.chmod(0o600)
        except FileExistsError:
            raise HTTPException(409, "A file with this name already exists")
        except Exception:
            path.unlink(missing_ok=True)
            raise
        log_audit(db, user.username, "upload_file", None, {"filename": path.name, "bytes": total})
        return {"message": "File uploaded", "filename": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

@router.post("/encrypt")
def encrypt_file(filename: str = Form(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    PLAIN, ENCRYPTED, _ = workspace_paths(user)
    with operation_lock(user.workspace_id):
        path = existing(PLAIN, filename)
        destination = checked_path(ENCRYPTED, filename + ".enc")
        nonce = os.urandom(12)
        payload = nonce + cipher(user).encrypt(nonce, path.read_bytes(), None)
        try:
            with destination.open("xb") as output:
                output.write(payload); output.flush(); os.fsync(output.fileno())
        except FileExistsError: raise HTTPException(409, "An encrypted copy already exists")
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        destination.chmod(0o600)
        # Record the durable encrypted copy before removing the original.
        log_audit(db, user.username, "encrypt_file", None, {"filename": filename, "algorithm": "AES-256-GCM"})
        path.unlink()
        return {"message": "Encrypted copy saved; original removed from plaintext storage"}

@router.post("/decrypt")
def decrypt_file(filename: str = Form(...), db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    PLAIN, ENCRYPTED, _ = workspace_paths(user)
    with operation_lock(user.workspace_id):
        if not filename.endswith(".enc"): raise HTTPException(400, "Choose an .enc file")
        path = existing(ENCRYPTED, filename)
        destination = checked_path(PLAIN, filename[:-4])
        payload = path.read_bytes()
        try: plaintext = cipher(user).decrypt(payload[:12], payload[12:], None)
        except Exception: raise HTTPException(422, "Ciphertext authentication failed; nothing was restored")
        try:
            with destination.open("xb") as output:
                output.write(plaintext); output.flush(); os.fsync(output.fileno())
        except FileExistsError: raise HTTPException(409, "Plaintext already exists; it will not be overwritten")
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        destination.chmod(0o600)
        digest = hashlib.sha256(plaintext).hexdigest()
        log_audit(db, user.username, "decrypt_file", None, {"filename": destination.name, "sha256": digest})
        return {"message": "File restored; encrypted backup retained", "sha256": digest}

def file_bytes(kind, filename, user):
    PLAIN, ENCRYPTED, _ = workspace_paths(user)
    roots = {"sensitive": PLAIN, "encrypted": ENCRYPTED}
    if kind not in roots: raise HTTPException(400, "Invalid file type")
    return existing(roots[kind], filename).read_bytes()

@router.get("/preview")
def preview(type: str = Query(...), filename: str = Query(...), user: DBUser = Depends(get_current_user)):
    with operation_lock(user.workspace_id): data = file_bytes(type, filename, user)
    return {"is_image": False, "content": data[:256].hex() if type == "encrypted" else data[:10000].decode("utf-8", errors="replace")}

@router.get("/download")
def download(type: str = Query(...), filename: str = Query(...), user: DBUser = Depends(get_current_user)):
    with operation_lock(user.workspace_id): data = file_bytes(type, filename, user)
    return Response(data, media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}"})
