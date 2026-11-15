import os
import hmac
import hashlib
import base64
import json
import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash

from api.database import get_db
from api.models import DBUser, DBWorkspace, UserCreate, UserEdit, UserResponse
from api import tenancy  # Register mandatory workspace query/write guards.
from pydantic import BaseModel, Field
from api.audit import log_audit

from api.settings import required_secret
SECRET_KEY = required_secret("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600 * 24  # 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ==================== JWT Helpers ====================

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).replace(b'=', b'').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data.encode('utf-8'))

def create_access_token(data: dict, expires_in: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["exp"] = int(time.time()) + expires_in

    header_enc = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_enc = base64url_encode(json.dumps(payload).encode('utf-8'))

    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        f"{header_enc}.{payload_enc}".encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_enc = base64url_encode(signature)
    return f"{header_enc}.{payload_enc}.{signature_enc}"

def decode_access_token(token: str) -> Optional[dict]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_enc, payload_enc, signature_enc = parts

        expected_sig = hmac.new(
            SECRET_KEY.encode('utf-8'),
            f"{header_enc}.{payload_enc}".encode('utf-8'),
            hashlib.sha256
        ).digest()
        expected_sig_enc = base64url_encode(expected_sig)

        if not hmac.compare_digest(signature_enc.encode('utf-8'), expected_sig_enc.encode('utf-8')):
            return None

        payload = json.loads(base64url_decode(payload_enc).decode('utf-8'))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ==================== Dependency Injection Helpers ====================

def session_stamp(user):
    return hmac.new(SECRET_KEY.encode(), user.password.encode(), hashlib.sha256).hexdigest()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> DBUser:
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    user = db.query(DBUser).filter(DBUser.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if payload.get("workspace_id") != user.workspace_id or not hmac.compare_digest(payload.get("auth_stamp", ""), session_stamp(user)):
        raise HTTPException(401, "Your session has changed. Please sign in again.")
    db.info["workspace_id"] = user.workspace_id
    workspace = db.query(DBWorkspace).filter(DBWorkspace.id == user.workspace_id).first()
    if workspace is None:
        raise HTTPException(401, "Workspace unavailable")
    user.workspace_name = workspace.name
    return user

def require_admin(current_user: DBUser = Depends(get_current_user)) -> DBUser:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user

# ==================== Auth Router ====================

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == form_data.username).first()
    # Support checking original password hash from users.yaml (werkzeug uses scrypt by default)
    if not user or not check_password_hash(user.password, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password"
        )

    access_token = create_access_token(data={"sub": user.username, "auth_stamp": session_stamp(user), "workspace_id": user.workspace_id})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
        "name": user.name
    }

@router.post("/signup")
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    raise HTTPException(status_code=403, detail="Create the first administrator with scripts/create_admin.py")

@router.get("/me", response_model=UserResponse)
def get_me(current_user: DBUser = Depends(get_current_user)):
    return current_user

@router.get("/users", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    return db.query(DBUser).all()

@router.post("/users", response_model=UserResponse)
def create_user(user_in: UserCreate, db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    existing = db.query(DBUser).execution_options(identity_lookup=True).filter(DBUser.username == user_in.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists."
        )

    hashed_password = generate_password_hash(user_in.password)
    db_user = DBUser(
        username=user_in.username,
        name=user_in.name,
        password=hashed_password,
        role=user_in.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    log_audit(db, admin=current_user.username, action="add_user", target_user=db_user.username, details={"name": db_user.name, "role": db_user.role})
    return db_user

@router.put("/users/{username}", response_model=UserResponse)
def edit_user(username: str, user_in: UserEdit, db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    db_user = db.query(DBUser).filter(DBUser.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if username == current_user.username and user_in.role not in {None, "admin"}:
        raise HTTPException(409, "You cannot remove your own administrator access")

    old_details = {"name": db_user.name, "role": db_user.role}
    new_details = {}

    if user_in.name is not None:
        db_user.name = user_in.name
        new_details["name"] = user_in.name
    if user_in.role is not None:
        db_user.role = user_in.role
        new_details["role"] = user_in.role
    if user_in.password is not None:
        db_user.password = generate_password_hash(user_in.password)
        new_details["password_changed"] = True

    db.commit()
    db.refresh(db_user)

    log_audit(db, admin=current_user.username, action="edit_user", target_user=username, details={"old": old_details, "new": new_details})
    return db_user

@router.delete("/users/{username}")
def delete_user(username: str, db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    db_user = db.query(DBUser).filter(DBUser.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if username == current_user.username:
        raise HTTPException(409, "You cannot delete the account you are signed in with")
    db.delete(db_user)
    db.commit()

    log_audit(db, admin=current_user.username, action="delete_user", target_user=username)
    return {"message": f"User {username} deleted successfully"}


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

@router.post("/password")
def change_password(payload: PasswordChange, db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    if not check_password_hash(user.password, payload.current_password):
        raise HTTPException(400, "Current password is incorrect")
    user.password = generate_password_hash(payload.new_password)
    db.commit()
    log_audit(db, user.username, "change_password", user.username)
    return {"message": "Password changed. Other sessions will need to sign in again.", "access_token": create_access_token({"sub": user.username, "auth_stamp": session_stamp(user), "workspace_id": user.workspace_id})}
