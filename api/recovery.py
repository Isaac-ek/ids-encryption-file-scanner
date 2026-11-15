"""Single-use account recovery with durable admission control and real Resend delivery."""
import hashlib
import hmac
import html
import logging
import os
import secrets
import time
from urllib.parse import urlsplit

import requests
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import delete
from sqlalchemy.orm import Session

from api.auth import SECRET_KEY, session_stamp
from api.audit import log_audit
from api.database import get_db, SessionLocal
from api.models import DBUser, DBPasswordReset, DBRecoveryThrottle
from werkzeug.security import generate_password_hash

router = APIRouter(prefix="/api/auth", tags=["Account recovery"])
logger = logging.getLogger(__name__)
TTL = 20 * 60
GENERIC = "If these details match an account with a recovery email, a reset link will arrive shortly. Check your spam folder too."


class ForgotPassword(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr


class ResetPassword(BaseModel):
    token: str = Field(min_length=40, max_length=100)
    new_password: str = Field(min_length=12, max_length=128)


def reset_origin():
    # Only configured origins; never trust the request Host or forwarded headers.
    origin = os.getenv("PASSWORD_RESET_ORIGIN", "").strip().rstrip("/")
    if not origin and os.getenv("VERCEL_URL"):
        origin = "https://" + os.environ["VERCEL_URL"]
    parsed = urlsplit(origin)
    local = parsed.hostname in {"localhost", "127.0.0.1"} and not os.getenv("VERCEL")
    if (parsed.scheme != "https" and not (local and parsed.scheme == "http")) or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Configure a trusted PASSWORD_RESET_ORIGIN")
    return origin


def recovery_stamp(user):
    return hmac.new(SECRET_KEY.encode(), (session_stamp(user) + ":" + (user.email or "")).encode(), hashlib.sha256).hexdigest()


def mail_sender():
    domain = os.getenv("RESEND_EMAIL_DOMAIN", "").strip()
    if not domain or any(char in domain for char in "@/<> \r\n"):
        raise ValueError("Resend sender domain is not configured")
    return f"SecureStream <security@{domain}>"


def delivery_ready():
    try:
        reset_origin(); mail_sender()
        return bool(os.getenv("RESEND_API_KEY"))
    except ValueError:
        return False


@router.get("/recovery-status")
def recovery_status(response: Response):
    response.headers["Cache-Control"] = "no-store"
    return {"available": delivery_ready()}


def admit(db, scope, limit, period, now):
    key = hmac.new(SECRET_KEY.encode(), scope.encode(), hashlib.sha256).hexdigest()
    values = dict(key=key, window_start=now - now % period, attempts=0)
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    db.execute(insert(DBRecoveryThrottle).values(**values).on_conflict_do_nothing(index_elements=["key"]))
    row = db.query(DBRecoveryThrottle).filter_by(key=key).with_for_update().one()
    if row.window_start != values["window_start"]:
        row.window_start = values["window_start"]; row.attempts = 0
    if row.attempts >= limit:
        return False
    row.attempts += 1
    db.flush()
    return True


def deliver_reset(token_hash, raw_token):
    # FastAPI awaits this task after its identical response for known/unknown accounts.
    # It runs inside the function lifetime, with its own transaction/session.
    with SessionLocal() as db:
        row = db.query(DBPasswordReset).filter_by(token_hash=token_hash).first()
        if not row or row.consumed_at or row.expires_at <= int(time.time()):
            return
        user = db.query(DBUser).filter_by(id=row.user_id, workspace_id=row.workspace_id).first()
        if not user or not user.email or not hmac.compare_digest(row.auth_stamp, recovery_stamp(user)):
            return
        db.info["workspace_id"] = user.workspace_id
        link = reset_origin() + "/#reset-password?token=" + raw_token
        message = (f"A password reset was requested for your SecureStream account ({user.username}).\n\n"
                   f"Choose a new password: {link}\n\n"
                   "This link expires in 20 minutes and can be used once. Resetting signs out all existing sessions. "
                   "If you did not request this, ignore this email; your password has not changed.")
        provider_status = None
        try:
            result = requests.post("https://api.resend.com/emails", headers={
                "Authorization": "Bearer " + os.environ["RESEND_API_KEY"],
                "Idempotency-Key": "password-reset-" + token_hash,
            }, json={"from": mail_sender(), "to": [user.email], "subject": "Reset your SecureStream password", "text": message,
                     "html": "<p>" + html.escape(message).replace("\n", "<br>") + "</p><p><a href=\"" + html.escape(link, quote=True) + "\">Choose a new password</a></p>"}, timeout=15)
            provider_status = result.status_code
            if provider_status not in {200, 201, 202}:
                # Do not log response bodies: they can contain recipient addresses.
                raise RuntimeError(f"Resend HTTP {result.status_code}")
            log_audit(db, None, "password_reset_email_sent", user.username)
        except (requests.RequestException, RuntimeError, ValueError, KeyError):
            logger.error("Password-reset email delivery failed (provider HTTP %s); check the Resend connection and sender domain", provider_status)
            db.delete(row)
            log_audit(db, None, "password_reset_email_failed", user.username, {"provider_status": provider_status})


@router.post("/forgot-password")
def forgot_password(payload: ForgotPassword, response: Response, tasks: BackgroundTasks, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    if not delivery_ready():
        raise HTTPException(503, "Password recovery is unavailable. Ask your workspace administrator to reset your password.")
    now = int(time.time())
    # Serialize quota accounting across processes/cold starts. Both outcomes are identical.
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy import text
        db.execute(text("SELECT pg_advisory_xact_lock(8372602)"))
    allowed = admit(db, "global-hour", 30, 3600, now)
    allowed = admit(db, "global-day", 80, 86400, now) and allowed
    if allowed:
        allowed = admit(db, "account:" + payload.username, 3, 3600, now)
        allowed = admit(db, "cooldown:" + payload.username, 1, 60, now) and allowed
    # Expired rows and old opaque quotas are bounded by recent requests.
    db.execute(delete(DBRecoveryThrottle).where(DBRecoveryThrottle.window_start < now - 172800))
    db.execute(delete(DBPasswordReset).where(DBPasswordReset.expires_at < now))
    user = db.query(DBUser).filter_by(username=payload.username).first() if allowed else None
    raw_token = secrets.token_urlsafe(32)
    if user and user.email and hmac.compare_digest(user.email.lower().encode(), str(payload.email).lower().encode()):
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        db.add(DBPasswordReset(token_hash=token_hash, user_id=user.id, workspace_id=user.workspace_id,
                               auth_stamp=recovery_stamp(user), expires_at=now + TTL))
        db.commit()
        tasks.add_task(deliver_reset, token_hash, raw_token)
    else:
        db.commit()
    return {"message": GENERIC}


@router.post("/reset-password")
def reset_password(payload: ResetPassword, response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    invalid = HTTPException(400, "This reset link has expired or was already used. Request a new link.")
    now = int(time.time())
    hashed = hashlib.sha256(payload.token.encode()).hexdigest()
    row = db.query(DBPasswordReset).filter_by(token_hash=hashed).with_for_update().first()
    if not row or row.consumed_at or row.expires_at <= now:
        raise invalid
    user = db.query(DBUser).filter_by(id=row.user_id, workspace_id=row.workspace_id).with_for_update().first()
    if not user or not hmac.compare_digest(row.auth_stamp, recovery_stamp(user)):
        raise invalid
    db.info["workspace_id"] = user.workspace_id
    # Conditional updates retain one-use semantics even on SQLite (no row locks).
    claimed = db.query(DBPasswordReset).filter_by(token_hash=hashed, consumed_at=None).update({"consumed_at": now}, synchronize_session=False)
    changed = db.query(DBUser).filter_by(id=user.id, workspace_id=row.workspace_id, password=user.password).update({"password": generate_password_hash(payload.new_password)}, synchronize_session=False) if claimed else 0
    if changed != 1:
        db.rollback(); raise invalid
    log_audit(db, user.username, "reset_password", user.username)
    return {"message": "Password updated. Sign in with your new password. All previous sessions have been signed out."}
