import hashlib
from types import SimpleNamespace
import pytest
from api import recovery
from api.database import SessionLocal
from api.models import DBUser, DBPasswordReset, DBRecoveryThrottle

ADDRESS = "owner@example.com"
NEW = "a-different-strong-password"

@pytest.fixture
def mail(client, monkeypatch):
    monkeypatch.setenv("PASSWORD_RECOVERY_ENABLED", "true")
    monkeypatch.setenv("RESEND_API_KEY", "test-key-used-only-by-mocked-http")
    monkeypatch.setenv("RESEND_EMAIL_DOMAIN", "mail.example.com")
    monkeypatch.setenv("PASSWORD_RESET_ORIGIN", "https://security.example.com")
    with SessionLocal() as db:
        db.query(DBUser).filter_by(username="owner").one().email = ADDRESS
        db.commit()
    sent = []
    def post(url, **options):
        sent.append((url, options))
        return SimpleNamespace(status_code=200)
    monkeypatch.setattr(recovery.requests, "post", post)
    return sent


def ask(client, username="owner", email=ADDRESS):
    return client.post("/api/auth/forgot-password", json={"username": username, "email": email}, headers={"Host":"attacker.invalid"})


def raw_token(mail):
    return mail[-1][1]["json"]["text"].split("?token=")[1].split()[0]


def test_complete_recovery_is_single_use_revokes_sessions_and_preserves_identity(client, auth, mail):
    assert client.get("/api/auth/recovery-status").json() == {"available":True}
    sent = ask(client)
    assert sent.status_code == 200 and sent.headers["cache-control"] == "no-store"
    token = raw_token(mail)
    url, options = mail[0]
    assert url == "https://api.resend.com/emails" and options["timeout"] == 15
    assert options["json"]["to"] == [ADDRESS] and options["json"]["from"] == "SecureStream <security@mail.example.com>"
    assert "https://security.example.com/#reset-password?token=" in options["json"]["text"]
    assert "attacker.invalid" not in options["json"]["text"]
    with SessionLocal() as db:
        row = db.query(DBPasswordReset).one()
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest() and row.token_hash != token
        assert row.consumed_at is None
        assert row.expires_at <= int(recovery.time.time()) + 1200
    # Recovery tokens cannot authenticate API sessions.
    assert client.get("/api/auth/me",headers={"Authorization":"Bearer "+token}).status_code == 401
    changed = client.post("/api/auth/reset-password", json={"token":token,"new_password":NEW})
    assert changed.status_code == 200 and "access_token" not in changed.json()
    assert client.get("/api/auth/me",headers=auth).status_code == 401
    assert client.post("/api/auth/login",data={"username":"owner","password":"fixture-password"}).status_code == 400
    login = client.post("/api/auth/login",data={"username":"owner","password":NEW})
    assert login.status_code == 200 and login.json()["role"] == "admin"
    headers = {"Authorization":"Bearer "+login.json()["access_token"]}
    me = client.get("/api/auth/me",headers=headers).json()
    assert me["workspace_id"] == 1 and me["email"] == ADDRESS
    assert client.post("/api/auth/reset-password",json={"token":token,"new_password":"yet-another-password"}).status_code == 400
    logs = client.get("/api/alerts/audit-logs",headers=headers).json()
    assert logs["is_valid"] and "reset_password" in [x["action"] for x in logs["logs"]]
    assert token not in str(logs) and ADDRESS not in str(logs)


def test_unknown_account_wrong_email_and_throttling_have_same_response(client, mail):
    unknown = ask(client, "absent").json()
    wrong = ask(client,email="other@example.com").json()
    assert len(mail) == 0
    # Wrong email attempts still count toward this account's cooldown.
    assert ask(client).json() == wrong == unknown
    assert not mail
    with SessionLocal() as db:
        assert db.query(DBPasswordReset).count() == 0
        assert "owner" not in str([row.key for row in db.query(DBRecoveryThrottle).all()])


def test_persistent_limits_and_expiry(client, mail, monkeypatch):
    clock = [1794780000]
    monkeypatch.setattr(recovery, "time", SimpleNamespace(time=lambda:clock[0]))
    for i in range(3):
        assert ask(client).status_code == 200
        clock[0] += 61
    assert len(mail) == 3
    assert ask(client).status_code == 200 and len(mail) == 3
    token = raw_token(mail)
    clock[0] += recovery.TTL + 1
    assert client.post("/api/auth/reset-password", json={"token":token,"new_password":NEW}).status_code == 400
    with SessionLocal() as db:
        assert db.query(DBRecoveryThrottle).count() == 4


def test_email_change_and_password_change_invalidate_old_links(client, auth, mail):
    ask(client); token = raw_token(mail)
    changed = client.put("/api/auth/users/owner", headers=auth,json={"email":"new@example.com"})
    assert changed.status_code == 200
    assert client.post("/api/auth/reset-password",json={"token":token,"new_password":NEW}).status_code == 400
    with SessionLocal() as db:
        db.query(DBUser).filter_by(username="owner").one().email = ADDRESS; db.commit()
    assert client.post("/api/auth/password",headers=auth,json={"current_password":"fixture-password","new_password":NEW}).status_code == 200
    assert client.post("/api/auth/reset-password",json={"token":token,"new_password":"another-new-password"}).status_code == 400


def test_failed_email_is_not_redeemable_and_is_audited_without_secret(client, auth, mail, monkeypatch):
    def fail(*args, **kwargs):
        mail.append((args[0],kwargs));return SimpleNamespace(status_code=403)
    monkeypatch.setattr(recovery.requests,"post",fail)
    assert ask(client).json()["message"] == recovery.GENERIC
    with SessionLocal() as db: assert db.query(DBPasswordReset).count() == 0
    audit = client.get("/api/alerts/audit-logs",headers=auth).json()
    assert audit["is_valid"] and audit["logs"][0]["action"] == "password_reset_email_failed"
    assert raw_token(mail) not in str(audit)


def test_email_permissions_validation_and_unconfigured_delivery(client, auth, monkeypatch):
    for name in ["RESEND_API_KEY","RESEND_EMAIL_DOMAIN","VERCEL_URL","PASSWORD_RESET_ORIGIN"]: monkeypatch.delenv(name,raising=False)
    assert client.get("/api/auth/recovery-status").json() == {"available":False}
    assert ask(client).status_code == 503
    assert client.put("/api/auth/users/owner",headers=auth,json={"email":"invalid"}).status_code == 422
    viewer = client.post("/api/auth/login",data={"username":"viewer","password":"fixture-password"}).json()["access_token"]
    assert client.put("/api/auth/users/owner",headers={"Authorization":"Bearer "+viewer},json={"email":ADDRESS}).status_code == 403
    assert client.put("/api/auth/users/owner",headers=auth,json={"email":"Owner@EXAMPLE.COM"}).json()["email"] == ADDRESS
    assert client.put("/api/auth/users/owner",headers=auth,json={"name":"New name"}).json()["email"] == ADDRESS
    assert client.put("/api/auth/users/owner",headers=auth,json={"email":""}).json()["email"] is None
    monkeypatch.setenv("PASSWORD_RECOVERY_ENABLED", "false")
    assert client.get("/api/auth/recovery-status").json() == {"available":False}
    monkeypatch.setenv("VERCEL","1");monkeypatch.setenv("PASSWORD_RESET_ORIGIN","http://localhost:8182")
    with pytest.raises(ValueError): recovery.reset_origin()


def test_global_quota_bounds_account_records(client, mail, monkeypatch):
    clock = 1794780000
    monkeypatch.setattr(recovery, "time", SimpleNamespace(time=lambda:clock))
    for i in range(35): assert ask(client,username=f"absent-{i}").status_code == 200
    assert not mail
    with SessionLocal() as db:
        assert db.query(DBRecoveryThrottle).count() <= 62
