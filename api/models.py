from sqlalchemy import Column, Integer, String, Boolean

class WorkspaceScoped:
    workspace_id = Column(Integer, nullable=False, default=1, index=True)
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, Literal
from api.database import Base

# ==================== SQLAlchemy Database Models ====================

class DBUser(WorkspaceScoped, Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="user")

class DBRule(WorkspaceScoped, Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)  # 'ip', 'port', 'bandwidth'
    value = Column(String, nullable=False)
    threshold = Column(Integer, nullable=True)
    enabled = Column(Boolean, default=True)

class DBAuditLog(WorkspaceScoped, Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, nullable=False)
    admin = Column(String, nullable=True)
    action = Column(String, nullable=False)
    target_user = Column(String, nullable=True)
    details = Column(String, nullable=True)  # Store as serialized JSON
    prev_hash = Column(String, nullable=False)
    entry_hash = Column(String, nullable=False)

class DBThreatAlert(WorkspaceScoped, Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, nullable=False)
    alert_type = Column(String, nullable=False)
    origin = Column(String, nullable=False, default="sensor")
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)

# ==================== Pydantic Schemas for API ====================

class UserBase(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=100)
    role: Literal["admin", "user"] = "user"

class UserCreate(UserBase):
    password: str = Field(min_length=12, max_length=128)

class UserEdit(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    role: Optional[Literal["admin", "user"]] = None
    password: Optional[str] = Field(default=None, min_length=12, max_length=128)

class UserResponse(UserBase):
    id: int
    workspace_id: int
    workspace_name: str = ""

    model_config = ConfigDict(from_attributes=True)

class DBScanRun(WorkspaceScoped, Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    requested_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    status = Column(String, nullable=False)
    findings_json = Column(String, nullable=False)

class RuleBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    type: Literal["ip", "port", "bandwidth"]
    value: str = Field(min_length=1, max_length=200)
    threshold: Optional[int] = Field(default=None, ge=0, le=2147483647)
    enabled: bool = True

class RuleResponse(RuleBase):
    id: int

    model_config = ConfigDict(from_attributes=True)

class AuditLogResponse(BaseModel):
    id: int
    timestamp: str
    admin: Optional[str] = None
    action: str
    target_user: Optional[str] = None
    details: Optional[str] = None
    prev_hash: str
    entry_hash: str

    model_config = ConfigDict(from_attributes=True)

class ThreatAlertResponse(BaseModel):
    origin: str = "sensor"
    id: int
    timestamp: str
    alert_type: str
    source_ip: str
    destination_ip: str

    model_config = ConfigDict(from_attributes=True)


class DBFileCheck(WorkspaceScoped, Base):
    __tablename__ = "file_checks"
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    sha256 = Column(String, nullable=False)
    status = Column(String, nullable=False)
    requested_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    report_json = Column(String, nullable=False)


class DBWorkspace(Base):
    __tablename__ = "workspaces"
    id = Column(Integer, primary_key=True)
    slug = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    worker_token_hash = Column(String, nullable=True)
    scan_allowed_hosts = Column(String, nullable=False, default="")
