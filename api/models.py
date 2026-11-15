from sqlalchemy import Column, Integer, String, Boolean
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from api.database import Base

# ==================== SQLAlchemy Database Models ====================

class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="user")

class DBRule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)  # 'ip', 'port', 'bandwidth'
    value = Column(String, nullable=False)
    threshold = Column(Integer, nullable=True)
    enabled = Column(Boolean, default=True)

class DBAuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, nullable=False)
    admin = Column(String, nullable=True)
    action = Column(String, nullable=False)
    target_user = Column(String, nullable=True)
    details = Column(String, nullable=True)  # Store as serialized JSON
    prev_hash = Column(String, nullable=False)
    entry_hash = Column(String, nullable=False)

class DBThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, nullable=False)
    alert_type = Column(String, nullable=False)
    origin = Column(String, nullable=False, default="sensor")
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)

# ==================== Pydantic Schemas for API ====================

class UserBase(BaseModel):
    username: str
    name: str
    role: str

class UserCreate(UserBase):
    password: str

class UserEdit(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True

class DBScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    requested_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    status = Column(String, nullable=False)
    findings_json = Column(String, nullable=False)

class RuleBase(BaseModel):
    name: str
    type: str
    value: str
    threshold: Optional[int] = None
    enabled: bool = True

class RuleResponse(RuleBase):
    id: int

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: int
    timestamp: str
    admin: Optional[str] = None
    action: str
    target_user: Optional[str] = None
    details: Optional[str] = None
    prev_hash: str
    entry_hash: str

    class Config:
        from_attributes = True

class ThreatAlertResponse(BaseModel):
    origin: str = "sensor"
    id: int
    timestamp: str
    alert_type: str
    source_ip: str
    destination_ip: str

    class Config:
        from_attributes = True
