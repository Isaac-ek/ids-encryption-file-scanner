from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import json

from api.database import get_db
from api.models import DBRule, DBThreatAlert, DBAuditLog, RuleBase, RuleResponse, AuditLogResponse, ThreatAlertResponse
from api.auth import get_current_user, require_admin, DBUser
from api.audit import verify_audit_log, log_audit
from api.websocket_manager import manager
from fastapi import Header
import os
import hmac

def authorize_worker(x_worker_token: str = Header(default="")):
    expected = os.getenv("WORKER_TOKEN", "")
    if len(expected) < 32 or expected.startswith("replace-with-") or not hmac.compare_digest(x_worker_token, expected):
        raise HTTPException(403, "Worker authentication required")


router = APIRouter(prefix="/api/alerts", tags=["Rules & Alerts"])

# ==================== Rules API ====================

@router.get("/rules", response_model=List[RuleResponse])
def get_rules(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    return db.query(DBRule).all()

@router.post("/rules", response_model=RuleResponse)
def add_rule(rule_in: RuleBase, db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    db_rule = DBRule(
        name=rule_in.name,
        type=rule_in.type,
        value=rule_in.value,
        threshold=rule_in.threshold,
        enabled=rule_in.enabled
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)

    log_audit(db, admin=current_user.username, action="add_rule", target_user=None, details={"name": db_rule.name})
    return db_rule

@router.put("/rules/{rule_id}", response_model=RuleResponse)
def edit_rule(rule_id: int, rule_in: RuleBase, db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    db_rule = db.query(DBRule).filter(DBRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    db_rule.name = rule_in.name
    db_rule.type = rule_in.type
    db_rule.value = rule_in.value
    db_rule.threshold = rule_in.threshold
    db_rule.enabled = rule_in.enabled

    db.commit()
    db.refresh(db_rule)

    log_audit(db, admin=current_user.username, action="edit_rule", target_user=None, details={"id": rule_id, "name": db_rule.name})
    return db_rule

@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db), current_user: DBUser = Depends(require_admin)):
    db_rule = db.query(DBRule).filter(DBRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule_name = db_rule.name
    db.delete(db_rule)
    db.commit()

    log_audit(db, admin=current_user.username, action="delete_rule", target_user=None, details={"id": rule_id, "name": rule_name})
    return {"message": f"Rule {rule_id} deleted successfully"}

# ==================== Threat Alerts API ====================

@router.get("/threat-alerts", response_model=List[ThreatAlertResponse])
def get_threat_alerts(
    date: Optional[str] = None,
    alert_type: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    query = db.query(DBThreatAlert)

    if date:
        query = query.filter(DBThreatAlert.timestamp.like(f"{date}%"))
    if alert_type:
        query = query.filter(DBThreatAlert.alert_type == alert_type)
    if src:
        query = query.filter(DBThreatAlert.source_ip.contains(src))
    if dst:
        query = query.filter(DBThreatAlert.destination_ip.contains(dst))

    query = query.order_by(DBThreatAlert.timestamp.desc())

    # Simple pagination
    offset = (page - 1) * per_page
    return query.offset(offset).limit(per_page).all()

# ==================== Audit Log API ====================

@router.get("/audit-logs")
def get_audit_logs(
    action: Optional[str] = None,
    admin_user: Optional[str] = None,
    target_user: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(require_admin)
):
    is_valid, tamper_id = verify_audit_log(db)

    query = db.query(DBAuditLog)
    if action:
        query = query.filter(DBAuditLog.action == action)
    if admin_user:
        query = query.filter(DBAuditLog.admin == admin_user)
    if target_user:
        query = query.filter(DBAuditLog.target_user == target_user)

    logs = query.order_by(DBAuditLog.timestamp.desc()).all()

    return {
        "is_valid": is_valid,
        "tamper_index_id": tamper_id,
        "logs": logs
    }

# ==================== Model Metrics API ====================

@router.get("/model-metrics")
def get_model_metrics(current_user: DBUser = Depends(get_current_user)):
    from api.ids_runtime import metadata
    return metadata()

@router.post("/broadcast")
async def broadcast_alert(alert_data: dict, db: Session = Depends(get_db), worker=Depends(authorize_worker)):
    required = ["timestamp", "alert_type", "source_ip", "destination_ip"]
    if any(not isinstance(alert_data.get(key), str) or not 0 < len(alert_data[key]) <= 200 for key in required):
        raise HTTPException(422, "Invalid alert fields")
    db_alert = DBThreatAlert(
        origin=alert_data.get("origin") if alert_data.get("origin") in {"sensor", "sensor-simulation", "file-scan"} else "sensor",
        timestamp=alert_data.get("timestamp"),
        alert_type=alert_data.get("alert_type"),
        source_ip=alert_data.get("source_ip"),
        destination_ip=alert_data.get("destination_ip")
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    # Broadcast to all websocket connections
    await manager.broadcast({
        "type": "threat_alert",
        "data": {
            "id": db_alert.id,
            "origin": db_alert.origin,
            "timestamp": db_alert.timestamp,
            "alert_type": db_alert.alert_type,
            "source_ip": db_alert.source_ip,
            "destination_ip": db_alert.destination_ip
        }
    })
    return {"status": "ok", "alert_id": db_alert.id}
