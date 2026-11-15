from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from api.auth import get_current_user, DBUser
from api.database import get_db
from api.models import DBThreatAlert
from api.audit import log_audit
from api.ids_runtime import metadata, predict

router = APIRouter(prefix="/api/detector", tags=["Trained intrusion detector"])

class PredictionInput(BaseModel):
    features: dict[str, float | int | str] = Field(max_length=128)
    source_ip: str = Field(default="sample-replay", max_length=100)
    destination_ip: str = Field(default="local-lab", max_length=100)

@router.get("/status")
def status(user: DBUser = Depends(get_current_user)):
    return metadata()

@router.post("/predict")
def classify(payload: PredictionInput, db: Session = Depends(get_db), user: DBUser = Depends(get_current_user)):
    try:
        result = predict(payload.features)
    except ValueError as error:
        raise HTTPException(422, str(error))
    except Exception:
        raise HTTPException(503, "The trained detector bundle could not process this record")
    event = DBThreatAlert(timestamp=datetime.now(timezone.utc).isoformat(), alert_type=result["label"], source_ip=payload.source_ip, destination_ip=payload.destination_ip, origin="model-replay")
    db.add(event); db.commit(); db.refresh(event)
    log_audit(db, user.username, "model_prediction", None, {"event_id": event.id, **result, "origin": "model-replay"})
    return {**result, "event_id": event.id, "origin": "model-replay", "note": "Prediction on supplied features; this is not live packet capture."}

@router.get("/sample")
def sample(user: DBUser = Depends(get_current_user)):
    import json
    from api.settings import ROOT
    return json.loads((ROOT / "examples" / "connection.json").read_text())
