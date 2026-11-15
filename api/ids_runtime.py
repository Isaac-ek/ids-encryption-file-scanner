"""Load the preserved detector bundle and apply its existing feature ordering/scaler."""
from functools import lru_cache
from hashlib import sha256
import json
import joblib
import numpy as np
import pandas as pd
from api.settings import MODEL_ROOT

LABELS = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}
CATEGORICAL = ["protocol_type", "service", "flag"]

@lru_cache(maxsize=1)
def bundle():
    model = joblib.load(MODEL_ROOT / "ids_model_full.joblib")
    scaler = joblib.load(MODEL_ROOT / "scaler.joblib")
    columns = joblib.load(MODEL_ROOT / "feature_columns.joblib")
    return model, scaler, columns

def artifact_hashes():
    return {name: sha256((MODEL_ROOT / name).read_bytes()).hexdigest() for name in ("ids_model_full.joblib", "scaler.joblib", "feature_columns.joblib")}

def metadata():
    try:
        model, _, columns = bundle()
        result = {"available": True, "model_type": type(model).__name__, "features": len(columns), "artifact_sha256": sha256((MODEL_ROOT / "ids_model_full.joblib").read_bytes()).hexdigest()}
        hashes = artifact_hashes()
        result["bundle_sha256"] = hashes
        report = MODEL_ROOT / "evaluation.json"
        if report.exists():
            evaluation = json.loads(report.read_text())
            if evaluation.get("bundle_sha256") == hashes:
                result["evaluation"] = evaluation
        from api.flow_features import UNOBSERVED
        result["live_capture"] = {"status": "experimental", "schema": "bidirectional-flow-v1", "unobserved_features": UNOBSERVED, "note": "Network-only flow extraction does not observe NSL-KDD host/content fields. Live predictions are not validated protection."}
        return result
    except Exception as error:
        return {"available": False, "model_type": None, "detail": "Detector bundle is unavailable or incompatible", "error_type": type(error).__name__}

def encode_features(features, columns):
    frame = pd.DataFrame([features])
    for column in CATEGORICAL:
        if column not in frame:
            raise ValueError(f"Missing categorical feature: {column}")
    numeric_columns = [name for name in columns if not any(name.startswith(prefix + "_") for prefix in CATEGORICAL)]
    missing = [name for name in numeric_columns if name not in features]
    if missing:
        raise ValueError("Missing numeric features: " + ", ".join(missing))
    for name in CATEGORICAL:
        if f"{name}_{features[name]}" not in columns:
            raise ValueError(f"Unknown categorical value for {name}")
    encoded = pd.get_dummies(frame[CATEGORICAL], prefix=CATEGORICAL)
    numeric = frame.drop(columns=CATEGORICAL, errors="ignore")
    full = pd.concat([numeric, encoded], axis=1).reindex(columns=columns, fill_value=0)
    values = full.to_numpy(dtype=np.float32)
    if not np.isfinite(values).all():
        raise ValueError("Features must be finite numeric values")
    return values

def predict(features):
    model, scaler, columns = bundle()
    transformed = scaler.transform(encode_features(features, columns))
    prediction = int(model.predict(transformed)[0])
    return {"label": LABELS[prediction], "class_id": prediction, "model_type": type(model).__name__, "feature_count": len(columns)}
