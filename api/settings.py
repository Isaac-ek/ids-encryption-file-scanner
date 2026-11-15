import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(os.getenv("SECURITY_DATA_DIR", ROOT / ".runtime")).resolve()
MODEL_ROOT = Path(os.getenv("IDS_MODEL_DIR", ROOT / "models2")).resolve()
MAX_UPLOAD_BYTES = 8 * 1024 * 1024

def required_secret(name):
    value = os.environ.get(name, "")
    if len(value) < 32 or value.startswith("replace-with-"):
        raise RuntimeError(f"{name} must be set to a random secret of at least 32 characters")
    return value
