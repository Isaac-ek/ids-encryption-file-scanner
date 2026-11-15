import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IS_VERCEL = os.getenv("VERCEL") == "1"
DATA_ROOT = Path(os.getenv("SECURITY_DATA_DIR", Path(tempfile.gettempdir()) / "securestream" if IS_VERCEL else ROOT / ".runtime")).resolve()
FILE_STORAGE_BACKEND = os.getenv("FILE_STORAGE_BACKEND", "local")
if FILE_STORAGE_BACKEND not in {"local", "database"}:
    raise RuntimeError("FILE_STORAGE_BACKEND must be local or database")
if IS_VERCEL and (FILE_STORAGE_BACKEND != "database" or not os.getenv("DATABASE_URL", "").startswith(("postgresql://", "postgresql+psycopg2://"))):
    raise RuntimeError("Vercel requires PostgreSQL and FILE_STORAGE_BACKEND=database; ephemeral storage is not supported for customer data")
MODEL_ROOT = Path(os.getenv("IDS_MODEL_DIR", ROOT / "models2")).resolve()
MAX_UPLOAD_BYTES = (3 if IS_VERCEL else 8) * 1024 * 1024

def required_secret(name):
    value = os.environ.get(name, "")
    if len(value) < 32 or value.startswith("replace-with-"):
        raise RuntimeError(f"{name} must be set to a random secret of at least 32 characters")
    return value
