import os
import tempfile

os.environ.setdefault("DISABLE_IDS_MONITOR", "1")
os.environ.setdefault(
    "APP_STORAGE_DIR",
    os.path.join(tempfile.gettempdir(), "ids-encryption-file-scanner"),
)
os.environ.setdefault(
    "SCAN_TEMP_DIR",
    os.path.join(tempfile.gettempdir(), "ids-encryption-file-scanner-scan"),
)
os.environ.setdefault("SECRET_KEY", "vercel-demo-secret-change-me")

from app import app as app
