"""Provision two isolated fictional customers for browser checks only."""
import os, runpy
from pathlib import Path
root = Path(__file__).resolve().parents[1]
runpy.run_path(str(root / "scripts/create_admin.py"), run_name="__main__")
os.environ.update(BOOTSTRAP_USERNAME="other-customer", BOOTSTRAP_PASSWORD="isolated-other-password", BOOTSTRAP_WORKSPACE="other-customer", BOOTSTRAP_WORKSPACE_NAME="Other customer workspace")
runpy.run_path(str(root / "scripts/create_admin.py"), run_name="__main__")
