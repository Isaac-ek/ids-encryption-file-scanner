"""Vercel FastAPI entrypoint; local and container deployments still use api.main."""
from api.main import app
