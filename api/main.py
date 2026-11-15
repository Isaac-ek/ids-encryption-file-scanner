from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from api.auth import router as auth_router, decode_access_token
from api.alerts import router as alerts_router
from api.encryption import router as encryption_router
from api.detector import router as detector_router
from api.scans import router as scans_router
from api.websocket_manager import manager
from api.database import Base, engine, SessionLocal
from api.models import DBUser

@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    yield

app = FastAPI(title="SecureStream · IDS and Website Security", version="1.0.0", lifespan=lifespan)
for router in [auth_router, alerts_router, encryption_router, detector_router, scans_router]:
    app.include_router(router)

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.websocket("/api/ws/alerts")
async def alerts_socket(websocket: WebSocket):
    # Authenticate in the first frame, never put bearer credentials in a URL/access log.
    await websocket.accept()
    import asyncio
    try:
        packet = await asyncio.wait_for(websocket.receive_json(), timeout=5)
        if not isinstance(packet, dict):
            await websocket.close(code=1008); return
        payload = decode_access_token(packet.get("token", ""))
        with SessionLocal() as db:
            valid = payload and db.query(DBUser).filter(DBUser.username == payload.get("sub")).first()
        if not valid:
            await websocket.close(code=1008); return
        manager.active_connections.append(websocket)
        await websocket.send_json({"type":"ready"})
        while True:
            if decode_access_token(packet["token"]) is None:
                await websocket.close(code=1008); break
            await asyncio.wait_for(websocket.receive_text(), timeout=60)
    except (WebSocketDisconnect, asyncio.TimeoutError, ValueError, TypeError, KeyError):
        pass
    finally:
        manager.disconnect(websocket)

# One deployable app serves both the built React interface and authenticated APIs.
FRONTEND = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if FRONTEND.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND / "assets"), name="assets")
    @app.get("/", include_in_schema=False)
    def interface(): return FileResponse(FRONTEND / "index.html")
