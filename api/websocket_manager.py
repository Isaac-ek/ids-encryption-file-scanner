from fastapi import WebSocket
from typing import List

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.workspaces = {}

    def register(self, websocket, workspace_id):
        self.active_connections.append(websocket)
        self.workspaces[websocket] = workspace_id

    async def connect(self, websocket: WebSocket, workspace_id: int):
        await websocket.accept()
        self.register(websocket, workspace_id)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.workspaces.pop(websocket, None)

    async def broadcast(self, message: dict, workspace_id: int):
        for connection in list(self.active_connections):
            if self.workspaces.get(connection) != workspace_id:
                continue
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()
