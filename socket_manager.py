import os
from flask_socketio import SocketIO

socketio = SocketIO()

def init_socketio(app):
    async_mode = 'threading' if os.environ.get('VERCEL') else 'eventlet'
    socketio.init_app(app, async_mode=async_mode)
