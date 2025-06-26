from flask_socketio import SocketIO

socketio = SocketIO()

def init_socketio(app):
    socketio.init_app(app, async_mode='eventlet') 