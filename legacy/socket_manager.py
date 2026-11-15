"""Forward structured IDS alerts to the authenticated shared API."""
import os
import requests

class AlertBridge:
    def emit(self, event, data=None, *args, **kwargs):
        if event != 'attack_alert' or not data:
            return
        payload = {key: data[key] for key in (
            'timestamp', 'alert_type', 'source_ip', 'destination_ip', 'origin'
        )}
        try:
            response = requests.post(
                os.getenv('API_URL', 'http://localhost:8000') + '/api/alerts/broadcast',
                headers={'X-Worker-Token': os.getenv('WORKER_TOKEN', '')},
                json=payload, timeout=5,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            print(f'Alert delivery failed: {type(error).__name__}')

socketio = AlertBridge()

def init_socketio(app):
    pass
