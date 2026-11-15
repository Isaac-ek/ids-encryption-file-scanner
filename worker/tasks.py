import sys
import os
import requests
from datetime import datetime

# Add legacy directory to sys.path so legacy modules can find each other
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../legacy')))

from worker.worker import celery_app

@celery_app.task(name="worker.tasks.start_network_monitor")
def start_network_monitor_task(interface: str = "en0", simulate: bool = False):
    """
    Task to launch the network intrusion detection system (IDS) sniffer/simulation.
    """
    print(f"Starting network monitor task on interface {interface} (simulate={simulate})")

    # Dynamically configure API URL for mock socket_manager inside network_monitor
    api_url = os.getenv("API_URL", "http://localhost:8000")
    os.environ["API_URL"] = api_url

    import network_monitor as nm

    # Configure paths in legacy network_monitor/aes_encryptor to project root
    from api.settings import DATA_ROOT
    project_root = str(DATA_ROOT)
    import aes_encryptor
    aes_encryptor.BASE_DIR = project_root
    aes_encryptor.TARGET_DIR = os.path.join(project_root, "files")
    aes_encryptor.QUARANTINE_DIR = os.path.join(project_root, "encrypted")
    aes_encryptor.KEYS_DIR = os.path.join(project_root, "keys")
    aes_encryptor.RSA_PRIV_PATH = os.path.join(aes_encryptor.KEYS_DIR, "rsa_private.pem")
    aes_encryptor.RSA_PUB_PATH = os.path.join(aes_encryptor.KEYS_DIR, "rsa_public.pem")
    aes_encryptor.AES_KEY_PATH = os.path.join(aes_encryptor.KEYS_DIR, "aes_gcm_key.bin.enc")
    aes_encryptor.LOG_PATH = os.path.join(aes_encryptor.QUARANTINE_DIR, "encryption_log.json")

    # Start monitor
    nm.start_monitor(interface=interface, simulate=simulate)

@celery_app.task(name="worker.tasks.scan_file")
def scan_file_task(filepath: str, api_broadcast_url: str):
    """
    Task to asynchronously scan a file for malware and report the outcome.
    """
    print(f"Starting file scan for: {filepath}")
    import file_scanner
    scanner = file_scanner.FileScanner()

    # Prepare dummy file object for Werkzeug compat
    class DummyFile:
        def __init__(self, path):
            self.filename = os.path.basename(path)
            self.path = path
        def save(self, target_path):
            import shutil
            shutil.copy(self.path, target_path)

    dummy_file = DummyFile(filepath)
    is_safe, message = scanner.scan_file(dummy_file)

    # Forward the scan result to the API for database logging & socket broadcast
    payload = {
        "origin": "file-scan",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alert_type": "Malware Detected" if not is_safe else "Clean Scan",
        "source_ip": "FILE_SCANNER",
        "destination_ip": os.path.basename(filepath)
    }

    try:
        requests.post(api_broadcast_url, headers={"X-Worker-Token": os.getenv("WORKER_TOKEN", "")}, json=payload, timeout=5)
    except Exception as e:
        print(f"Failed to post file scan results to API: {e}")

    return {"is_safe": is_safe, "message": message}
