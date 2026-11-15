# network_monitor.py

import os
import time
import threading
import joblib
import random
import scapy.all as scapy
from datetime import datetime


from typing import Dict

from config import MODEL_DIR
import aes_encryptor  # your enhanced AES module
from socket_manager import socketio

# ── LOAD TRAINED ARTIFACTS ──────────────────────────────────────────────────────
MODEL_PATH = os.path.join(MODEL_DIR, "ids_model_full.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.joblib")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
label_map_rev = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}

# Shared bounded flow extractor; retained training artifacts remain unchanged.
from api.flow_features import NetworkFeatureExtractor

def process_features(features: Dict[str, object], simulated: bool = False):
    """
    Given a dictionary of NSL-KDD features (real or simulated), this function:
      1) Builds a 1×D input array.
      2) Scales it.
      3) Runs model.predict().
      4) On pred != 0, emits a labelled event without changing files.
    """
    from api.ids_runtime import encode_features
    try:
        X = encode_features(features, feature_columns)
    except ValueError as error:
        print(f"[SKIP] Unsupported flow schema: {error}")
        return
    pred = model.predict(scaler.transform(X))[0]

    # Preserve the actual model prediction for replayed samples.
    src = features.get("src_ip", "sample-replay")
    # 4) On intrusion, log and encrypt
    if pred != 0:
        dst = features.get("dst_ip", "sample-target")
        origin = "sensor-simulation" if simulated else "sensor"
        alert_message = f"[ALERT][{origin}] {label_map_rev[pred]} src={src}, dst={dst}"
        print(alert_message)
        from api.settings import DATA_ROOT
        log_dir = DATA_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        from datetime import datetime
        from datetime import timezone
        now = datetime.now(timezone.utc).isoformat()
        with (log_dir / "threat_alerts.csv").open("a") as f_log:
            f_log.write(
                f"{now},{label_map_rev[pred]},{src},{dst}\n"
            )
        socketio.emit('attack_alert', {
            'message': alert_message, 'timestamp': now, 'origin': origin,
            'alert_type': label_map_rev[pred], 'source_ip': src, 'destination_ip': dst
        })
        # File changes require an authenticated customer-scoped API action.
        return


# ────────────────────────────────────────────────────────────────────────────────
# 2) PACKET CALLBACK (real‐sniffed packets)
# ────────────────────────────────────────────────────────────────────────────────

def packet_callback(packet):
    """
    Called by AsyncSniffer for each real packet. Extract features, then hand to process_features().
    """
    features = extractor.extract_features(packet)
    if features is None:
        return

    process_features(features)


# ────────────────────────────────────────────────────────────────────────────────
# 3) RANDOM SIMULATION: generate a synthetic feature‐dict every interval
# ────────────────────────────────────────────────────────────────────────────────

def generate_random_features() -> Dict[str, object]:
    """Replay raw sample features; dataset labels never override predictions."""
    import json
    from api.settings import ROOT
    samples = json.loads((ROOT / "examples/connection-cases.json").read_text())
    features = dict(random.choice(samples["cases"])["features"])
    features.update(src_ip="sample-replay", dst_ip="local-lab")
    return features


def start_simulation(interval: float = 5.0):
    """
    Runs in a daemon thread. Every `interval` seconds, generate random features
    and feed them through process_features(...).
    """
    print(f"[INFO] Simulation mode: generating random traffic every {interval} seconds.")
    while True:
        features = generate_random_features()
        process_features(features, simulated=True)
        time.sleep(interval)


# ────────────────────────────────────────────────────────────────────────────────
# 4) START MONITOR or SIMULATION
# ────────────────────────────────────────────────────────────────────────────────

def start_monitor(interface: str = "en0", simulate: bool = False, sim_interval: float = 2.0):
    """
    If simulate=False (default), starts AsyncSniffer on `interface` and processes real packets.
    If simulate=True, spawns a background thread that generates random features every `sim_interval` seconds.
    """
    global extractor

    if simulate:
        # No real sniffing at all: just spawn the simulation thread
        sim_thread = threading.Thread(target=lambda: start_simulation(interval=sim_interval), daemon=True)
        sim_thread.start()
        return

    # Otherwise, start real‐packet sniffing via AsyncSniffer
    extractor = NetworkFeatureExtractor(interface=interface, timeout=60, detect_internal=False)
    print("[INFO] Background IDS monitor starting on interface:", interface)
    from scapy.all import AsyncSniffer
    sniffer = AsyncSniffer(
        iface=interface,
        prn=packet_callback,
        filter="ip",
        store=False
    )
    sniffer.start()
    def flush_idle_flows():
        while sniffer.running:
            time.sleep(1)
            for features in extractor.drain_expired():
                process_features(features)
    threading.Thread(target=flush_idle_flows, daemon=True).start()
    # returns immediately; runs in its own thread


# ────────────────────────────────────────────────────────────────────────────────
# 5) RUN AS A SCRIPT FOR LIVE SNIFF (no simulation). Remains unchanged.
# ────────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    extractor = NetworkFeatureExtractor(interface="en0", timeout=60, detect_internal=False)
    print("[INFO] Running IDS monitor in foreground (Ctrl+C to stop).")
    try:
        scapy.sniff(prn=packet_callback, filter="ip", store=False)
    except KeyboardInterrupt:
        print("\n[INFO] IDS monitor stopped by user.")
        exit(0)
