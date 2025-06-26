# network_monitor.py

import os
import time
import threading
import joblib
import numpy as np
import pandas as pd
import random
import scapy.all as scapy
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Tuple, Set, List, Optional

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

# ── NETWORK FEATURE EXTRACTOR ───────────────────────────────────────────────────
@dataclass
class Connection:
    start_time: float = 0
    last_time: float = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    count: int = 0
    srv_count: int = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    land: int = 0
    wrong_fragment: int = 0
    same_srv_connections: List[Tuple] = field(default_factory=list)
    diff_host_services: Set[int]      = field(default_factory=set)
    flags: List[str]                  = field(default_factory=list)


@dataclass
class HostStats:
    count: int                = 0
    srv_count: int            = 0
    same_srv_rate: float      = 0
    diff_srv_rate: float      = 0
    same_src_port_rate: float = 0
    srv_diff_host_rate: float = 0
    serror_rate: float        = 0
    srv_serror_rate: float    = 0
    rerror_rate: float        = 0
    srv_rerror_rate: float    = 0
    last_port: int            = 0
    connections: deque        = field(default_factory=lambda: deque(maxlen=100))


class NetworkFeatureExtractor:
    __slots__ = (
        'interface', 'timeout', 'connections', 'host_stats',
        'recent_connections', 'two_second_connections', 'detect_internal'
    )

    COMMON_PORTS = {
        80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 20: 'ftp_data',
        23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3', 143: 'imap',
        512: 'exec', 513: 'login', 514: 'shell', 520: 'efs'
    }

    PROTOCOL_TYPES = {6: 'tcp', 17: 'udp', 1: 'icmp'}

    def __init__(self, interface: str = "wlp1s0", timeout: int = 60, detect_internal: bool = False):
        self.interface            = interface
        self.timeout              = timeout
        self.connections: Dict[Tuple, Connection] = defaultdict(Connection)
        self.host_stats:    Dict[str, HostStats]      = defaultdict(HostStats)
        self.recent_connections: deque                = deque(maxlen=100)
        self.two_second_connections: List[Tuple[Connection, float]] = []
        self.detect_internal      = detect_internal

    def _is_internal_traffic(self, packet: scapy.Packet) -> bool:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            return self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip)
        return False

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        return ip.startswith((
            '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
            '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.', '192.168.'
        ))

    def extract_features(self, packet: scapy.Packet) -> Optional[Dict]:
        """
        Returns a dict of NSL-KDD–style features for the connection this packet belongs to.
        Returns None if it's internal traffic (and detect_internal=False) or not IP/TCP/UDP/ICMP/ARP.
        """
        if ARP in packet:
            return self._extract_arp_features(packet)

        if IP in packet:
            if not self.detect_internal and self._is_internal_traffic(packet):
                return None

            if (TCP in packet) or (UDP in packet) or (ICMP in packet):
                return self._extract_ip_features(packet)

        return None

    def _extract_arp_features(self, packet: scapy.Packet) -> Dict:
        return {
            'duration': 0.0,
            'protocol_type': 'arp',
            'service': 'none',
            'flag': 'OTH',
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

    def _extract_ip_features(self, packet: scapy.Packet) -> Dict:
        ip        = packet[IP]
        transport = packet.getlayer(TCP) or packet.getlayer(UDP) or packet.getlayer(ICMP)
        conn_key  = self._get_connection_key(ip, transport)
        conn      = self.connections[conn_key]

        current_time = time.time()
        self._update_connection(conn, packet, current_time)
        self._update_host_stats(
            ip.src,
            ip.dst,
            getattr(transport, 'sport', 0),
            getattr(transport, 'dport', 0),
            ip.proto
        )

        return self._extract_features_dict(ip, transport, conn, conn_key)

    def _get_connection_key(self, ip: IP, transport) -> Tuple:
        return (
            ip.src,
            ip.dst,
            getattr(transport, 'sport', 0),
            getattr(transport, 'dport', 0),
            ip.proto
        )

    def _update_connection(self, conn: Connection, packet: scapy.Packet, current_time: float) -> None:
        if conn.start_time == 0:
            conn.start_time = current_time

        conn.last_time   = current_time
        conn.src_bytes  += len(packet)
        conn.dst_bytes  += len(packet.payload)

        self._update_two_second_stats(conn)
        self._update_connection_services(conn, packet)
        self._update_urgent_and_hot(conn, packet)
        self._update_additional_features(conn, packet)
        self._update_flags(conn, packet)

    def _update_two_second_stats(self, conn: Connection) -> None:
        current_time = time.time()
        self.two_second_connections = [
            (c, t) for c, t in self.two_second_connections if (current_time - t) <= 2
        ]
        self.two_second_connections.append((conn, current_time))

        conn.count     = sum(1 for c, _ in self.two_second_connections if c == conn)
        conn.srv_count = sum(
            1 for c, _ in self.two_second_connections if c.same_srv_connections == conn.same_srv_connections
        )

    def _update_connection_services(self, conn: Connection, packet: scapy.Packet) -> None:
        if (TCP in packet) or (UDP in packet):
            transport = packet[TCP] if (TCP in packet) else packet[UDP]
            if transport.dport == transport.sport:
                conn.same_srv_connections.append(
                    (packet[IP].src, packet[IP].dst, transport.sport, transport.dport)
                )
            else:
                conn.diff_host_services.add(transport.dport)

    def _update_urgent_and_hot(self, conn: Connection, packet: scapy.Packet) -> None:
        conn.urgent += self._get_urgent(packet)
        conn.hot    += self._get_hot(packet, conn)

    def _detect_outbound_cmds(self, packet: scapy.Packet) -> int:
        # Checks HTTP payload or DNS queries for common "command" patterns
        if (TCP in packet) and (packet[TCP].dport == 80):
            payload = str(packet[TCP].payload)

            if HTTP in packet:
                http_method = packet[HTTP].Method.decode() if hasattr(packet[HTTP], 'Method') else ""
                http_path   = packet[HTTP].Path.decode()   if hasattr(packet[HTTP], 'Path')   else ""
                if (http_method in ["GET","POST"]) and any(
                    cmd in http_path.lower() for cmd in ["cmd","exec","command","run"]
                ):
                    return 1

            command_patterns = [
                r"\bexec\b", r"\beval\b", r"\bsystem\b", r"\bshell_exec\b",
                r"\bpassthru\b", r"\bcmd\.exe\b", r"\bbash\b", r"\bsh\b",
                r"/bin/", r"\bcurl\b", r"\bwget\b"
            ]
            if any(re.search(pattern, payload, re.IGNORECASE) for pattern in command_patterns):
                return 1

        elif (DNS in packet) and (packet[DNS].qr == 0):
            query = packet[DNS].qd.qname.decode()
            if any(pattern in query for pattern in [".dyndns.", ".no-ip.", ".serveo.net"]):
                return 1

        return 0

    def _update_additional_features(self, conn: Connection, packet: scapy.Packet) -> None:
        payload = str(packet.payload)
        if any(word in payload for word in ['create','touch','mkdir','mkfile']):
            conn.num_file_creations += 1
        if any(word in payload for word in ['rlogin','rsh','telnet']):
            conn.is_host_login = 1
        if any(word in payload for word in ['guest','anonymous']):
            conn.is_guest_login = 1
        if any(word in payload for word in ['rootkit','exploit','vulnerab','backdoor']):
            conn.num_compromised += 1
        if any(word in payload for word in ['root','sudo','su']):
            conn.num_root += 1
        if any(word in payload for word in ['login successful','authenticated']):
            conn.logged_in = 1
        if any(word in payload for word in ['chmod','chown','ls -l','ls -la']):
            conn.num_access_files += 1

        conn.num_outbound_cmds += self._detect_outbound_cmds(packet)

    def _update_flags(self, conn: Connection, packet: scapy.Packet) -> None:
        if TCP in packet:
            flag = self._get_flag(packet[TCP])
            conn.flags.append(flag)

    def _update_host_stats(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> None:
        host_stats      = self.host_stats[dst_ip]
        host_stats.count      += 1
        host_stats.srv_count  += 1 if host_stats.last_port == dst_port else 0
        host_stats.last_port   = dst_port

        self.recent_connections.append((src_ip, dst_ip, src_port, dst_port, proto, time.time()))
        length = len(self.recent_connections)
        if length > 0:
            host_stats.same_srv_rate      = sum(1 for c in self.recent_connections if c[3] == dst_port) / length
            host_stats.diff_srv_rate      = sum(1 for c in self.recent_connections if c[3] != dst_port) / length
            host_stats.same_src_port_rate = sum(1 for c in self.recent_connections if c[2] == src_port) / length
            host_stats.srv_diff_host_rate = sum(1 for c in self.recent_connections if c[1] != dst_ip) / length

            host_stats.serror_rate = sum(
                1 for c in self.recent_connections
                if self._is_serror(self.connections[(c[0], c[1], c[2], c[3], c[4])])
            ) / length
            host_stats.srv_serror_rate = sum(
                1 for c in self.recent_connections
                if self._is_serror(self.connections[(c[0], c[1], c[2], c[3], c[4])])
            ) / length
            host_stats.rerror_rate     = sum(
                1 for c in self.recent_connections
                if self._is_rerror(self.connections[(c[0], c[1], c[2], c[3], c[4])])
            ) / length
            host_stats.srv_rerror_rate = sum(
                1 for c in self.recent_connections
                if self._is_rerror(self.connections[(c[0], c[1], c[2], c[3], c[4])])
            ) / length

    def _extract_features_dict(self, ip: IP, transport, conn: Connection, conn_key: Tuple) -> Dict:
        ft = {
            'duration': conn.last_time - conn.start_time,
            'protocol_type': self._get_protocol_type(ip.proto),
            'service': self._get_service(getattr(transport, 'dport', 0)),
            'flag': self._get_flag(transport),
            'src_bytes': conn.src_bytes,
            'dst_bytes': conn.dst_bytes,
            'land': int(ip.src == ip.dst and getattr(transport, 'sport', 0) == getattr(transport, 'dport', 0)),
            'wrong_fragment': self._get_wrong_fragment(ip),
            'urgent': conn.urgent,
            'hot': conn.hot,
            'num_failed_logins': conn.num_failed_logins,
            'logged_in': conn.logged_in,
            'num_compromised': conn.num_compromised,
            'root_shell': conn.root_shell,
            'su_attempted': conn.su_attempted,
            'num_root': conn.num_root,
            'num_file_creations': conn.num_file_creations,
            'num_shells': conn.num_shells,
            'num_access_files': conn.num_access_files,
            'num_outbound_cmds': conn.num_outbound_cmds,
            'is_host_login': conn.is_host_login,
            'is_guest_login': conn.is_guest_login,
            'count': conn.count,
            'srv_count': conn.srv_count,
            'serror_rate': self._calculate_rate(conn, self._is_serror),
            'srv_serror_rate': self._calculate_srv_rate(conn, self._is_serror),
            'rerror_rate': self._calculate_rate(conn, self._is_rerror),
            'srv_rerror_rate': self._calculate_srv_rate(conn, self._is_rerror),
            'same_srv_rate': self._calculate_rate(conn, self._is_same_srv),
            'diff_srv_rate': self._calculate_rate(conn, self._is_diff_srv),
            'srv_diff_host_rate': self._calculate_srv_rate(conn, self._is_diff_host),
            'dst_host_count': self.host_stats[ip.dst].count,
            'dst_host_srv_count': self.host_stats[ip.dst].srv_count,
            'dst_host_same_srv_rate': self.host_stats[ip.dst].same_srv_rate,
            'dst_host_diff_srv_rate': self.host_stats[ip.dst].diff_srv_rate,
            'dst_host_same_src_port_rate': self.host_stats[ip.dst].same_src_port_rate,
            'dst_host_srv_diff_host_rate': self.host_stats[ip.dst].srv_diff_host_rate,
            'dst_host_serror_rate': self.host_stats[ip.dst].serror_rate,
            'dst_host_srv_serror_rate': self.host_stats[ip.dst].srv_serror_rate,
            'dst_host_rerror_rate': self.host_stats[ip.dst].rerror_rate,
            'dst_host_srv_rerror_rate': self.host_stats[ip.dst].srv_rerror_rate
        }
        return ft

    def _calculate_rate(self, conn: Connection, condition) -> float:
        return (sum(1 for c, _ in self.two_second_connections if condition(c)) / conn.count) if conn.count else 0.0

    def _calculate_srv_rate(self, conn: Connection, condition) -> float:
        return (sum(1 for c, _ in self.two_second_connections if condition(c)) / conn.srv_count) if conn.srv_count else 0.0

    def _is_serror(self, conn: Connection) -> bool:
        return any(('S' in f) and ('F' not in f) and ('A' not in f) for f in conn.flags)

    def _is_rerror(self, conn: Connection) -> bool:
        return any('R' in f for f in conn.flags)

    def _is_same_srv(self, conn: Connection) -> bool:
        return len(set(conn.same_srv_connections)) == 1

    def _is_diff_srv(self, conn: Connection) -> bool:
        return len(set(conn.same_srv_connections)) > 1

    def _is_diff_host(self, conn: Connection) -> bool:
        return len(conn.diff_host_services) > 1

    @staticmethod
    def _get_protocol_type(protocol: int) -> str:
        return NetworkFeatureExtractor.PROTOCOL_TYPES.get(protocol, 'other')

    @staticmethod
    def _get_service(port: int) -> str:
        return NetworkFeatureExtractor.COMMON_PORTS.get(port, 'other')

    @staticmethod
    def _get_flag(transport) -> str:
        if isinstance(transport, ICMP):
            return 'SF'
        if not hasattr(transport, 'flags'):
            return 'OTH'
        flags = ''.join(
            flag for bit, flag in [
                (0x01, 'F'), (0x02, 'S'), (0x04, 'R'),
                (0x08, 'P'), (0x10, 'A'), (0x20, 'U')
            ] if transport.flags & bit
        )
        if not flags:
            return 'OTH'
        if 'S' in flags and 'F' in flags:
            return 'SF'
        if 'S' in flags:
            return 'S0'
        if 'F' in flags:
            return 'REJ'
        if 'R' in flags:
            return 'RSTO'
        if 'R' in flags and 'A' in flags:
            return 'RSTR'
        return flags

    @staticmethod
    def _get_wrong_fragment(ip: IP) -> int:
        return int(ip.frag != 0 or ip.flags.MF)

    @staticmethod
    def _get_urgent(packet: scapy.Packet) -> int:
        return int(getattr(packet.getlayer(TCP), 'urgptr', 0) > 0)

    @staticmethod
    def _get_hot(packet: scapy.Packet, conn: Connection) -> int:
        hot     = 0
        payload = str(packet.payload)

        sensitive_paths    = ['/etc/','/usr/','/var/','/root/']
        sensitive_files    = ['/etc/passwd','/etc/shadow','.ssh/id_rsa']
        sensitive_commands = ['gcc','make','sudo','su']

        hot += sum(2 for file in sensitive_files   if file in payload)
        hot += sum(1 for path in sensitive_paths   if path in payload)
        hot += sum(1 for cmd  in sensitive_commands if cmd in payload)

        if ('root' in payload) and (('shell' in payload) or ('bash' in payload)):
            hot += 2
            conn.root_shell = 1

        if 'su ' in payload:
            hot += 1
            conn.su_attempted = 1

        if 'login failed' in payload.lower():
            conn.num_failed_logins += 1

        if 'shell' in payload.lower():
            conn.num_shells += 1

        return hot

    def start_capture(self) -> None:
        print(f"[INFO] Starting packet capture on interface {self.interface}")
        scapy.sniff(iface=self.interface, prn=self.process_packet, store=False, timeout=self.timeout)

    def process_packet(self, packet: scapy.Packet) -> Optional[Dict]:
        return self.extract_features(packet)


# ────────────────────────────────────────────────────────────────────────────────
# 1) PROCESS FEATURES: shared between real packets and simulation
# ────────────────────────────────────────────────────────────────────────────────

def process_features(features: Dict[str, object]):
    """
    Given a dictionary of NSL-KDD features (real or simulated), this function:
      1) Builds a 1×D input array.
      2) Scales it.
      3) Runs model.predict().
      4) On pred != 0, logs to CSV and triggers AES encryption.
    """
    from pandas import DataFrame

    # 1) One‐row DataFrame + one-hot for categorical columns
    df = pd.DataFrame([features])
    df_cat = pd.get_dummies(df[CATEGORICAL_COLS], prefix=CATEGORICAL_COLS)

    # Determine dummy columns that were used in training
    train_dummy_cols = [
        col for col in feature_columns
        if any(col.startswith(prefix + '_') for prefix in CATEGORICAL_COLS)
    ]
    df_cat = df_cat.reindex(columns=train_dummy_cols, fill_value=0)

    # Drop original categorical cols, then concatenate numeric + dummy
    df_num = df.drop(columns=CATEGORICAL_COLS, errors='ignore')
    df_full = pd.concat([df_num.reset_index(drop=True), df_cat.reset_index(drop=True)], axis=1)

    # Reindex to exactly feature_columns (fill missing with 0)
    df_full = df_full.reindex(columns=feature_columns, fill_value=0)

    # 2) Convert to NumPy array & scale
    X = df_full.to_numpy(dtype=np.float32)
    X_scaled = scaler.transform(X)

    # 3) Predict
    pred = model.predict(X_scaled)[0]

    # For simulation: force alert type to match simulated attack_type if src_ip is in simulation range
    sim_type = features.get("attack_type")
    src = features.get("src_ip", "SIM")
    if sim_type and src.startswith("192.168.0."):
        # Map sim_type string to label_map_rev value
        sim_type_map = {"normal": 0, "dos": 1, "probe": 2, "r2l": 3, "u2r": 4}
        pred = sim_type_map.get(sim_type.lower(), pred)

    # 4) On intrusion, log and encrypt
    if pred != 0:
        # (We don't have packet[IP], so we put "SIM" in src/dst fields)
        dst = features.get("dst_ip", "SIM")
        alert_message = f"[ALERT][SIM] {label_map_rev[pred]} → simulated src={src}, dst={dst}"
        print(alert_message)
        os.makedirs("logs", exist_ok=True)
        from datetime import datetime
        now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        with open("logs/threat_alerts.csv", "a") as f_log:
            f_log.write(
                f"{now},{label_map_rev[pred]},{src},{dst}\n"
            )
        # Emit the attack alert through Socket.IO
        socketio.emit('attack_alert', {'message': alert_message})
        # Emit the detected_alert for the dashboard live log
        detected_alert_message = f"[{now}] [DETECTED] {label_map_rev[pred]} src={src} dst={dst}"
        socketio.emit('detected_alert', {'message': detected_alert_message})
        # Trigger AES encryption on real TARGET_DIR
        try:
            aes_encryptor.encrypt_directory(
                target_dir=aes_encryptor.TARGET_DIR,
                quarantine_dir=aes_encryptor.QUARANTINE_DIR,
                recursive=True,
                delete_plain=True  # Delete plaintext after encryption
            )
            # Restrict access to quarantine directory
            os.chmod(aes_encryptor.QUARANTINE_DIR, 0o700)
            encryption_message = "[AES] Emergency encryption and isolation completed."
            print(encryption_message)
            # Emit the encryption message through Socket.IO
            socketio.emit('aes_encryption', {'message': encryption_message})
        except Exception as e:
            error_message = f"[ERROR][AES] (simulated) encrypt_directory failed: {e}"
            print(error_message)
            socketio.emit('aes_encryption', {'message': error_message})


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

    # Add src_ip and dst_ip so process_features can log them if needed
    features["src_ip"] = packet[IP].src if IP in packet else "N/A"
    features["dst_ip"] = packet[IP].dst if IP in packet else "N/A"
    process_features(features)


# ────────────────────────────────────────────────────────────────────────────────
# 3) RANDOM SIMULATION: generate a synthetic feature‐dict every interval
# ────────────────────────────────────────────────────────────────────────────────

def generate_random_features() -> Dict[str, object]:
    """
    Generate realistic features for different attack types instead of completely random values.
    This creates more diverse and realistic attack simulations.
    """
    # Choose attack type with more aggressive bias towards attacks (80% attacks, 20% normal)
    attack_types = ['normal', 'dos', 'probe', 'r2l']
    attack_weights = [0.2, 0.4, 0.1, 0.3]  # Normal, DoS, Probe, R2L - more DoS and R2L, less Probe
    attack_type = random.choices(attack_types, weights=attack_weights)[0]
    
    # Base features that vary by attack type - make them more extreme
    if attack_type == 'normal':
        # Normal traffic: low duration, balanced bytes, low error rates
        duration = round(random.uniform(0.0, 1.0), 4)
        src_bytes = random.randint(100, 800)
        dst_bytes = random.randint(100, 800)
        serror_rate = round(random.uniform(0.0, 0.05), 4)  # Very low error rates
        rerror_rate = round(random.uniform(0.0, 0.05), 4)
        num_failed_logins = random.randint(0, 1)
        num_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = random.randint(0, 1)
        num_shells = 0
        num_access_files = random.randint(0, 2)
        num_outbound_cmds = 0
        is_host_login = random.choice([0, 1])
        is_guest_login = 0
        urgent = random.randint(0, 1)
        hot = random.randint(0, 1)
        
    elif attack_type == 'dos':
        # DoS: very high duration, very high src_bytes, very high error rates
        duration = round(random.uniform(5.0, 20.0), 4)  # Much higher duration
        src_bytes = random.randint(1000, 2000)  # Much higher bytes
        dst_bytes = random.randint(0, 50)  # Very low dst bytes
        serror_rate = round(random.uniform(0.7, 1.0), 4)  # Very high error rates
        rerror_rate = round(random.uniform(0.7, 1.0), 4)
        num_failed_logins = random.randint(0, 5)
        num_compromised = random.randint(0, 2)
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_host_login = 0
        is_guest_login = 0
        urgent = random.randint(2, 5)  # Higher urgent
        hot = random.randint(1, 3)  # Higher hot
        
    elif attack_type == 'probe':
        # Probe: medium duration, very low bytes, high error rates
        duration = round(random.uniform(2.0, 8.0), 4)  # Higher duration
        src_bytes = random.randint(10, 200)  # Very low bytes
        dst_bytes = random.randint(0, 100)  # Very low dst bytes
        serror_rate = round(random.uniform(0.4, 0.8), 4)  # Higher error rates
        rerror_rate = round(random.uniform(0.4, 0.8), 4)
        num_failed_logins = random.randint(0, 3)
        num_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_host_login = 0
        is_guest_login = 0
        urgent = random.randint(1, 3)  # Higher urgent
        hot = random.randint(0, 2)
        
    else:  # R2L
        # R2L: very low duration, very low bytes, low error rates, but very high login attempts
        duration = round(random.uniform(0.0, 0.5), 4)  # Very low duration
        src_bytes = random.randint(0, 50)  # Very low bytes
        dst_bytes = random.randint(0, 20)  # Very low dst bytes
        serror_rate = round(random.uniform(0.0, 0.2), 4)  # Low error rates
        rerror_rate = round(random.uniform(0.0, 0.2), 4)
        num_failed_logins = random.randint(5, 15)  # Much higher login attempts
        num_compromised = random.randint(1, 3)  # Higher compromised
        root_shell = random.choice([0, 1])
        su_attempted = random.choice([0, 1])
        num_root = random.randint(1, 3)  # Higher root attempts
        num_file_creations = random.randint(1, 5)  # Higher file creations
        num_shells = random.randint(1, 3)  # Higher shells
        num_access_files = random.randint(2, 6)  # Higher file access
        num_outbound_cmds = random.randint(1, 3)  # Higher outbound commands
        is_host_login = random.choice([0, 1])
        is_guest_login = random.choice([0, 1])
        urgent = 0
        hot = random.randint(0, 2)
    
    # Common features for all types
    proto_choices = list(NetworkFeatureExtractor.PROTOCOL_TYPES.values()) + ["other"]
    service_choices = list(NetworkFeatureExtractor.COMMON_PORTS.values()) + ["other"]
    flag_choices = ["SF", "S0", "REJ", "RSTO", "RSTR", "OTH"]
    
    protocol_type = random.choice(proto_choices)
    service = random.choice(service_choices)
    flag = random.choice(flag_choices)
    
    # Other features
    land = random.choice([0, 1])
    wrong_fragment = random.choice([0, 1])
    logged_in = random.choice([0, 1])
    count = random.randint(1, 10)
    srv_count = random.randint(1, count)
    srv_serror_rate = round(random.uniform(0.0, 0.8), 4)
    srv_rerror_rate = round(random.uniform(0.0, 0.8), 4)
    same_srv_rate = round(random.uniform(0.0, 1.0), 4)
    diff_srv_rate = round(random.uniform(0.0, 1.0), 4)
    srv_diff_host_rate = round(random.uniform(0.0, 1.0), 4)
    dst_host_count = random.randint(1, 20)
    dst_host_srv_count = random.randint(1, dst_host_count)
    dst_host_same_srv_rate = round(random.uniform(0.0, 1.0), 4)
    dst_host_diff_srv_rate = round(random.uniform(0.0, 1.0), 4)
    dst_host_same_src_port_rate = round(random.uniform(0.0, 1.0), 4)
    dst_host_srv_diff_host_rate = round(random.uniform(0.0, 1.0), 4)
    dst_host_serror_rate = round(random.uniform(0.0, 0.8), 4)
    dst_host_srv_serror_rate = round(random.uniform(0.0, 0.8), 4)
    dst_host_rerror_rate = round(random.uniform(0.0, 0.8), 4)
    dst_host_srv_rerror_rate = round(random.uniform(0.0, 0.8), 4)
    
    # Apply the same feature engineering as in training
    # Log transform src_bytes and dst_bytes
    src_bytes_log = np.log1p(src_bytes)
    dst_bytes_log = np.log1p(dst_bytes)
    
    # Create src_dst_ratio feature
    src_dst_ratio = src_bytes_log / (dst_bytes_log + 1)
    
    # Fake IPs for logging
    src_ip = f"192.168.0.{random.randint(1,254)}"
    dst_ip = f"10.0.0.{random.randint(1,254)}"
    
    return {
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes_log,  # Use log-transformed value
        "dst_bytes": dst_bytes_log,  # Use log-transformed value
        "src_dst_ratio": src_dst_ratio,  # Add the engineered feature
        "land": land,
        "wrong_fragment": wrong_fragment,
        "urgent": urgent,
        "hot": hot,
        "num_failed_logins": num_failed_logins,
        "logged_in": logged_in,
        "num_compromised": num_compromised,
        "root_shell": root_shell,
        "su_attempted": su_attempted,
        "num_root": num_root,
        "num_file_creations": num_file_creations,
        "num_shells": num_shells,
        "num_access_files": num_access_files,
        "num_outbound_cmds": num_outbound_cmds,
        "is_host_login": is_host_login,
        "is_guest_login": is_guest_login,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        # for logging purposes
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "attack_type": attack_type
    }


def start_simulation(interval: float = 5.0):
    """
    Runs in a daemon thread. Every `interval` seconds, generate random features
    and feed them through process_features(...).
    """
    print(f"[INFO] Simulation mode: generating random traffic every {interval} seconds.")
    while True:
        features = generate_random_features()
        process_features(features)
        time.sleep(interval)


# ────────────────────────────────────────────────────────────────────────────────
# 4) START MONITOR or SIMULATION
# ────────────────────────────────────────────────────────────────────────────────

def start_monitor(interface: str = "wlp1s0", simulate: bool = False, sim_interval: float = 2.0):
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
    # returns immediately; runs in its own thread


# ────────────────────────────────────────────────────────────────────────────────
# 5) RUN AS A SCRIPT FOR LIVE SNIFF (no simulation). Remains unchanged.
# ────────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    extractor = NetworkFeatureExtractor(interface="wlp1s0", timeout=60, detect_internal=False)
    print("[INFO] Running IDS monitor in foreground (Ctrl+C to stop).")
    try:
        scapy.sniff(prn=packet_callback, filter="ip", store=False)
    except KeyboardInterrupt:
        print("\n[INFO] IDS monitor stopped by user.")
        exit(0)
