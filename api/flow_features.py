"""Bounded bidirectional flow mechanics; NSL content fields remain unobserved.

This is an approximate network-only schema, not a reconstruction of NSL-KDD's
host/content instrumentation. Predictions must remain experimental.
"""
from collections import OrderedDict, deque
from dataclasses import dataclass, field
import ipaddress
import hashlib
import threading
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from legacy.ids_features import COL_NAMES

SERVICES = {80: "http", 443: "http_443", 22: "ssh", 21: "ftp", 20: "ftp_data", 23: "telnet", 25: "smtp", 110: "pop_3", 143: "imap4"}
UNOBSERVED = ["hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "wrong_fragment"]

@dataclass
class Flow:
    key: tuple
    start: float
    last: float
    src_bytes: int = 0
    dst_bytes: int = 0
    urgent: int = 0
    fragments: int = 0
    syn: bool = False
    acknowledged: bool = False
    reset: bool = False
    fin: set = field(default_factory=set)

class NetworkFeatureExtractor:
    def __init__(self, interface="en0", timeout=60, detect_internal=False, max_flows=4096, clock=time.monotonic):
        self.interface, self.timeout, self.detect_internal = interface, timeout, detect_internal
        self.max_flows, self.clock = max_flows, clock
        self.connections = OrderedDict()
        self.history = deque(maxlen=4096)
        self.ready = deque()
        self.lock = threading.RLock()

    def extract_features(self, packet):
        with self.lock:
            now = self.clock()
            self._expire(now)
            if IP not in packet or not any(layer in packet for layer in [TCP, UDP, ICMP]):
                return self.ready.popleft() if self.ready else None
            ip = packet[IP]
            if not self.detect_internal and ipaddress.ip_address(ip.src).is_private and ipaddress.ip_address(ip.dst).is_private:
                return self.ready.popleft() if self.ready else None
            transport = packet.getlayer(TCP) or packet.getlayer(UDP) or packet.getlayer(ICMP)
            sport, dport = getattr(transport, "sport", 0), getattr(transport, "dport", 0)
            # ICMP identifier prevents unrelated echo exchanges sharing one flow.
            if ICMP in packet:
                sport = dport = getattr(transport, "id", 0)
            key = (ip.src, ip.dst, sport, dport, ip.proto)
            reverse = (ip.dst, ip.src, dport, sport, ip.proto)
            direction = 0
            if reverse in self.connections:
                key, direction = reverse, 1
            if key not in self.connections:
                if len(self.connections) >= self.max_flows:
                    _, old = self.connections.popitem(last=False)
                    self.ready.append(self._finish(old, now))
                self.connections[key] = Flow(key, now, now)
            flow = self.connections[key]
            flow.last = now
            self.connections.move_to_end(key)
            size = len(bytes(transport.payload))
            if direction: flow.dst_bytes += size
            else: flow.src_bytes += size
            flow.fragments += int(bool(int(ip.frag)))
            if TCP in packet:
                flags = int(transport.flags)
                flow.syn |= bool(flags & 2)
                flow.acknowledged |= direction == 1 and bool(flags & 16)
                flow.reset |= bool(flags & 4)
                flow.urgent += int(bool(flags & 32))
                if flags & 1: flow.fin.add(direction)
                if flow.reset or len(flow.fin) == 2:
                    del self.connections[key]
                    self.ready.append(self._finish(flow, now))
            elif ICMP in packet and int(transport.type) == 0:
                del self.connections[key]
                self.ready.append(self._finish(flow, now))
            return self.ready.popleft() if self.ready else None

    def _expire(self, now):
        expired = [key for key, flow in self.connections.items() if now - flow.last >= self.timeout]
        for key in expired:
            self.ready.append(self._finish(self.connections.pop(key), now))

    def drain_expired(self):
        with self.lock:
            self._expire(self.clock())
            results = list(self.ready); self.ready.clear()
            return results

    def _finish(self, flow, now):
        src, dst, sport, dport, proto = flow.key
        service = "domain_u" if proto == 17 and dport == 53 else "domain" if dport == 53 else SERVICES.get(dport, "other")
        if proto == 1: service = "eco_i"
        flag = "REJ" if flow.reset and not flow.acknowledged else "RSTO" if flow.reset else "SF" if proto != 6 or len(flow.fin) == 2 else "S1" if flow.acknowledged else "S0" if flow.syn else "OTH"
        record = {"time": now, "dst": dst, "service": service, "sport": sport, "flag": flag}
        self.history.append(record)
        recent = [row for row in self.history if now - row["time"] <= 2]
        same_host = [row for row in recent if row["dst"] == dst]
        same_service = [row for row in recent if row["service"] == service]
        hosts = [row for row in list(self.history)[-100:] if row["dst"] == dst]
        services = [row for row in list(self.history)[-100:] if row["service"] == service]
        ratio = lambda rows, predicate: sum(bool(predicate(row)) for row in rows) / len(rows) if rows else 0.
        syn_error = lambda row: row["flag"] == "S0"
        reject = lambda row: row["flag"] == "REJ"
        features = {name: 0 for name in COL_NAMES[:-1]}
        features.update(duration=max(0., flow.last-flow.start), protocol_type={6: "tcp", 17: "udp", 1: "icmp"}[proto], service=service, flag=flag,
            src_bytes=flow.src_bytes, dst_bytes=flow.dst_bytes, urgent=flow.urgent, wrong_fragment=0, land=int(src==dst and sport==dport),
            count=len(same_host), srv_count=len(same_service), serror_rate=ratio(same_host,syn_error), srv_serror_rate=ratio(same_service,syn_error), rerror_rate=ratio(same_host,reject), srv_rerror_rate=ratio(same_service,reject),
            same_srv_rate=ratio(same_host,lambda row:row["service"]==service), diff_srv_rate=ratio(same_host,lambda row:row["service"]!=service), srv_diff_host_rate=ratio(same_service,lambda row:row["dst"]!=dst),
            dst_host_count=len(hosts), dst_host_srv_count=len([row for row in hosts if row["service"]==service]),
            dst_host_same_srv_rate=ratio(hosts,lambda row:row["service"]==service), dst_host_diff_srv_rate=ratio(hosts,lambda row:row["service"]!=service), dst_host_same_src_port_rate=ratio(hosts,lambda row:row["sport"]==sport),
            dst_host_srv_diff_host_rate=ratio(services,lambda row:row["dst"]!=dst), dst_host_serror_rate=ratio(hosts,syn_error), dst_host_srv_serror_rate=ratio(services,syn_error), dst_host_rerror_rate=ratio(hosts,reject), dst_host_srv_rerror_rate=ratio(services,reject),
            src_ip=src, dst_ip=dst,
            flow_id=hashlib.sha256(repr((flow.key,flow.start)).encode()).hexdigest(),
            started_at=flow.start, ended_at=flow.last)
        return features
