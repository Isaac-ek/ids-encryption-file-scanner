"""Offline authorized-PCAP feature/label validation; does not transmit packets."""
import argparse, csv, hashlib, json, sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scapy.utils import PcapReader
from api.flow_features import NetworkFeatureExtractor, UNOBSERVED
from api.ids_runtime import predict, artifact_hashes
from scripts.train_candidate import metrics
LABELS = {"Normal":0, "DoS":1, "Probe":2, "R2L":3, "U2R":4}


def capture_hash(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()

def evaluate(path, label_path=None, max_packets=100000):
    clock = [0.]
    extractor = NetworkFeatureExtractor(detect_internal=True, clock=lambda:clock[0])
    flows = []; packets = 0
    with PcapReader(str(path)) as capture:
        for packet in capture:
            packets += 1
            if packets > max_packets:
                raise ValueError("Capture exceeds packet limit; split it into smaller authorized captures")
            timestamp = float(packet.time)
            if timestamp < clock[0]:
                raise ValueError("Capture timestamps must be in chronological order")
            clock[0] = timestamp
            result = extractor.extract_features(packet)
            if result: flows.append(result)
    clock[0] += extractor.timeout
    flows.extend(extractor.drain_expired())
    labels = {}
    if label_path:
        with Path(label_path).open(newline="") as source:
            for row in csv.DictReader(source):
                if row.get("label") not in LABELS or not row.get("flow_id") or row["flow_id"] in labels:
                    raise ValueError("Labels require a unique flow_id and one supported class per row")
                labels[row["flow_id"]] = row["label"]
        unknown = set(labels) - {flow["flow_id"] for flow in flows}
        if unknown: raise ValueError("Labels contain flows absent from this capture")
    results = []; truth = []; predictions = []
    for features in flows:
        result = predict(features)
        expected = labels.get(features["flow_id"])
        results.append({"flow_id":features["flow_id"], "source":features["src_ip"], "destination":features["dst_ip"], "started_at":features["started_at"], "ended_at":features["ended_at"], "prediction":result["label"], "label":expected, "features":features})
        if expected is not None:
            truth.append(LABELS[expected]); predictions.append(result["class_id"])
    return {"kind":"experimental offline capture evaluation", "capture_sha256":capture_hash(path), "bundle_sha256":artifact_hashes(), "packets":packets, "flows":len(flows), "labelled_flows":len(truth), "label_coverage":len(truth)/len(flows) if flows else 0,
            "unobserved_features":UNOBSERVED, "results":results, "metrics":metrics(truth,predictions) if truth else None,
            "note":"Labels must come from independent traffic/host evidence, not classifier predictions. Unlabelled flows are excluded from metrics. Network-only features remain experimental."}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap",type=Path,required=True)
    parser.add_argument("--labels",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    report = evaluate(args.pcap,args.labels)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as destination:
        os.fchmod(destination.fileno(),0o600)
        json.dump(report,destination,indent=2)
    print(json.dumps({key:report[key] for key in ["packets","flows","labelled_flows","label_coverage"]}))
