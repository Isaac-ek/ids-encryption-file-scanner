from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from api.flow_features import NetworkFeatureExtractor
from api.ids_runtime import encode_features, bundle, predict
import numpy as np


def test_tcp_exchange_has_one_flow_directional_payload_bytes_and_actual_model_inference():
    clock = [1.]
    extractor = NetworkFeatureExtractor(detect_internal=True, clock=lambda: clock[0])
    forward = IP(src="192.0.2.10", dst="198.51.100.20")
    reverse = IP(src="198.51.100.20", dst="192.0.2.10")
    packets = [forward/TCP(sport=40000,dport=443,flags="S"),
               reverse/TCP(sport=443,dport=40000,flags="SA"),
               forward/TCP(sport=40000,dport=443,flags="PA")/Raw(b"abc"),
               reverse/TCP(sport=443,dport=40000,flags="PA")/Raw(b"reply"),
               forward/TCP(sport=40000,dport=443,flags="FA"),
               reverse/TCP(sport=443,dport=40000,flags="FA")]
    for packet in packets[:-1]:
        assert extractor.extract_features(packet) is None
        clock[0] += 1
    features = extractor.extract_features(packets[-1])
    assert features["src_bytes"] == 3 and features["dst_bytes"] == 5
    assert features["src_ip"] == "192.0.2.10" and features["dst_ip"] == "198.51.100.20"
    assert features["duration"] == 5 and features["service"] == "http_443"
    assert features["flag"] == "SF" and features["count"] == features["srv_count"] == 1
    assert len(extractor.connections) == 0
    model, scaler, columns = bundle()
    expected = int(model.predict(scaler.transform(encode_features(features, columns)))[0])
    assert predict(features)["class_id"] == expected


def test_udp_expiration_uses_flows_instead_of_counting_each_packet():
    clock = [1.]
    extractor = NetworkFeatureExtractor(timeout=2, detect_internal=True, clock=lambda: clock[0])
    for _ in range(5):
        assert extractor.extract_features(IP(src="192.0.2.1",dst="198.51.100.1")/UDP(sport=40000,dport=53)/Raw(b"dns")) is None
    extractor.extract_features(IP(src="198.51.100.1",dst="192.0.2.1")/UDP(sport=53,dport=40000)/Raw(b"answer"))
    assert len(extractor.connections) == 1
    clock[0] = 4.
    result = extractor.drain_expired()
    assert len(result) == 1
    assert result[0]["count"] == 1 and result[0]["src_bytes"] == 15 and result[0]["dst_bytes"] == 6
    assert extractor.drain_expired() == []


def test_distinct_connections_and_service_statistics_are_bounded():
    extractor = NetworkFeatureExtractor(detect_internal=True, max_flows=2)
    first = extractor.extract_features(IP(src="192.0.2.1",dst="198.51.100.1")/TCP(sport=40000,dport=80,flags="R"))
    second = extractor.extract_features(IP(src="192.0.2.1",dst="198.51.100.1")/TCP(sport=40001,dport=22,flags="R"))
    assert first["count"] == 1 and second["count"] == 2
    assert second["same_srv_rate"] == second["diff_srv_rate"] == .5
    assert second["rerror_rate"] == 1
    for port in range(10):
        extractor.extract_features(IP(src="192.0.2.1",dst="198.51.100.1")/UDP(sport=41000+port,dport=53))
        assert len(extractor.connections) <= 2


def test_icmp_request_reply_share_flow_and_unsupported_layers_are_skipped():
    extractor = NetworkFeatureExtractor(detect_internal=True)
    assert extractor.extract_features(IP(src="192.0.2.1",dst="198.51.100.1")/ICMP(type=8,id=7)/Raw(b"ping")) is None
    result = extractor.extract_features(IP(src="198.51.100.1",dst="192.0.2.1")/ICMP(type=0,id=7)/Raw(b"pong"))
    assert result["src_bytes"] == result["dst_bytes"] == 4
    assert result["protocol_type"] == "icmp"
    from scapy.layers.l2 import ARP
    assert extractor.extract_features(ARP()) is None


def test_simulation_replays_raw_features_supported_by_the_preserved_schema():
    import sys
    from api.settings import ROOT
    sys.path.insert(0, str(ROOT / "legacy"))
    import network_monitor as sensor
    _, _, columns = bundle()
    for _ in range(10):
        features = sensor.generate_random_features()
        assert "src_dst_ratio" not in features
        assert np.isfinite(encode_features(features, columns)).all()


def test_offline_pcap_evaluation_requires_independent_labels_and_tracks_coverage(tmp_path):
    from scapy.utils import wrpcap
    from scripts.evaluate_capture import evaluate
    import csv
    capture = tmp_path/"owned-fixture.pcap"
    first = IP(src="192.0.2.1",dst="198.51.100.1")/TCP(sport=45000,dport=80,flags="R")
    first.time = 1000.
    second = IP(src="192.0.2.2",dst="198.51.100.2")/TCP(sport=45001,dport=22,flags="R")
    second.time = 1001.
    wrpcap(str(capture),[first,second])
    report = evaluate(capture)
    assert report["flows"] == 2 and report["metrics"] is None
    labels = tmp_path/"labels.csv"
    with labels.open("w",newline="") as output:
        writer=csv.writer(output);writer.writerow(["flow_id","label"])
        writer.writerow([report["results"][0]["flow_id"],"Normal"])
    labelled = evaluate(capture,labels)
    assert labelled["labelled_flows"] == 1 and labelled["label_coverage"] == .5
    assert sum(map(sum,labelled["metrics"]["confusion_matrix"])) == 1
    labels.write_text("flow_id,label\nunknown,Normal\n")
    import pytest
    with pytest.raises(ValueError,match="absent"):
        evaluate(capture,labels)
