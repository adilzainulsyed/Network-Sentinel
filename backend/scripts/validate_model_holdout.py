"""Evaluate the existing model on varied synthetic captures not used for training."""

import json
import os
import sys
import tempfile

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from scapy.all import wrpcap

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.app.features.extractor import FeatureExtractor
from backend.app.flows.extractor import FlowExtractor
from simulator.benign import generate_benign
from simulator.c2_beacon import generate_c2_beacon
from simulator.dns_tunnel import generate_dns_tunnel
from simulator.port_scan import generate_port_scan
from simulator.syn_flood import generate_syn_flood


def extract_features(packets):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as capture:
        capture_path = capture.name
    try:
        wrpcap(capture_path, packets)
        flow_extractor = FlowExtractor()
        flow_extractor.process_pcap(capture_path)
        flows = flow_extractor.to_dataframe()
        return FeatureExtractor(flows).extract_features()
    finally:
        if os.path.exists(capture_path):
            os.unlink(capture_path)


def main():
    models_dir = os.path.join(project_root, "backend", "models")
    model = joblib.load(os.path.join(models_dir, "rf_model.joblib"))
    with open(os.path.join(models_dir, "features.json"), "r", encoding="utf-8") as feature_file:
        feature_columns = json.load(feature_file)

    cases = [
        ("BENIGN", generate_benign(num_packets=73)),
        ("SYN_FLOOD", generate_syn_flood(num_packets=137, target_port=443, spoof_ips=False)),
        ("PORT_SCAN", generate_port_scan(num_packets=1500, target_ip="10.0.0.9")),
        ("C2_BEACON", generate_c2_beacon(num_packets=37, base_interval=37.0, jitter_percent=0.08)),
        ("DNS_TUNNEL", generate_dns_tunnel(num_packets=83, min_subdomain_length=18, max_subdomain_length=24, encoding_variety=False)),
    ]

    frames = []
    labels = []
    for label, packets in cases:
        frame = extract_features(packets)
        frames.append(frame)
        labels.extend([label] * len(frame))
    holdout = pd.concat(frames, ignore_index=True)
    for column in feature_columns:
        if column not in holdout.columns:
            holdout[column] = 0
    predictions = model.predict(holdout[feature_columns].fillna(0))
    probabilities = model.predict_proba(holdout[feature_columns].fillna(0)).max(axis=1)
    report = classification_report(labels, predictions, output_dict=True, zero_division=0)
    result = {
        "samples": len(labels),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(labels, predictions, labels=list(model.classes_)).tolist(),
        "labels": list(model.classes_),
        "confidence_min": float(probabilities.min()),
        "confidence_max": float(probabilities.max()),
        "confidence_mean": float(probabilities.mean()),
        "note": "Generated with changed packet counts, ports, targets, beacon intervals, jitter, and DNS lengths/encoding; this is still synthetic and not a production accuracy estimate.",
    }
    output_path = os.path.join(models_dir, "synthetic_holdout_metrics.json")
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(result, output_file, indent=2)
    print(json.dumps(result, indent=2))
    print(f"Saved varied synthetic holdout metrics to {output_path}")


if __name__ == "__main__":
    main()
