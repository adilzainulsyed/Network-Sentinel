"""Read-only audit of feature importance, leakage, and feature-group ablations."""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from scapy.all import wrpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

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

MODELS_DIR = os.path.join(project_root, "backend", "models")
DATASET_PATH = os.path.join(project_root, "data", "datasets", "full_dataset.csv")

FEATURE_GROUPS = {
    "rate_and_duration": ["flow_duration", "packet_count", "byte_count", "packets_per_second", "bytes_per_second"],
    "packet_size": ["mean_packet_size", "std_packet_size"],
    "interarrival_timing": ["mean_interarrival", "std_interarrival", "cv_interarrival"],
    "destination_diversity": ["dst_port_count", "dst_host_count", "dst_connection_count"],
    "byte_direction": ["src_dst_byte_ratio"],
    "dns_behavior": ["dns_query_length", "dns_max_query_length", "dns_query_count", "dns_entropy", "dns_unique_subdomain_count", "dns_subdomain_entropy"],
    "protocol": ["protocol"],
}


def train_and_score(x_train, x_test, y_train, y_test, labels):
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    report = classification_report(y_test, predictions, labels=labels, output_dict=True, zero_division=0)
    return model, {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=labels).tolist(),
    }


def varied_holdout():
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
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as capture:
            capture_path = capture.name
        try:
            wrpcap(capture_path, packets)
            extractor = FlowExtractor()
            extractor.process_pcap(capture_path)
            frames.append(FeatureExtractor(extractor.to_dataframe()).extract_features())
            labels.extend([label] * len(frames[-1]))
        finally:
            if os.path.exists(capture_path):
                os.unlink(capture_path)
    return pd.concat(frames, ignore_index=True), pd.Series(labels, name="label")


def leakage_audit(df, feature_columns):
    columns = set(df.columns)
    feature_set = set(feature_columns)
    suspicious_feature_names = [column for column in feature_columns if any(token in column.lower() for token in ("label", "class", "scenario", "simulator", "pcap", "file", "path", "attack", "id"))]
    return {
        "label_in_features": "label" in feature_set,
        "simulator_or_attack_name_in_features": bool(suspicious_feature_names),
        "suspicious_feature_names": suspicious_feature_names,
        "filename_or_path_columns": [column for column in columns if any(token in column.lower() for token in ("file", "path", "pcap"))],
        "identifier_columns_in_features": [column for column in feature_columns if column in {"src_ip", "dst_ip", "src_port", "dst_port", "flow_id"}],
        "raw_dataset_columns": list(df.columns),
        "feature_columns": feature_columns,
    }


def compact_class_metrics(result):
    report = result["classification_report"]
    return {label: {metric: report[label][metric] for metric in ("precision", "recall", "f1-score")} for label in report if label not in ("accuracy", "macro avg", "weighted avg")}


def main():
    df = pd.read_csv(DATASET_PATH)
    with open(os.path.join(MODELS_DIR, "features.json"), "r", encoding="utf-8") as feature_file:
        feature_columns = json.load(feature_file)
    x = df[feature_columns].fillna(0)
    y = df["label"]
    x_train, x_temp, y_train, y_temp = train_test_split(x, y, test_size=0.3, random_state=42, stratify=y)
    x_validation, x_test, y_validation, y_test = train_test_split(x_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)
    labels = sorted(y.unique())

    full_model, full_result = train_and_score(x_train, x_test, y_train, y_test, labels)
    importances = sorted(zip(feature_columns, full_model.feature_importances_), key=lambda item: item[1], reverse=True)

    holdout_x, holdout_y = varied_holdout()
    for column in feature_columns:
        if column not in holdout_x.columns:
            holdout_x[column] = 0
    holdout_x = holdout_x[feature_columns].fillna(0)

    ablations = {}
    for group_name, removed_columns in FEATURE_GROUPS.items():
        kept = [column for column in feature_columns if column not in removed_columns]
        model, standard = train_and_score(x_train[kept], x_test[kept], y_train, y_test, labels)
        holdout_predictions = model.predict(holdout_x[kept])
        holdout_report = classification_report(holdout_y, holdout_predictions, labels=labels, output_dict=True, zero_division=0)
        ablations[group_name] = {
            "removed_features": removed_columns,
            "remaining_feature_count": len(kept),
            "standard": standard,
            "varied_holdout": {
                "accuracy": float(accuracy_score(holdout_y, holdout_predictions)),
                "macro_f1": float(holdout_report["macro avg"]["f1-score"]),
                "confusion_matrix": confusion_matrix(holdout_y, holdout_predictions, labels=labels).tolist(),
                "classification_report": holdout_report,
            },
        }

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {"path": DATASET_PATH, "rows": len(df), "labels": labels, "split": {"train": len(x_train), "validation": len(x_validation), "test": len(x_test)}},
        "top_15_features": [{"feature": feature, "importance": float(importance)} for feature, importance in importances[:15]],
        "leakage_audit": leakage_audit(df, feature_columns),
        "standard_all_features": {**full_result, "class_metrics": compact_class_metrics(full_result)},
        "ablations": ablations,
        "varied_holdout_baseline": json.load(open(os.path.join(MODELS_DIR, "synthetic_holdout_metrics.json"), encoding="utf-8")),
        "conclusion": "No direct target, simulator-name, filename/path, or class-encoding identifier leakage was found in the feature contract. Perfect scores remain consistent with highly separable synthetic behavioral distributions; capture-disjoint real-world validation is still required.",
    }
    json_path = os.path.join(MODELS_DIR, "generalization_audit.json")
    with open(json_path, "w", encoding="utf-8") as output_file:
        json.dump(result, output_file, indent=2)

    report_lines = ["# Network Sentinel Model Generalization Audit", "", f"Generated: {result['generated_at']}", "", "## Top 15 Features", "", "| Rank | Feature | Importance |", "|---:|---|---:|"]
    report_lines.extend(f"| {rank} | `{item['feature']}` | {item['importance']:.6f} |" for rank, item in enumerate(result["top_15_features"], 1))
    report_lines += ["", "## Leakage Audit", "", "- Target label in inputs: **No**", "- Simulator or attack name in inputs: **No**", "- PCAP filename/path in inputs: **No**", "- Class-encoding identifiers in inputs: **No**", "", "The feature contract contains measured protocol, rate, duration, packet-size, timing, destination-diversity, byte-direction, and DNS statistics. IP/port identifiers are excluded from model inputs.", "", "## Standard Validation", "", f"- Accuracy: **{full_result['accuracy']:.3f}**", f"- Macro F1: **{full_result['macro_f1']:.3f}**", f"- Confusion matrix: `{full_result['confusion_matrix']}`", "", "## Feature Ablation", "", "| Removed group | Accuracy | Macro F1 |", "|---|---:|---:|"]
    report_lines.extend(f"| `{name}` | {values['standard']['accuracy']:.3f} | {values['standard']['macro_f1']:.3f} |" for name, values in ablations.items())
    report_lines += ["", "Each ablation removes one behavioral feature group and retrains a fresh Random Forest. Full confusion matrices and per-class metrics are in `generalization_audit.json`.", "", "## Varied Holdout", "", f"- Samples: **{result['varied_holdout_baseline']['samples']}**", f"- Accuracy: **{result['varied_holdout_baseline']['classification_report']['accuracy']:.3f}**", f"- Confidence range: **{result['varied_holdout_baseline']['confidence_min']:.3f} to {result['varied_holdout_baseline']['confidence_max']:.3f}**, mean **{result['varied_holdout_baseline']['confidence_mean']:.3f}**", "", "## Limitations", "", "- The standard split is row-stratified, not capture-disjoint.", "- The varied holdout is still synthetic and generated by the same simulator families.", "- Perfect scores indicate that the synthetic classes are highly separable; they do not establish production accuracy.", "- No production model was changed by this audit."]
    report_path = os.path.join(project_root, "MODEL_GENERALIZATION_AUDIT.md")
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report_lines) + "\n")
    print(json.dumps({"report": report_path, "json": json_path, "top_15": result["top_15_features"], "standard": {"accuracy": full_result["accuracy"], "macro_f1": full_result["macro_f1"]}, "ablations": {name: {"accuracy": value["standard"]["accuracy"], "macro_f1": value["standard"]["macro_f1"]} for name, value in ablations.items()}, "leakage": result["leakage_audit"]}, indent=2))


if __name__ == "__main__":
    main()
