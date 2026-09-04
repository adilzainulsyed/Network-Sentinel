"""FastAPI wrapper for the passive Network-Sentinel detection pipeline."""

from datetime import datetime
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import joblib
import sklearn
from scapy.all import wrpcap

from backend.app.evidence import AlertGenerator, EvidenceEngine
from backend.app.features.extractor import FeatureExtractor
from backend.app.flows.extractor import FlowExtractor

app = FastAPI(title="Network-Sentinel API", version="1.0.0")

recent_alerts: List[Dict[str, Any]] = []
last_analysis: Dict[str, Any] = {}
traffic_statistics = {
    "flows_processed": 0,
    "packets_processed": 0,
    "bytes_processed": 0,
    "observed_duration_seconds": 0.0,
    "alerts_count": 0,
    "threats_detected": {"SYN_FLOOD": 0, "PORT_SCAN": 0, "C2_BEACON": 0, "DNS_TUNNEL": 0, "BENIGN": 0},
    "start_time": datetime.utcnow().isoformat(),
}

models_dir = os.path.join(project_root, "backend", "models")
model_path = os.path.join(models_dir, "rf_model.joblib")
features_path = os.path.join(models_dir, "features.json")
metadata_path = os.path.join(models_dir, "model_metadata.json")

try:
    clf = joblib.load(model_path)
    with open(features_path, "r", encoding="utf-8") as feature_file:
        feature_columns = json.load(feature_file)
    with open(metadata_path, "r", encoding="utf-8") as metadata_file:
        model_metadata = json.load(metadata_file)
except FileNotFoundError as error:
    print(f"Model metadata file unavailable: {error}")
    clf = joblib.load(model_path) if os.path.exists(model_path) else None
    with open(features_path, "r", encoding="utf-8") as feature_file:
        feature_columns = json.load(feature_file) if os.path.exists(features_path) else []
    model_metadata = {}
except Exception as error:
    print(f"Error loading model: {error}")
    clf = None
    feature_columns = []
    model_metadata = {}

if clf is not None:
    model_metadata = {
        "name": model_metadata.get("name", clf.__class__.__name__.replace("Classifier", "")),
        "version": model_metadata.get("version", "1.0.0"),
        "sklearn_version": model_metadata.get("sklearn_version", sklearn.__version__),
        "training_timestamp": model_metadata.get("training_timestamp"),
        "classes": list(getattr(clf, "classes_", [])),
    }
    print("Model loaded successfully")


class SimulationRequest(BaseModel):
    scenario: str
    num_packets: int = Field(default=100, ge=1, le=10000)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    timestamp: str
    model: Dict[str, Any] = {}


class AnalysisResponse(BaseModel):
    status: str
    total_flows: int
    packets_processed: int
    bytes_processed: int
    traffic_mbps: float
    threats_detected: Dict[str, int]
    alerts: List[Dict[str, Any]]
    summary: str


class AlertsResponse(BaseModel):
    status: str
    alerts: List[Dict[str, Any]]
    count: int


class StatisticsResponse(BaseModel):
    status: str
    flows_processed: int
    packets_processed: int
    bytes_processed: int
    traffic_mbps: float
    alerts_count: int
    threats_detected: Dict[str, int]
    observed_duration_seconds: float
    start_time: str
    uptime_seconds: float
    model: Dict[str, Any]


def _json_value(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _traffic_rate(bytes_processed: int, duration_seconds: float) -> float:
    if duration_seconds <= 0:
        return 0.0
    return (bytes_processed * 8) / duration_seconds / 1_000_000


def _analyze_pcap_path(
    pcap_path: str,
    summary_prefix: str,
    simulation_type: Optional[str] = None,
    simulator_called: Optional[str] = None,
    generated_packet_count: Optional[int] = None,
) -> AnalysisResponse:
    started = time.perf_counter()
    flow_ext = FlowExtractor()
    flow_ext.process_pcap(pcap_path)
    df_flows = flow_ext.to_dataframe()
    packet_count = int(df_flows["packets"].sum()) if not df_flows.empty else 0
    byte_count = int(df_flows["bytes"].sum()) if not df_flows.empty else 0
    timestamps = [timestamp for values in df_flows.get("timestamps", []) for timestamp in values] if not df_flows.empty else []
    observed_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    if observed_duration <= 0:
        observed_duration = max(time.perf_counter() - started, 0.000001)
    analysis_rate = _traffic_rate(byte_count, observed_duration)

    if df_flows.empty:
        response = AnalysisResponse(status="success", total_flows=0, packets_processed=0, bytes_processed=0, traffic_mbps=0.0, threats_detected={}, alerts=[], summary=f"{summary_prefix}: no flows found")
        _record_analysis(response, observed_duration, simulation_type, simulator_called, generated_packet_count, [])
        return response

    df_features = FeatureExtractor(df_flows).extract_features()
    for column in feature_columns:
        if column not in df_features.columns:
            df_features[column] = 0
    model_input = df_features[feature_columns].fillna(0)
    predictions = clf.predict(model_input)
    probabilities = clf.predict_proba(model_input) if hasattr(clf, "predict_proba") else None
    alert_generator = AlertGenerator(EvidenceEngine(), model_metadata)
    alerts = []
    threat_counts: Dict[str, int] = {}

    for index, prediction in enumerate(predictions):
        prediction = str(prediction)
        threat_counts[prediction] = threat_counts.get(prediction, 0) + 1
        if prediction == "BENIGN":
            continue
        confidence = float(probabilities[index].max()) if probabilities is not None else 0.0
        flow_data = df_flows.iloc[index].to_dict()
        flow_data.update(df_features.iloc[index].to_dict())
        alert = alert_generator.generate_alert(_json_value(flow_data), prediction, confidence)
        alerts.append(alert)

    summary = f"{summary_prefix}: analyzed {len(df_flows)} flows, detected {len(alerts)} threats"
    if threat_counts:
        summary += ": " + ", ".join(f"{threat}: {count}" for threat, count in threat_counts.items() if threat != "BENIGN")
    response = AnalysisResponse(status="success", total_flows=len(df_flows), packets_processed=packet_count, bytes_processed=byte_count, traffic_mbps=analysis_rate, threats_detected=threat_counts, alerts=alerts, summary=summary)
    representative_index = 0
    debug_prediction = str(predictions[representative_index])
    debug_probabilities = probabilities[representative_index].tolist() if probabilities is not None else []
    _record_analysis(response, observed_duration, simulation_type, simulator_called, generated_packet_count, alerts, {
        "pcap_path": pcap_path,
        "packet_count": generated_packet_count if generated_packet_count is not None else packet_count,
        "flows_extracted": len(df_flows),
        "unique_destination_ports": int(df_features["dst_port_count"].max()),
        "unique_destination_hosts": int(df_features["dst_host_count"].max()),
        "representative_features": _json_value(df_features.iloc[representative_index].to_dict()),
        "prediction": debug_prediction,
        "probabilities": debug_probabilities,
    })
    return response


def _record_analysis(response, observed_duration, simulation_type, simulator_called, generated_packet_count, alerts, debug=None):
    recent_alerts.extend(alerts)
    del recent_alerts[:-100]
    traffic_statistics["flows_processed"] += response.total_flows
    traffic_statistics["packets_processed"] += response.packets_processed
    traffic_statistics["bytes_processed"] += response.bytes_processed
    traffic_statistics["observed_duration_seconds"] += observed_duration
    traffic_statistics["alerts_count"] += len(alerts)
    for threat, count in response.threats_detected.items():
        traffic_statistics["threats_detected"][threat] = traffic_statistics["threats_detected"].get(threat, 0) + count
    traffic_statistics["traffic_mbps"] = _traffic_rate(traffic_statistics["bytes_processed"], traffic_statistics["observed_duration_seconds"])
    last_analysis.clear()
    last_analysis.update(debug or {})
    last_analysis.update({"simulation_type": simulation_type, "simulator_called": simulator_called, "generated_packet_count": generated_packet_count, "response": response.model_dump()})
    if simulation_type:
        print(f"Simulation: {simulation_type}")
        print(f"Simulator: {simulator_called}")
        print(f"Packets generated: {generated_packet_count}")
        print(f"Unique destination ports: {last_analysis.get('unique_destination_ports')}")
        print(f"Unique destination hosts: {last_analysis.get('unique_destination_hosts')}")


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="healthy", model_loaded=clf is not None, timestamp=datetime.utcnow().isoformat(), model=model_metadata)


@app.post("/analyze/pcap", response_model=AnalysisResponse)
async def analyze_pcap(file: UploadFile = File(...)):
    if clf is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    if not file.filename:
        raise HTTPException(status_code=400, detail="A PCAP file is required")
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="The uploaded PCAP is empty")
        temp_file.write(content)
        temp_file.close()
        return _analyze_pcap_path(temp_file.name, "Analyzed")
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {error}")
    finally:
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


@app.post("/simulate", response_model=AnalysisResponse)
async def simulate_scenario(request: SimulationRequest):
    if clf is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    scenario = request.scenario.upper()
    generators = {
        "BENIGN": ("benign", "simulator.benign", "generate_benign"),
        "SYN_FLOOD": ("syn_flood", "simulator.syn_flood", "generate_syn_flood"),
        "PORT_SCAN": ("port_scan", "simulator.port_scan", "generate_port_scan"),
        "C2_BEACON": ("c2_beacon", "simulator.c2_beacon", "generate_c2_beacon"),
        "DNS_TUNNEL": ("dns_tunnel", "simulator.dns_tunnel", "generate_dns_tunnel"),
    }
    if scenario not in generators:
        raise HTTPException(status_code=400, detail=f"Invalid scenario. Must be one of: {sorted(generators)}")
    simulator_name, module_name, function_name = generators[scenario]
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        module = __import__(module_name, fromlist=[function_name])
        packets = getattr(module, function_name)(num_packets=request.num_packets)
        wrpcap(temp_file.name, packets)
        temp_file.close()
        return _analyze_pcap_path(temp_file.name, f"Simulated {scenario}", scenario, simulator_name, len(packets))
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {error}")
    finally:
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


@app.get("/alerts", response_model=AlertsResponse)
async def get_alerts(limit: int = Query(default=10, ge=1, le=100)):
    return AlertsResponse(status="success", alerts=recent_alerts[-limit:], count=len(recent_alerts))


@app.get("/statistics", response_model=StatisticsResponse)
async def get_statistics():
    start_time = datetime.fromisoformat(traffic_statistics["start_time"])
    return StatisticsResponse(status="success", flows_processed=traffic_statistics["flows_processed"], packets_processed=traffic_statistics["packets_processed"], bytes_processed=traffic_statistics["bytes_processed"], traffic_mbps=traffic_statistics.get("traffic_mbps", 0.0), alerts_count=traffic_statistics["alerts_count"], threats_detected=traffic_statistics["threats_detected"], observed_duration_seconds=traffic_statistics["observed_duration_seconds"], start_time=traffic_statistics["start_time"], uptime_seconds=(datetime.utcnow() - start_time).total_seconds(), model=model_metadata)


@app.post("/session/reset")
async def reset_session():
    """Clear only in-memory session telemetry and recent alerts."""
    recent_alerts.clear()
    last_analysis.clear()
    traffic_statistics["flows_processed"] = 0
    traffic_statistics["packets_processed"] = 0
    traffic_statistics["bytes_processed"] = 0
    traffic_statistics["observed_duration_seconds"] = 0.0
    traffic_statistics["traffic_mbps"] = 0.0
    traffic_statistics["alerts_count"] = 0
    traffic_statistics["threats_detected"] = {
        "SYN_FLOOD": 0,
        "PORT_SCAN": 0,
        "C2_BEACON": 0,
        "DNS_TUNNEL": 0,
        "BENIGN": 0,
    }
    traffic_statistics["start_time"] = datetime.utcnow().isoformat()
    return {"status": "success", "message": "In-memory session telemetry reset"}


@app.get("/debug/last-analysis")
async def debug_last_analysis():
    return {"status": "success", "analysis": last_analysis}


@app.get("/debug/model-validation")
async def debug_model_validation():
    metrics_path = os.path.join(models_dir, "validation_metrics.json")
    if not os.path.exists(metrics_path):
        raise HTTPException(status_code=404, detail="Validation metrics are not available")
    with open(metrics_path, "r", encoding="utf-8") as metrics_file:
        return {"status": "success", "metrics": json.load(metrics_file)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
