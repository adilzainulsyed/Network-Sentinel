"""
FastAPI wrapper for Network-Sentinel detection pipeline
"""

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import sys
import tempfile
import uuid
from datetime import datetime
import json

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.app.flows.extractor import FlowExtractor
from backend.app.features.extractor import FeatureExtractor
from backend.app.evidence import EvidenceEngine, AlertGenerator
import joblib

app = FastAPI(title="Network-Sentinel API", version="1.0.0")

# Global state for hackathon prototype (in production, use proper database)
recent_alerts = []
traffic_statistics = {
    "total_flows_analyzed": 0,
    "threats_detected": {
        "SYN_FLOOD": 0,
        "PORT_SCAN": 0,
        "C2_BEACON": 0,
        "DNS_TUNNEL": 0,
        "BENIGN": 0
    },
    "start_time": datetime.utcnow().isoformat()
}

# Load model once at startup
models_dir = os.path.join(project_root, "backend", "models")
model_path = os.path.join(models_dir, "rf_model.joblib")
features_path = os.path.join(models_dir, "features.json")

try:
    clf = joblib.load(model_path)
    with open(features_path, "r") as f:
        feature_columns = json.load(f)
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    clf = None
    feature_columns = []


class SimulationRequest(BaseModel):
    scenario: str
    num_packets: Optional[int] = 100


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    timestamp: str


class AnalysisResponse(BaseModel):
    status: str
    total_flows: int
    threats_detected: dict
    alerts: List[dict]
    summary: str


class AlertsResponse(BaseModel):
    status: str
    alerts: List[dict]
    count: int


class StatisticsResponse(BaseModel):
    status: str
    total_flows_analyzed: int
    threats_detected: dict
    start_time: str
    uptime_seconds: float


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        model_loaded=clf is not None,
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/analyze/pcap", response_model=AnalysisResponse)
async def analyze_pcap(file: UploadFile = File(...)):
    """Analyze a PCAP file and return detection results"""
    if clf is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    # Save uploaded file temporarily
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        # Write uploaded content to temp file
        content = await file.read()
        temp_file.write(content)
        temp_file.close()
        
        # Run detection pipeline
        flow_ext = FlowExtractor()
        flow_ext.process_pcap(temp_file.name)
        df_flows = flow_ext.to_dataframe()
        
        if df_flows.empty:
            return AnalysisResponse(
                status="success",
                total_flows=0,
                threats_detected={},
                alerts=[],
                summary="No flows found in PCAP file"
            )
        
        # Extract features
        feat_ext = FeatureExtractor(df_flows)
        df_features = feat_ext.extract_features()
        
        # Prepare data for prediction
        for col in feature_columns:
            if col not in df_features.columns:
                df_features[col] = 0
        
        X = df_features[feature_columns].fillna(0)
        
        # Predict
        predictions = clf.predict(X)
        
        # Generate evidence-based alerts
        evidence_engine = EvidenceEngine()
        alert_generator = AlertGenerator(evidence_engine)
        
        threat_alerts = []
        threat_counts = {}
        
        for idx in range(len(df_flows)):
            prediction = predictions[idx]
            if prediction != 'BENIGN':
                # Combine flow data with feature data
                flow_data = df_flows.iloc[idx].to_dict()
                feature_data = df_features.iloc[idx].to_dict()
                flow_data.update(feature_data)
                
                alert = alert_generator.generate_alert(flow_data, prediction, confidence=1.0)
                threat_alerts.append(alert)
                
                # Update counts
                threat_counts[prediction] = threat_counts.get(prediction, 0) + 1
                
                # Add to recent alerts (keep last 100)
                recent_alerts.append(alert)
                if len(recent_alerts) > 100:
                    recent_alerts.pop(0)
        
        # Update global statistics
        traffic_statistics["total_flows_analyzed"] += len(df_flows)
        for threat, count in threat_counts.items():
            traffic_statistics["threats_detected"][threat] = traffic_statistics["threats_detected"].get(threat, 0) + count
        traffic_statistics["threats_detected"]["BENIGN"] = traffic_statistics["threats_detected"].get("BENIGN", 0) + (len(predictions) - sum(threat_counts.values()))
        
        # Generate summary
        total_threats = sum(threat_counts.values())
        summary = f"Analyzed {len(df_flows)} flows, detected {total_threats} threats"
        if threat_counts:
            summary += ": " + ", ".join([f"{k}: {v}" for k, v in threat_counts.items()])
        
        return AnalysisResponse(
            status="success",
            total_flows=len(df_flows),
            threats_detected=threat_counts,
            alerts=threat_alerts,
            summary=summary
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        # Clean up temp file
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


@app.post("/simulate", response_model=AnalysisResponse)
async def simulate_scenario(request: SimulationRequest):
    """Simulate a network threat scenario and analyze it"""
    if clf is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    scenario = request.scenario.upper()
    valid_scenarios = ["BENIGN", "SYN_FLOOD", "PORT_SCAN", "C2_BEACON", "DNS_TUNNEL"]
    
    if scenario not in valid_scenarios:
        raise HTTPException(status_code=400, detail=f"Invalid scenario. Must be one of: {valid_scenarios}")
    
    try:
        # Import simulator modules
        if scenario == "BENIGN":
            from simulator.benign import generate_benign
            packets = generate_benign(num_packets=request.num_packets)
        elif scenario == "SYN_FLOOD":
            from simulator.syn_flood import generate_syn_flood
            packets = generate_syn_flood(num_packets=request.num_packets)
        elif scenario == "PORT_SCAN":
            from simulator.port_scan import generate_port_scan
            packets = generate_port_scan(num_packets=request.num_packets)
        elif scenario == "C2_BEACON":
            from simulator.c2_beacon import generate_c2_beacon
            packets = generate_c2_beacon(num_packets=request.num_packets)
        elif scenario == "DNS_TUNNEL":
            from simulator.dns_tunnel import generate_dns_tunnel
            packets = generate_dns_tunnel(num_packets=request.num_packets)
        
        # Save to temporary PCAP file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        from scapy.all import wrpcap
        wrpcap(temp_file.name, packets)
        temp_file.close()
        
        # Run detection pipeline
        flow_ext = FlowExtractor()
        flow_ext.process_pcap(temp_file.name)
        df_flows = flow_ext.to_dataframe()
        
        if df_flows.empty:
            return AnalysisResponse(
                status="success",
                total_flows=0,
                threats_detected={},
                alerts=[],
                summary=f"No flows generated for {scenario} scenario"
            )
        
        # Extract features
        feat_ext = FeatureExtractor(df_flows)
        df_features = feat_ext.extract_features()
        
        # Prepare data for prediction
        for col in feature_columns:
            if col not in df_features.columns:
                df_features[col] = 0
        
        X = df_features[feature_columns].fillna(0)
        
        # Predict
        predictions = clf.predict(X)
        
        # Generate evidence-based alerts
        evidence_engine = EvidenceEngine()
        alert_generator = AlertGenerator(evidence_engine)
        
        threat_alerts = []
        threat_counts = {}
        
        for idx in range(len(df_flows)):
            prediction = predictions[idx]
            if prediction != 'BENIGN':
                # Combine flow data with feature data
                flow_data = df_flows.iloc[idx].to_dict()
                feature_data = df_features.iloc[idx].to_dict()
                flow_data.update(feature_data)
                
                alert = alert_generator.generate_alert(flow_data, prediction, confidence=1.0)
                threat_alerts.append(alert)
                
                # Update counts
                threat_counts[prediction] = threat_counts.get(prediction, 0) + 1
                
                # Add to recent alerts
                recent_alerts.append(alert)
                if len(recent_alerts) > 100:
                    recent_alerts.pop(0)
        
        # Update global statistics
        traffic_statistics["total_flows_analyzed"] += len(df_flows)
        for threat, count in threat_counts.items():
            traffic_statistics["threats_detected"][threat] = traffic_statistics["threats_detected"].get(threat, 0) + count
        traffic_statistics["threats_detected"]["BENIGN"] = traffic_statistics["threats_detected"].get("BENIGN", 0) + (len(predictions) - sum(threat_counts.values()))
        
        # Generate summary
        total_threats = sum(threat_counts.values())
        summary = f"Simulated {scenario} with {len(df_flows)} flows, detected {total_threats} threats"
        if threat_counts:
            summary += ": " + ", ".join([f"{k}: {v}" for k, v in threat_counts.items()])
        
        return AnalysisResponse(
            status="success",
            total_flows=len(df_flows),
            threats_detected=threat_counts,
            alerts=threat_alerts,
            summary=summary
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")
    finally:
        # Clean up temp file
        if 'temp_file' in locals() and os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


@app.get("/alerts", response_model=AlertsResponse)
async def get_alerts(limit: int = 10):
    """Get recent alerts"""
    return AlertsResponse(
        status="success",
        alerts=recent_alerts[-limit:],
        count=len(recent_alerts)
    )


@app.get("/statistics", response_model=StatisticsResponse)
async def get_statistics():
    """Get traffic and threat statistics"""
    start_time = datetime.fromisoformat(traffic_statistics["start_time"])
    uptime = (datetime.utcnow() - start_time).total_seconds()
    
    return StatisticsResponse(
        status="success",
        total_flows_analyzed=traffic_statistics["total_flows_analyzed"],
        threats_detected=traffic_statistics["threats_detected"],
        start_time=traffic_statistics["start_time"],
        uptime_seconds=uptime
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)