"""Evidence and standardized alert generation from measured flow features."""

from datetime import datetime
import math
import uuid
from typing import Any, Dict, List, Optional


EVIDENCE_THRESHOLDS = {
    "SYN_FLOOD": {"packets_per_second": 1000, "bytes_per_second": 1_000_000, "short_duration": 0.001},
    "PORT_SCAN": {"dst_port_count": 10, "packets_per_second": 500, "small_packet_size": 80, "short_duration": 0.01},
    "C2_BEACON": {"repeated_connections": 50, "cv_interarrival": 0.3},
    "DNS_TUNNEL": {"query_length": 20, "query_entropy": 2.5, "subdomain_entropy": 3.0},
}


def _value(flow_data: Dict[str, Any], name: str) -> Optional[float]:
    value = flow_data.get(name)
    if value is None:
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _protocol_name(protocol: Any) -> Optional[str]:
    names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    if protocol is None:
        return None
    try:
        return names.get(int(protocol), str(int(protocol)))
    except (TypeError, ValueError):
        return str(protocol)


class EvidenceEngine:
    def __init__(self):
        self.evidence_rules = {
            "SYN_FLOOD": self._syn_flood_evidence,
            "PORT_SCAN": self._port_scan_evidence,
            "C2_BEACON": self._c2_beacon_evidence,
            "DNS_TUNNEL": self._dns_tunnel_evidence,
            "BENIGN": self._benign_evidence,
        }

    def generate_evidence(self, flow_data: Dict[str, Any], prediction: str, confidence: float = 0.0) -> Dict[str, Any]:
        evidence_func = self.evidence_rules.get(prediction, self._generic_evidence)
        return {
            "threat_class": prediction,
            "confidence": confidence,
            "evidence": evidence_func(flow_data),
            "timestamp": datetime.utcnow().isoformat(),
            "flow_id": str(uuid.uuid4()),
            "flow_data": flow_data,
        }

    def _syn_flood_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        evidence = []
        packet_rate = _value(flow_data, "packets_per_second")
        byte_rate = _value(flow_data, "bytes_per_second")
        duration = _value(flow_data, "flow_duration")
        packet_size = _value(flow_data, "mean_packet_size")
        port_count = _value(flow_data, "dst_port_count")
        thresholds = EVIDENCE_THRESHOLDS["SYN_FLOOD"]
        if packet_rate is not None and packet_rate > thresholds["packets_per_second"]:
            evidence.append(f"High packet rate: {packet_rate:.0f} packets/second (threshold: {thresholds['packets_per_second']})")
        if byte_rate is not None and byte_rate > thresholds["bytes_per_second"]:
            evidence.append(f"High byte rate: {byte_rate / 1_000_000:.1f} MB/s (threshold: {thresholds['bytes_per_second'] / 1_000_000:.1f} MB/s)")
        if duration is not None and duration < thresholds["short_duration"]:
            evidence.append(f"Very short flow duration: {duration * 1000:.3f} ms (threshold: {thresholds['short_duration'] * 1000:.3f} ms)")
        if packet_size is not None and 40 <= packet_size <= 60:
            evidence.append(f"Small packet size: {packet_size:.1f} bytes")
        if port_count is not None and port_count == 1:
            evidence.append(f"Single destination port: {port_count:.0f}")
        return evidence

    def _port_scan_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        evidence = []
        port_count = _value(flow_data, "dst_port_count")
        host_count = _value(flow_data, "dst_host_count")
        packet_rate = _value(flow_data, "packets_per_second")
        packet_size = _value(flow_data, "mean_packet_size")
        duration = _value(flow_data, "flow_duration")
        thresholds = EVIDENCE_THRESHOLDS["PORT_SCAN"]
        if port_count is not None and port_count > thresholds["dst_port_count"]:
            evidence.append(f"Destination ports contacted: {port_count:.0f} (threshold: {thresholds['dst_port_count']})")
        if host_count is not None and host_count <= 5:
            evidence.append(f"Destination hosts contacted: {host_count:.0f}")
        if packet_rate is not None and packet_rate > thresholds["packets_per_second"]:
            evidence.append(f"Connection rate: {packet_rate:.0f} packets/second (threshold: {thresholds['packets_per_second']})")
        if packet_size is not None and packet_size < thresholds["small_packet_size"]:
            evidence.append(f"Small packet size: {packet_size:.1f} bytes")
        if duration is not None and duration < thresholds["short_duration"]:
            evidence.append(f"Short flow duration: {duration * 1000:.3f} ms")
        return evidence

    def _c2_beacon_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        evidence = []
        connection_count = _value(flow_data, "dst_connection_count")
        host_count = _value(flow_data, "dst_host_count")
        port_count = _value(flow_data, "dst_port_count")
        mean_iat = _value(flow_data, "mean_interarrival")
        std_iat = _value(flow_data, "std_interarrival")
        cv_iat = _value(flow_data, "cv_interarrival")
        thresholds = EVIDENCE_THRESHOLDS["C2_BEACON"]
        if connection_count is not None and connection_count >= thresholds["repeated_connections"]:
            evidence.append(f"Repeated connections to destination: {connection_count:.0f} (threshold: {thresholds['repeated_connections']})")
        if host_count is not None and host_count == 1:
            evidence.append(f"Destination hosts contacted: {host_count:.0f}")
        if port_count is not None and port_count == 1:
            evidence.append(f"Destination ports contacted: {port_count:.0f}")
        if cv_iat is not None and cv_iat < thresholds["cv_interarrival"]:
            evidence.append(f"Timing regularity: CV={cv_iat:.3f} (threshold: {thresholds['cv_interarrival']:.2f})")
        elif cv_iat is not None and cv_iat < 0.5:
            evidence.append(f"Timing regularity: CV={cv_iat:.3f}")
        if mean_iat is not None and mean_iat > 0:
            evidence.append(f"Mean inter-arrival time: {mean_iat:.3f} seconds")
        if std_iat is not None and std_iat > 0:
            evidence.append(f"Inter-arrival standard deviation: {std_iat:.3f} seconds")
        return evidence

    def _dns_tunnel_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        evidence = []
        query_length = _value(flow_data, "dns_query_length")
        max_length = _value(flow_data, "dns_max_query_length")
        query_entropy = _value(flow_data, "dns_entropy")
        unique_subdomains = _value(flow_data, "dns_unique_subdomain_count")
        subdomain_entropy = _value(flow_data, "dns_subdomain_entropy")
        query_count = _value(flow_data, "dns_query_count")
        thresholds = EVIDENCE_THRESHOLDS["DNS_TUNNEL"]
        if query_length is not None and query_length > thresholds["query_length"]:
            evidence.append(f"Average DNS query length: {query_length:.1f} characters (threshold: {thresholds['query_length']})")
        if max_length is not None and max_length > 40:
            evidence.append(f"Maximum DNS query length: {max_length:.1f} characters")
        if query_entropy is not None and query_entropy > thresholds["query_entropy"]:
            evidence.append(f"DNS query entropy: {query_entropy:.3f} (threshold: {thresholds['query_entropy']})")
        if unique_subdomains is not None and unique_subdomains > 0:
            evidence.append(f"Unique subdomains: {unique_subdomains:.0f}")
        if subdomain_entropy is not None and subdomain_entropy > thresholds["subdomain_entropy"]:
            evidence.append(f"DNS subdomain entropy: {subdomain_entropy:.3f} (threshold: {thresholds['subdomain_entropy']})")
        if query_count is not None and query_count > 1:
            evidence.append(f"DNS queries in flow: {query_count:.0f}")
        protocol = _protocol_name(flow_data.get("protocol"))
        if protocol:
            evidence.append(f"Observed protocol: {protocol}")
        return evidence

    def _benign_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        evidence = []
        packet_rate = _value(flow_data, "packets_per_second")
        query_length = _value(flow_data, "dns_query_length")
        port_count = _value(flow_data, "dst_port_count")
        cv_iat = _value(flow_data, "cv_interarrival")
        if packet_rate is not None and packet_rate < 100:
            evidence.append(f"Packet rate: {packet_rate:.1f} packets/second")
        if query_length is not None and 0 < query_length < 20:
            evidence.append(f"DNS query length: {query_length:.1f} characters")
        if port_count is not None and 1 < port_count < 10:
            evidence.append(f"Destination ports contacted: {port_count:.0f}")
        if cv_iat is not None:
            evidence.append(f"Inter-arrival CV: {cv_iat:.3f}")
        return evidence

    def _generic_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        return []


class AlertGenerator:
    """Build the backend-owned alert schema from one measured flow row."""

    threat_severity = {
        "SYN_FLOOD": "CRITICAL",
        "DNS_TUNNEL": "HIGH",
        "C2_BEACON": "HIGH",
        "PORT_SCAN": "MEDIUM",
        "BENIGN": "NONE",
    }

    def __init__(self, evidence_engine: EvidenceEngine, model_metadata: Optional[Dict[str, Any]] = None):
        self.evidence_engine = evidence_engine
        self.model_metadata = model_metadata or {}

    def generate_alert(self, flow_data: Dict[str, Any], prediction: str, confidence: float = 0.0) -> Dict[str, Any]:
        evidence = self.evidence_engine.generate_evidence(flow_data, prediction, confidence)
        model = dict(self.model_metadata)
        return {
            "timestamp": evidence["timestamp"],
            "flow_id": evidence["flow_id"],
            "source_ip": flow_data.get("src_ip"),
            "destination_ip": flow_data.get("dst_ip"),
            "source_port": flow_data.get("src_port"),
            "destination_port": flow_data.get("dst_port"),
            "protocol": _protocol_name(flow_data.get("protocol")),
            "threat_class": prediction,
            "confidence": confidence,
            "severity": self.threat_severity.get(prediction, "UNKNOWN"),
            "model": model,
            "evidence": evidence["evidence"],
        }

    def generate_batch_alerts(self, flows_df, predictions, probabilities=None) -> List[Dict[str, Any]]:
        alerts = []
        for position, (_, row) in enumerate(flows_df.iterrows()):
            prediction = predictions[position]
            confidence = float(probabilities[position].max()) if probabilities is not None else 0.0
            alerts.append(self.generate_alert(row.to_dict(), prediction, confidence))
        return alerts
