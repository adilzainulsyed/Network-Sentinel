"""
Evidence Engine for Network Threat Detection
Converts detection results into human-readable evidence based on actual feature values
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Any
import uuid


class EvidenceEngine:
    def __init__(self):
        self.evidence_rules = {
            'SYN_FLOOD': self._syn_flood_evidence,
            'PORT_SCAN': self._port_scan_evidence,
            'C2_BEACON': self._c2_beacon_evidence,
            'DNS_TUNNEL': self._dns_tunnel_evidence,
            'BENIGN': self._benign_evidence
        }
    
    def generate_evidence(self, flow_data: Dict[str, Any], prediction: str, 
                         confidence: float = 1.0) -> Dict[str, Any]:
        """
        Generate evidence for a detected threat based on actual feature values
        
        Args:
            flow_data: Dictionary containing flow features and metadata
            prediction: Model prediction (threat class)
            confidence: Detection confidence score
            
        Returns:
            Dictionary containing threat evidence with human-readable explanations
        """
        threat_class = prediction
        evidence_func = self.evidence_rules.get(threat_class, self._generic_evidence)
        
        evidence = {
            'threat_class': threat_class,
            'confidence': confidence,
            'evidence': evidence_func(flow_data),
            'timestamp': datetime.utcnow().isoformat(),
            'flow_id': str(uuid.uuid4()),
            'flow_data': flow_data
        }
        
        return evidence
    
    def _syn_flood_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        """Generate evidence for SYN_FLOOD detection"""
        evidence = []
        
        # High SYN rate evidence
        packets_per_second = flow_data.get('packets_per_second', 0)
        if packets_per_second > 1000:
            evidence.append(f"High packet rate: {packets_per_second:.0f} packets/second (normal < 100)")
        
        # Abnormal packet rate
        bytes_per_second = flow_data.get('bytes_per_second', 0)
        if bytes_per_second > 1000000:
            evidence.append(f"High byte rate: {bytes_per_second/1000000:.1f} MB/s (suspicious for SYN flood)")
        
        # Flow duration
        flow_duration = flow_data.get('flow_duration', 0)
        if flow_duration < 0.001:
            evidence.append(f"Very short flow duration: {flow_duration*1000:.3f}ms (characteristic of flood attacks)")
        
        # Packet size analysis
        mean_packet_size = flow_data.get('mean_packet_size', 0)
        if 40 <= mean_packet_size <= 60:
            evidence.append(f"Small packet size: {mean_packet_size:.0f} bytes (typical SYN packet size)")
        
        # Source diversity (if multiple flows from same source)
        dst_port_count = flow_data.get('dst_port_count', 0)
        if dst_port_count == 1:
            evidence.append(f"Single destination port: {dst_port_count} (focused attack on specific service)")
        
        if not evidence:
            evidence.append("SYN flood detected based on multiple suspicious traffic patterns")
        
        return evidence
    
    def _port_scan_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        """Generate evidence for PORT_SCAN detection"""
        evidence = []
        
        # Destination port diversity
        dst_port_count = flow_data.get('dst_port_count', 0)
        if dst_port_count > 100:
            evidence.append(f"High destination port diversity: {dst_port_count} unique ports (normal < 10)")
        elif dst_port_count > 10:
            evidence.append(f"Elevated destination port diversity: {dst_port_count} unique ports")
        
        # Destination host diversity
        dst_host_count = flow_data.get('dst_host_count', 0)
        if dst_host_count == 1:
            evidence.append(f"Single target host: {dst_host_count} (focused scanning activity)")
        elif dst_host_count < 5:
            evidence.append(f"Limited target hosts: {dst_host_count} (targeted scanning)")
        
        # Connection rate
        packets_per_second = flow_data.get('packets_per_second', 0)
        if packets_per_second > 500:
            evidence.append(f"High connection rate: {packets_per_second:.0f} connections/second (rapid scanning)")
        
        # Small packet sizes (typical of port scanning)
        mean_packet_size = flow_data.get('mean_packet_size', 0)
        if mean_packet_size < 80:
            evidence.append(f"Small packet size: {mean_packet_size:.0f} bytes (characteristic of SYN scanning)")
        
        # Flow duration
        flow_duration = flow_data.get('flow_duration', 0)
        if flow_duration < 0.01:
            evidence.append(f"Short flow duration: {flow_duration*1000:.1f}ms (typical of scan probes)")
        
        if not evidence:
            evidence.append("Port scan detected based on port diversity and scanning patterns")
        
        return evidence
    
    def _c2_beacon_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        """Generate evidence for C2_BEACON detection"""
        evidence = []
        
        # Repeated destination connections
        dst_connection_count = flow_data.get('dst_connection_count', 0)
        if dst_connection_count > 100:
            evidence.append(f"High repeated connections: {dst_connection_count} to same destination (beaconing pattern)")
        elif dst_connection_count > 50:
            evidence.append(f"Frequent repeated connections: {dst_connection_count} to same destination")
        
        # Single destination (C2 server)
        dst_host_count = flow_data.get('dst_host_count', 0)
        if dst_host_count == 1:
            evidence.append(f"Single destination host: {dst_host_count} (consistent C2 server contact)")
        
        # Timing regularity (low coefficient of variation)
        cv_interarrival = flow_data.get('cv_interarrival', 0)
        if cv_interarrival < 0.3:
            evidence.append(f"High timing regularity: CV={cv_interarrival:.2f} (periodic beaconing intervals)")
        elif cv_interarrival < 0.5:
            evidence.append(f"Moderate timing regularity: CV={cv_interarrival:.2f} (structured communication)")
        
        # Inter-arrival time analysis
        mean_interarrival = flow_data.get('mean_interarrival', 0)
        if mean_interarrival > 0:
            evidence.append(f"Mean inter-arrival time: {mean_interarrival:.1f}s (consistent beacon interval)")
        
        # Limited port diversity
        dst_port_count = flow_data.get('dst_port_count', 0)
        if dst_port_count == 1:
            evidence.append(f"Single destination port: {dst_port_count} (consistent C2 communication channel)")
        
        # Connection count per destination
        if dst_connection_count > 0 and dst_host_count > 0:
            avg_conns_per_host = dst_connection_count / dst_host_count
            if avg_conns_per_host > 50:
                evidence.append(f"High connections per host: {avg_conns_per_host:.0f} (repeated C2 check-ins)")
        
        if not evidence:
            evidence.append("C2 beaconing detected based on repeated connections and timing patterns")
        
        return evidence
    
    def _dns_tunnel_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        """Generate evidence for DNS_TUNNEL detection"""
        evidence = []
        
        # Query length analysis
        dns_query_length = flow_data.get('dns_query_length', 0)
        if dns_query_length > 30:
            evidence.append(f"Long DNS queries: {dns_query_length:.0f} characters avg (normal < 20)")
        elif dns_query_length > 20:
            evidence.append(f"Elevated DNS query length: {dns_query_length:.0f} characters avg")
        
        # Maximum query length
        dns_max_query_length = flow_data.get('dns_max_query_length', 0)
        if dns_max_query_length > 40:
            evidence.append(f"Maximum query length: {dns_max_query_length:.0f} characters (suspicious for tunneling)")
        
        # High entropy queries
        dns_entropy = flow_data.get('dns_entropy', 0)
        if dns_entropy > 3.5:
            evidence.append(f"High query entropy: {dns_entropy:.2f} (indicates encoded data)")
        elif dns_entropy > 2.5:
            evidence.append(f"Elevated query entropy: {dns_entropy:.2f} (unusual for normal DNS)")
        
        # Unique subdomain count
        dns_unique_subdomain_count = flow_data.get('dns_unique_subdomain_count', 0)
        if dns_unique_subdomain_count > 0:
            evidence.append(f"Unique subdomains: {dns_unique_subdomain_count} (random subdomain generation)")
        
        # Subdomain entropy
        dns_subdomain_entropy = flow_data.get('dns_subdomain_entropy', 0)
        if dns_subdomain_entropy > 3.0:
            evidence.append(f"High subdomain entropy: {dns_subdomain_entropy:.2f} (encoded tunneling data)")
        
        # Query frequency
        dns_query_count = flow_data.get('dns_query_count', 0)
        if dns_query_count > 1:
            evidence.append(f"Multiple queries: {dns_query_count} per flow (tunneling requires frequent queries)")
        
        # Protocol check (should be UDP/DNS)
        protocol = flow_data.get('protocol', 0)
        if protocol == 17:  # UDP
            evidence.append("UDP protocol used (consistent with DNS traffic)")
        
        if not evidence:
            evidence.append("DNS tunneling detected based on query patterns and entropy analysis")
        
        return evidence
    
    def _benign_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        """Generate evidence for BENIGN classification"""
        evidence = []
        
        # Normal packet rates
        packets_per_second = flow_data.get('packets_per_second', 0)
        if packets_per_second < 100:
            evidence.append(f"Normal packet rate: {packets_per_second:.0f} packets/second")
        
        # Normal query lengths
        dns_query_length = flow_data.get('dns_query_length', 0)
        if dns_query_length > 0 and dns_query_length < 20:
            evidence.append(f"Normal DNS query length: {dns_query_length:.0f} characters")
        
        # Low entropy
        dns_entropy = flow_data.get('dns_entropy', 0)
        if dns_entropy > 0 and dns_entropy < 2.0:
            evidence.append(f"Low query entropy: {dns_entropy:.2f} (normal DNS patterns)")
        
        # Moderate port diversity
        dst_port_count = flow_data.get('dst_port_count', 0)
        if dst_port_count > 1 and dst_port_count < 10:
            evidence.append(f"Normal port diversity: {dst_port_count} unique ports")
        
        # Normal timing variation
        cv_interarrival = flow_data.get('cv_interarrival', 0)
        if cv_interarrival > 0.5 or cv_interarrival == 0:
            evidence.append(f"Normal timing variation: CV={cv_interarrival:.2f}")
        
        if not evidence:
            evidence.append("Normal traffic patterns detected")
        
        return evidence
    
    def _generic_evidence(self, flow_data: Dict[str, Any]) -> List[str]:
        """Generate generic evidence for unknown threat classes"""
        return ["Threat detected based on anomalous traffic patterns"]


class AlertGenerator:
    """Generate human-readable alerts from evidence"""
    
    def __init__(self, evidence_engine: EvidenceEngine):
        self.evidence_engine = evidence_engine
        # Threat-based severity mapping
        self.threat_severity = {
            'SYN_FLOOD': 'CRITICAL',
            'DNS_TUNNEL': 'HIGH',
            'C2_BEACON': 'HIGH',
            'PORT_SCAN': 'MEDIUM',
            'BENIGN': 'NONE'
        }
    
    def generate_alert(self, flow_data: Dict[str, Any], prediction: str, 
                      confidence: float = 1.0) -> Dict[str, Any]:
        """Generate a complete alert with evidence"""
        evidence = self.evidence_engine.generate_evidence(flow_data, prediction, confidence)
        
        alert = {
            'timestamp': evidence['timestamp'],
            'flow_id': evidence['flow_id'],
            'threat_class': evidence['threat_class'],
            'confidence': evidence['confidence'],
            'severity': self._get_severity(evidence['threat_class']),
            'evidence': evidence['evidence']
        }
        
        return alert
    
    def _get_severity(self, threat_class: str) -> str:
        """Get severity based on threat class"""
        return self.threat_severity.get(threat_class, 'UNKNOWN')
    
    def _generate_summary(self, evidence: Dict[str, Any]) -> str:
        """Generate a human-readable summary of the alert"""
        threat_class = evidence['threat_class']
        evidence_points = evidence['evidence']
        
        if threat_class == 'BENIGN':
            return "Normal traffic detected with no suspicious patterns"
        
        summary = f"{threat_class} detected: "
        if evidence_points:
            summary += evidence_points[0]
            if len(evidence_points) > 1:
                summary += f" (+{len(evidence_points)-1} more indicators)"
        
        return summary
    
    def generate_batch_alerts(self, flows_df: pd.DataFrame, predictions: np.ndarray) -> List[Dict[str, Any]]:
        """Generate alerts for multiple flows"""
        alerts = []
        
        for idx, row in flows_df.iterrows():
            flow_data = row.to_dict()
            prediction = predictions[idx]
            
            # Calculate confidence (simplified - in real system would use model probabilities)
            confidence = 1.0  # Using deterministic predictions for now
            
            alert = self.generate_alert(flow_data, prediction, confidence)
            alerts.append(alert)
        
        return alerts