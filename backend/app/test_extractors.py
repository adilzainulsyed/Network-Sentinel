import pytest
import os
import pandas as pd
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap
from backend.app.flows.extractor import FlowExtractor
from backend.app.features.extractor import FeatureExtractor

@pytest.fixture(scope="module")
def test_pcap_path(tmpdir_factory):
    # Generate a small test pcap
    pcap_file = str(tmpdir_factory.mktemp("data").join("test.pcap"))
    
    # 1 TCP flow (3 packets)
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S")
    pkt2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1000, flags="SA")
    pkt3 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A")
    
    # 1 DNS flow (2 packets)
    pkt4 = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.com"))
    pkt5 = IP(src="8.8.8.8", dst="10.0.0.1") / UDP(sport=53, dport=5353) / DNS(aa=1, qd=DNSQR(qname="test.com"))
    
    # Apply synthetic timestamps to simulate interarrival and flow duration
    pkt1.time = 1.0
    pkt2.time = 1.1
    pkt3.time = 1.2
    
    pkt4.time = 2.0
    pkt5.time = 2.5
    
    wrpcap(pcap_file, [pkt1, pkt2, pkt3, pkt4, pkt5])
    return pcap_file

def test_flow_extraction(test_pcap_path):
    extractor = FlowExtractor()
    extractor.process_pcap(test_pcap_path)
    
    assert len(extractor.flows) == 2
    df = extractor.to_dataframe()
    
    # Check TCP flow
    tcp_flow = df[(df['protocol'] == 6)].iloc[0]
    assert tcp_flow['packets'] == 3
    assert tcp_flow['fwd_bytes'] > 0
    assert tcp_flow['bwd_bytes'] > 0
    assert len(tcp_flow['packet_sizes']) == 3
    
    # Check DNS flow
    dns_flow = df[(df['protocol'] == 17)].iloc[0]
    assert dns_flow['packets'] == 2
    assert "test.com" in dns_flow['dns_queries'][0].decode('utf-8') if isinstance(dns_flow['dns_queries'][0], bytes) else dns_flow['dns_queries'][0]

def test_feature_extraction(test_pcap_path):
    flow_ext = FlowExtractor()
    flow_ext.process_pcap(test_pcap_path)
    df_flows = flow_ext.to_dataframe()
    
    feat_ext = FeatureExtractor(df_flows)
    df_features = feat_ext.extract_features()
    
    assert not df_features.empty
    assert 'flow_duration' in df_features.columns
    assert 'mean_packet_size' in df_features.columns
    assert 'dns_query_length' in df_features.columns
    
    # For src_ip 10.0.0.1, it talked to 10.0.0.2 and 8.8.8.8
    # So dst_host_count should be 2
    host_10_0_0_1 = df_features[df_features['src_ip'] == '10.0.0.1']
    assert host_10_0_0_1.iloc[0]['dst_host_count'] == 2
    
    # Check flow durations based on synthetic timestamps
    # TCP flow: 1.2 - 1.0 = 0.2
    # UDP flow: 2.5 - 2.0 = 0.5
    tcp_dur = df_features[df_features['protocol'] == 6].iloc[0]['flow_duration']
    udp_dur = df_features[df_features['protocol'] == 17].iloc[0]['flow_duration']
    
    assert abs(tcp_dur - 0.2) < 0.01
    assert abs(udp_dur - 0.5) < 0.01
