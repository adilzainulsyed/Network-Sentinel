from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS
import pandas as pd
import time

class FlowExtractor:
    def __init__(self):
        self.flows = {}

    def _get_flow_key(self, pkt):
        if IP not in pkt:
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        sport = 0
        dport = 0
        
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            sport = pkt[ICMP].type
            dport = pkt[ICMP].code
            
        # Bidirectional 5-tuple canonicalization
        # The direction is determined by whichever endpoint we see first
        key1 = (src_ip, dst_ip, sport, dport, proto)
        key2 = (dst_ip, src_ip, dport, sport, proto)
        
        if key2 in self.flows:
            return key2, False # False means this packet is backward
        return key1, True # True means this packet is forward

    def process_pcap(self, pcap_path):
        with PcapReader(pcap_path) as pcap:
            for pkt in pcap:
                if IP not in pkt:
                    continue
                    
                key_dir = self._get_flow_key(pkt)
                if not key_dir:
                    continue
                    
                flow_key, is_forward = key_dir
                
                pkt_time = float(pkt.time)
                pkt_len = len(pkt)
                
                if flow_key not in self.flows:
                    self.flows[flow_key] = {
                        "src_ip": flow_key[0],
                        "dst_ip": flow_key[1],
                        "src_port": flow_key[2],
                        "dst_port": flow_key[3],
                        "protocol": flow_key[4],
                        "start_time": pkt_time,
                        "end_time": pkt_time,
                        "fwd_packets": 0,
                        "bwd_packets": 0,
                        "fwd_bytes": 0,
                        "bwd_bytes": 0,
                        "packet_sizes": [],
                        "timestamps": [],
                        "dns_queries": []
                    }
                
                flow = self.flows[flow_key]
                flow["end_time"] = pkt_time
                flow["packet_sizes"].append(pkt_len)
                flow["timestamps"].append(pkt_time)
                
                if is_forward:
                    flow["fwd_packets"] += 1
                    flow["fwd_bytes"] += pkt_len
                else:
                    flow["bwd_packets"] += 1
                    flow["bwd_bytes"] += pkt_len
                    
                if DNS in pkt and pkt[DNS].qd:
                    try:
                        qname = pkt[DNS].qd.qname.decode('utf-8')
                        flow["dns_queries"].append(qname)
                    except:
                        pass
                        
    def to_dataframe(self):
        records = []
        for flow in self.flows.values():
            flow_duration = max(flow["end_time"] - flow["start_time"], 0.000001)
            packets = flow["fwd_packets"] + flow["bwd_packets"]
            bytes_count = flow["fwd_bytes"] + flow["bwd_bytes"]
            
            records.append({
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                "packets": packets,
                "bytes": bytes_count,
                "flow_duration": flow_duration,
                "packet_sizes": flow["packet_sizes"],
                "timestamps": flow["timestamps"],
                "fwd_bytes": flow["fwd_bytes"],
                "bwd_bytes": flow["bwd_bytes"],
                "dns_queries": flow["dns_queries"]
            })
            
        return pd.DataFrame(records)

    def to_csv(self, output_path):
        df = self.to_dataframe()
        # Drop lists before saving to simple CSV if requested, or convert to string
        df_csv = df.drop(columns=['packet_sizes', 'timestamps', 'dns_queries'], errors='ignore')
        df_csv.to_csv(output_path, index=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        extractor = FlowExtractor()
        extractor.process_pcap(sys.argv[1])
        extractor.to_csv(sys.argv[2])
        print(f"Extracted {len(extractor.flows)} flows to {sys.argv[2]}")
