import pandas as pd
import numpy as np
from scipy.stats import entropy
import collections

class FeatureExtractor:
    def __init__(self, flows_df):
        self.df = flows_df.copy()

    def _shannon_entropy(self, s):
        if not s:
            return 0.0
        probabilities = [n_x / len(s) for x, n_x in collections.Counter(s).items()]
        return entropy(probabilities, base=2)

    def extract_features(self):
        if self.df.empty:
            return pd.DataFrame()

        # Basic counts and rates
        self.df['flow_duration'] = self.df['flow_duration']
        self.df['packet_count'] = self.df['packets']
        self.df['byte_count'] = self.df['bytes']
        
        self.df['packets_per_second'] = self.df['packet_count'] / self.df['flow_duration']
        self.df['bytes_per_second'] = self.df['byte_count'] / self.df['flow_duration']

        # Packet sizes
        self.df['mean_packet_size'] = self.df['packet_sizes'].apply(lambda x: np.mean(x) if x else 0)
        self.df['std_packet_size'] = self.df['packet_sizes'].apply(lambda x: np.std(x) if len(x) > 1 else 0)

        # Interarrival time statistics for beaconing detection
        def calc_iat_stats(timestamps):
            if len(timestamps) > 1:
                iats = np.diff(timestamps)
                mean_iat = np.mean(iats)
                std_iat = np.std(iats) if len(iats) > 1 else 0.0
                # Coefficient of variation (std/mean) - low CV indicates regularity (beaconing)
                cv_iat = std_iat / mean_iat if mean_iat > 0 else 0.0
                return mean_iat, std_iat, cv_iat
            return 0.0, 0.0, 0.0
            
        iat_stats = self.df['timestamps'].apply(calc_iat_stats)
        self.df['mean_interarrival'] = [x[0] for x in iat_stats]
        self.df['std_interarrival'] = [x[1] for x in iat_stats]
        self.df['cv_interarrival'] = [x[2] for x in iat_stats]

        # Byte ratios
        self.df['src_dst_byte_ratio'] = self.df.apply(
            lambda row: row['fwd_bytes'] / row['bwd_bytes'] if row['bwd_bytes'] > 0 else row['fwd_bytes'], 
            axis=1
        )

        # DNS features
        def process_dns_length(queries):
            if not queries:
                return 0.0
            return np.mean([len(q) for q in queries])

        def process_dns_max_length(queries):
            if not queries:
                return 0.0
            return max([len(q) for q in queries])

        def process_dns_count(queries):
            if not queries:
                return 0
            return len(queries)

        def process_dns_entropy(queries):
            if not queries:
                return 0.0
            # Calculate entropy of the longest query or all combined
            combined = "".join(queries)
            return self._shannon_entropy(combined)

        def process_dns_unique_subdomains(queries):
            if not queries:
                return 0
            # Extract unique subdomains (parts before the main domain)
            subdomains = set()
            for query in queries:
                parts = query.split('.')
                if len(parts) > 2:  # Has subdomain(s)
                    subdomains.add(parts[0])  # Take first subdomain
            return len(subdomains)

        def process_dns_subdomain_entropy(queries):
            if not queries:
                return 0.0
            # Calculate entropy of subdomain parts
            subdomain_chars = []
            for query in queries:
                parts = query.split('.')
                if len(parts) > 2:
                    subdomain_chars.extend(list(parts[0]))  # Characters from first subdomain
            if not subdomain_chars:
                return 0.0
            return self._shannon_entropy(subdomain_chars)

        self.df['dns_query_length'] = self.df['dns_queries'].apply(process_dns_length)
        self.df['dns_max_query_length'] = self.df['dns_queries'].apply(process_dns_max_length)
        self.df['dns_query_count'] = self.df['dns_queries'].apply(process_dns_count)
        self.df['dns_entropy'] = self.df['dns_queries'].apply(process_dns_entropy)
        self.df['dns_unique_subdomain_count'] = self.df['dns_queries'].apply(process_dns_unique_subdomains)
        self.df['dns_subdomain_entropy'] = self.df['dns_queries'].apply(process_dns_subdomain_entropy)

        # Diversity features: dst_port_count and dst_host_count
        # Group by source IP to find how many unique destinations and ports it contacts
        host_counts = self.df.groupby('src_ip')['dst_ip'].nunique().to_dict()
        port_counts = self.df.groupby('src_ip')['dst_port'].nunique().to_dict()

        self.df['dst_host_count'] = self.df['src_ip'].map(host_counts)
        self.df['dst_port_count'] = self.df['src_ip'].map(port_counts)

        # Destination repetition features for beaconing detection
        # Count how many times each source connects to the same destination
        connection_counts = self.df.groupby(['src_ip', 'dst_ip']).size().to_dict()
        self.df['dst_connection_count'] = self.df.apply(
            lambda row: connection_counts.get((row['src_ip'], row['dst_ip']), 0), 
            axis=1
        )

        # Select ML-ready columns
        features = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'flow_duration', 'packet_count', 'byte_count',
            'packets_per_second', 'bytes_per_second',
            'mean_packet_size', 'std_packet_size',
            'mean_interarrival', 'std_interarrival', 'cv_interarrival',
            'dst_port_count', 'dst_host_count', 'dst_connection_count',
            'src_dst_byte_ratio', 'dns_query_length', 'dns_max_query_length', 
            'dns_query_count', 'dns_entropy', 'dns_unique_subdomain_count', 'dns_subdomain_entropy'
        ]
        
        return self.df[features]

if __name__ == "__main__":
    import sys
    import os
    
    # Add project root to PYTHONPATH so we can import backend
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        
    from backend.app.flows.extractor import FlowExtractor
    
    if len(sys.argv) > 2:
        pcap_path = sys.argv[1]
        out_csv = sys.argv[2]
        
        print(f"Extracting flows from {pcap_path}...")
        flow_ext = FlowExtractor()
        flow_ext.process_pcap(pcap_path)
        df_flows = flow_ext.to_dataframe()
        
        print(f"Extracting ML features...")
        feat_ext = FeatureExtractor(df_flows)
        df_features = feat_ext.extract_features()
        
        df_features.to_csv(out_csv, index=False)
        print(f"Saved features for {len(df_features)} flows to {out_csv}")
