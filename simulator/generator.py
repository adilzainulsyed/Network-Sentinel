import argparse
import os
from scapy.all import wrpcap

from benign import generate_benign
from syn_flood import generate_syn_flood
from port_scan import generate_port_scan
from c2_beacon import generate_c2_beacon
from dns_tunnel import generate_dns_tunnel

def main():
    parser = argparse.ArgumentParser(description="NTRO Network Traffic Simulator")
    parser.add_argument("--out_dir", type=str, default="../data/pcaps", help="Output directory for PCAPs")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Requested flow counts
    counts = {
        "BENIGN": 5000,
        "SYN_FLOOD": 2000,
        "PORT_SCAN": 2000,
        "C2_BEACON": 2000,
        "DNS_TUNNEL": 2000
    }

    print("Generating scenarios...")

    print(f"Generating {counts['BENIGN']} BENIGN flows...")
    benign_pkts = generate_benign(num_packets=counts['BENIGN'])
    wrpcap(os.path.join(args.out_dir, "benign.pcap"), benign_pkts)

    print(f"Generating {counts['SYN_FLOOD']} SYN_FLOOD flows...")
    syn_flood_pkts = generate_syn_flood(num_packets=counts['SYN_FLOOD'])
    wrpcap(os.path.join(args.out_dir, "syn_flood.pcap"), syn_flood_pkts)

    print(f"Generating {counts['PORT_SCAN']} PORT_SCAN flows...")
    port_scan_pkts = generate_port_scan(num_packets=counts['PORT_SCAN'])
    wrpcap(os.path.join(args.out_dir, "port_scan.pcap"), port_scan_pkts)

    print(f"Generating {counts['C2_BEACON']} C2_BEACON flows with varying intervals...")
    # Generate C2 beacon with varying intervals for training diversity
    c2_pkts = []
    intervals = [30.0, 60.0, 120.0, 300.0]  # Different beacon intervals
    packets_per_interval = counts['C2_BEACON'] // len(intervals)
    
    for interval in intervals:
        pkts = generate_c2_beacon(num_packets=packets_per_interval, base_interval=interval, jitter_percent=0.2)
        c2_pkts.extend(pkts)
    
    wrpcap(os.path.join(args.out_dir, "c2_beacon.pcap"), c2_pkts)

    print(f"Generating {counts['DNS_TUNNEL']} DNS_TUNNEL flows...")
    dns_pkts = generate_dns_tunnel(num_packets=counts['DNS_TUNNEL'])
    wrpcap(os.path.join(args.out_dir, "dns_tunnel.pcap"), dns_pkts)

    print("Generation complete! Check the output directory.")

if __name__ == "__main__":
    main()
