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
    parser.add_argument("--num_packets", type=int, default=100, help="Number of packets to generate per scenario")
    parser.add_argument("--out_dir", type=str, default="../data/pcaps", help="Output directory for PCAPs")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print(f"Generating scenarios with {args.num_packets} packets each...")

    # Generate Benign
    print("Generating BENIGN traffic...")
    benign_pkts = generate_benign(num_packets=args.num_packets)
    wrpcap(os.path.join(args.out_dir, "benign.pcap"), benign_pkts)

    # Generate SYN Flood
    print("Generating SYN_FLOOD traffic...")
    syn_flood_pkts = generate_syn_flood(num_packets=args.num_packets)
    wrpcap(os.path.join(args.out_dir, "syn_flood.pcap"), syn_flood_pkts)

    # Generate Port Scan
    print("Generating PORT_SCAN traffic...")
    port_scan_pkts = generate_port_scan(num_packets=args.num_packets)
    wrpcap(os.path.join(args.out_dir, "port_scan.pcap"), port_scan_pkts)

    # Generate C2 Beacon
    print("Generating C2_BEACON traffic...")
    c2_pkts = generate_c2_beacon(num_packets=args.num_packets)
    wrpcap(os.path.join(args.out_dir, "c2_beacon.pcap"), c2_pkts)

    # Generate DNS Tunnel
    print("Generating DNS_TUNNEL traffic...")
    dns_pkts = generate_dns_tunnel(num_packets=args.num_packets)
    wrpcap(os.path.join(args.out_dir, "dns_tunnel.pcap"), dns_pkts)

    print("Generation complete! Check the output directory.")

if __name__ == "__main__":
    main()
