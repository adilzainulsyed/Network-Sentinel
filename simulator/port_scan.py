from scapy.all import IP, TCP
import random

def generate_port_scan(num_packets=100, src_ip="192.168.1.50", target_ip="10.0.0.5"):
    packets = []
    ports = list(range(1, 1024)) + [8080, 8443, 3306, 22, 21, 23]
    
    # We will simulate scanning up to num_packets ports
    scan_ports = random.sample(ports, min(num_packets, len(ports)))
    
    for dport in scan_ports:
        sport = random.randint(1024, 65535)
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags="S")
        packets.append(pkt)
        
    # If num_packets > len(ports), add more random port scans
    while len(packets) < num_packets:
        sport = random.randint(1024, 65535)
        dport = random.randint(1024, 65535)
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=dport, flags="S")
        packets.append(pkt)
        
    return packets
