from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, Raw
import random
import time

def generate_benign(num_packets=100, src_ips=["192.168.1.100", "192.168.1.101"], dst_ips=["8.8.8.8", "1.1.1.1", "10.0.0.5"]):
    packets = []
    ports = [80, 443, 53]
    
    for _ in range(num_packets):
        src = random.choice(src_ips)
        dst = random.choice(dst_ips)
        sport = random.randint(1024, 65535)
        dport = random.choice(ports)
        
        # Ether layer for PCAP correctness if needed, but often IP is enough
        # We'll just generate IP packets and let Scapy write them.
        
        if dport == 53: # DNS
            pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        elif dport in [80, 443]: # HTTP/HTTPS SYN
            pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
            
        packets.append(pkt)
        
    return packets
