from scapy.all import IP, TCP, Raw
import random

def generate_c2_beacon(num_packets=50, src_ip="192.168.1.50", c2_ip="185.20.10.5", c2_port=80):
    packets = []
    
    for i in range(num_packets):
        sport = random.randint(1024, 65535)
        
        # HTTP GET request simulating a beacon
        payload = f"GET /beacon/{i} HTTP/1.1\r\nHost: {c2_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        pkt = IP(src=src_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="PA") / Raw(load=payload)
        packets.append(pkt)
        
    return packets
