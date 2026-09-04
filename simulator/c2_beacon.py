from scapy.all import IP, TCP, Raw
import random
import time

def generate_c2_beacon(num_packets=50, src_ip="192.168.1.50", c2_ip="185.20.10.5", c2_port=80, 
                       base_interval=60.0, jitter_percent=0.2):
    """
    Generate C2 beacon traffic with varying intervals and timing jitter.
    
    Args:
        num_packets: Number of beacon packets to generate
        src_ip: Source IP address
        c2_ip: C2 server IP address  
        c2_port: C2 server port
        base_interval: Base beacon interval in seconds
        jitter_percent: Percentage of jitter to add (0.2 = 20%)
    """
    packets = []
    current_time = time.time()
    
    for i in range(num_packets):
        sport = random.randint(1024, 65535)
        
        # HTTP GET request simulating a beacon
        payload = f"GET /beacon/{i} HTTP/1.1\r\nHost: {c2_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        pkt = IP(src=src_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="PA") / Raw(load=payload)
        
        # Add timestamp to simulate beacon intervals
        jitter = base_interval * jitter_percent * (random.random() - 0.5) * 2
        interval = base_interval + jitter
        current_time += interval
        
        pkt.time = current_time
        packets.append(pkt)
        
    return packets
