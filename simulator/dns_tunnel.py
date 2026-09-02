from scapy.all import IP, UDP, DNS, DNSQR
import random
import base64

def generate_dns_tunnel(num_packets=50, src_ip="192.168.1.50", dns_ip="8.8.8.8", domain="tunnel.malicious.com"):
    packets = []
    
    for i in range(num_packets):
        sport = random.randint(1024, 65535)
        
        # Create a random payload
        random_data = f"data_chunk_{i}_" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20))
        encoded_data = base64.b32encode(random_data.encode()).decode().lower().replace("=", "")
        
        qname = f"{encoded_data}.{domain}"
        
        pkt = IP(src=src_ip, dst=dns_ip) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        packets.append(pkt)
        
    return packets
