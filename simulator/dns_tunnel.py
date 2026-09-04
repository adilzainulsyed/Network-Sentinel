from scapy.all import IP, UDP, DNS, DNSQR
import random
import base64
import string

def generate_dns_tunnel(num_packets=50, src_ip="192.168.1.50", dns_ip="8.8.8.8", domain="tunnel.malicious.com",
                       min_subdomain_length=10, max_subdomain_length=30, encoding_variety=True):
    """
    Generate DNS tunnel traffic with varying query lengths, entropy, and patterns.
    
    Args:
        num_packets: Number of DNS tunnel packets to generate
        src_ip: Source IP address
        dns_ip: DNS server IP address
        domain: Base domain for tunneling
        min_subdomain_length: Minimum length of generated subdomains
        max_subdomain_length: Maximum length of generated subdomains
        encoding_variety: Use different encoding schemes for variation
    """
    packets = []
    
    for i in range(num_packets):
        sport = random.randint(1024, 65535)
        
        # Vary the encoding scheme for diversity
        if encoding_variety and random.random() < 0.5:
            # Base32 encoding (high entropy)
            random_data = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(15, 25)))
            encoded_data = base64.b32encode(random_data.encode()).decode().lower().replace("=", "")
        else:
            # Base64-like encoding (different entropy pattern)
            random_data = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(15, 25)))
            encoded_data = base64.b64encode(random_data.encode()).decode().lower().replace("=", "").replace("/", "-").replace("+", "_")
        
        # Ensure length variation
        if len(encoded_data) < min_subdomain_length:
            encoded_data = encoded_data + "".join(random.choices(string.ascii_lowercase, k=min_subdomain_length - len(encoded_data)))
        elif len(encoded_data) > max_subdomain_length:
            encoded_data = encoded_data[:max_subdomain_length]
        
        # Create multi-level subdomains for some packets (common in DNS tunneling)
        if random.random() < 0.3:
            subdomain_parts = encoded_data[:len(encoded_data)//2], encoded_data[len(encoded_data)//2:]
            qname = f"{'.'.join(subdomain_parts)}.{domain}"
        else:
            qname = f"{encoded_data}.{domain}"
        
        # Vary DNS record types
        record_types = ["TXT", "CNAME", "MX", "A"]
        qtype = random.choice(record_types)
        
        pkt = IP(src=src_ip, dst=dns_ip) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
        packets.append(pkt)
        
    return packets
