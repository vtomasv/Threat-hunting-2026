#!/usr/bin/env python3
"""
generate_c2_pcap.py
===================
Genera un archivo PCAP sintético con:
- Tráfico HTTP normal (navegación web legítima simulada)
- Tráfico DNS normal
- Beaconing C2 HTTP con intervalos regulares (~60s ± jitter)
- User-Agent anómalo en las conexiones C2

El PCAP resultante simula 30 minutos de captura de un host comprometido.

Curso MAR404 - Cacería de Amenazas - Clase 1
Universidad Mayor 2026
"""

import os
import random
import struct
import time
from datetime import datetime, timedelta

# Intentar importar scapy
try:
    from scapy.all import (
        IP, TCP, UDP, DNS, DNSQR, Ether, Raw,
        wrpcap, RandShort
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

OUTPUT_FILE = "/pcap/c2_beaconing.pcap"

# Configuración del escenario
VICTIM_IP = "192.168.1.105"
VICTIM_MAC = "00:11:22:33:44:55"
GATEWAY_MAC = "aa:bb:cc:dd:ee:ff"
DNS_SERVER = "192.168.1.1"

# C2 Server
C2_IP = "203.0.113.42"
C2_DOMAIN = "update-service-cdn.com"
C2_USER_AGENT = "Mozilla/5.0 (compatible; UpdateAgent/1.0)"
C2_BEACON_INTERVAL = 60  # segundos
C2_JITTER = 2  # ± segundos

# Sitios legítimos para tráfico normal
LEGIT_SITES = [
    {"ip": "142.250.80.46", "domain": "www.google.com", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"ip": "13.107.42.14", "domain": "outlook.office365.com", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"ip": "151.101.1.69", "domain": "www.reddit.com", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"ip": "104.16.132.229", "domain": "cdn.cloudflare.com", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"ip": "185.199.108.153", "domain": "github.com", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
]


def generate_pcap_scapy():
    """Genera el PCAP usando Scapy."""
    packets = []
    base_time = datetime(2026, 1, 15, 10, 0, 0)
    
    # Generar 30 minutos de tráfico
    duration_seconds = 1800
    
    # === TRÁFICO C2 BEACONING ===
    beacon_times = []
    current_time = 5  # Primer beacon a los 5 segundos
    while current_time < duration_seconds:
        beacon_times.append(current_time)
        current_time += C2_BEACON_INTERVAL + random.randint(-C2_JITTER, C2_JITTER)
    
    for bt in beacon_times:
        src_port = random.randint(49152, 65535)
        
        # DNS query para el C2
        dns_pkt = (
            Ether(src=VICTIM_MAC, dst=GATEWAY_MAC) /
            IP(src=VICTIM_IP, dst=DNS_SERVER) /
            UDP(sport=src_port, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=C2_DOMAIN))
        )
        dns_pkt.time = bt
        packets.append(dns_pkt)
        
        # HTTP GET al C2 (beacon check-in)
        http_request = (
            f"GET /api/v1/check HTTP/1.1\r\n"
            f"Host: {C2_DOMAIN}\r\n"
            f"User-Agent: {C2_USER_AGENT}\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        
        # SYN
        syn = (
            Ether(src=VICTIM_MAC, dst=GATEWAY_MAC) /
            IP(src=VICTIM_IP, dst=C2_IP) /
            TCP(sport=src_port, dport=80, flags='S', seq=1000)
        )
        syn.time = bt + 0.05
        packets.append(syn)
        
        # SYN-ACK
        syn_ack = (
            Ether(src=GATEWAY_MAC, dst=VICTIM_MAC) /
            IP(src=C2_IP, dst=VICTIM_IP) /
            TCP(sport=80, dport=src_port, flags='SA', seq=2000, ack=1001)
        )
        syn_ack.time = bt + 0.1
        packets.append(syn_ack)
        
        # ACK + HTTP Request
        http_pkt = (
            Ether(src=VICTIM_MAC, dst=GATEWAY_MAC) /
            IP(src=VICTIM_IP, dst=C2_IP) /
            TCP(sport=src_port, dport=80, flags='PA', seq=1001, ack=2001) /
            Raw(load=http_request.encode())
        )
        http_pkt.time = bt + 0.15
        packets.append(http_pkt)
        
        # HTTP Response (C2 command - simulated)
        http_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: 32\r\n"
            f"Server: nginx/1.24.0\r\n"
            f"\r\n"
            f'{{\"status\":\"ok\",\"cmd\":\"sleep\"}}'
        )
        
        resp_pkt = (
            Ether(src=GATEWAY_MAC, dst=VICTIM_MAC) /
            IP(src=C2_IP, dst=VICTIM_IP) /
            TCP(sport=80, dport=src_port, flags='PA', seq=2001, ack=1001+len(http_request)) /
            Raw(load=http_response.encode())
        )
        resp_pkt.time = bt + 0.3
        packets.append(resp_pkt)
    
    # === TRÁFICO LEGÍTIMO (ruido de fondo) ===
    for _ in range(150):
        t = random.uniform(0, duration_seconds)
        site = random.choice(LEGIT_SITES)
        src_port = random.randint(49152, 65535)
        
        # DNS para sitio legítimo
        dns_pkt = (
            Ether(src=VICTIM_MAC, dst=GATEWAY_MAC) /
            IP(src=VICTIM_IP, dst=DNS_SERVER) /
            UDP(sport=random.randint(49152, 65535), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=site["domain"]))
        )
        dns_pkt.time = t
        packets.append(dns_pkt)
        
        # HTTP request legítimo
        http_req = (
            f"GET /{random.choice(['', 'index.html', 'api/data', 'assets/main.js'])} HTTP/1.1\r\n"
            f"Host: {site['domain']}\r\n"
            f"User-Agent: {site['ua']}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"\r\n"
        )
        
        pkt = (
            Ether(src=VICTIM_MAC, dst=GATEWAY_MAC) /
            IP(src=VICTIM_IP, dst=site["ip"]) /
            TCP(sport=src_port, dport=443, flags='PA', seq=random.randint(1000, 50000)) /
            Raw(load=http_req.encode())
        )
        pkt.time = t + 0.1
        packets.append(pkt)
    
    # Ordenar por tiempo
    packets.sort(key=lambda p: float(p.time))
    
    # Escribir PCAP
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    wrpcap(OUTPUT_FILE, packets)
    
    print(f"[+] PCAP generado: {OUTPUT_FILE}")
    print(f"[+] Total paquetes: {len(packets)}")
    print(f"[+] Beacons C2: {len(beacon_times)} (intervalo ~{C2_BEACON_INTERVAL}s)")
    print(f"[+] C2 IP: {C2_IP}")
    print(f"[+] C2 Domain: {C2_DOMAIN}")
    print(f"[+] C2 User-Agent: {C2_USER_AGENT}")


def generate_pcap_raw():
    """Genera un PCAP básico sin Scapy (fallback)."""
    import struct
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # PCAP Global Header
    pcap_header = struct.pack(
        '<IHHiIII',
        0xa1b2c3d4,  # magic number
        2, 4,         # version
        0,            # timezone
        0,            # sigfigs
        65535,        # snaplen
        1             # link type (Ethernet)
    )
    
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(pcap_header)
        # Escribir un paquete dummy para que el archivo sea válido
        # En producción se usaría Scapy
        timestamp = int(time.time())
        dummy_packet = b'\x00' * 64
        packet_header = struct.pack('<IIII', timestamp, 0, len(dummy_packet), len(dummy_packet))
        f.write(packet_header + dummy_packet)
    
    print(f"[+] PCAP básico generado: {OUTPUT_FILE}")
    print("[!] Nota: Instale scapy para generar PCAP completo con tráfico realista")


def main():
    if SCAPY_AVAILABLE:
        generate_pcap_scapy()
    else:
        print("[!] Scapy no disponible, generando PCAP básico")
        generate_pcap_raw()


if __name__ == "__main__":
    main()
