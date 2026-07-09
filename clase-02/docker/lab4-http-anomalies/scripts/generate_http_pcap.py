#!/usr/bin/env python3
"""
MAR404 - Clase 2 - Lab 4
Genera un PCAP con tráfico HTTP mixto:
- Navegación web legítima con User-Agents normales (Chrome, Firefox, Edge)
- Tráfico C2 con User-Agent anómalo (WinHTTP/1.0) con patrón de beaconing

El estudiante debe:
1. Extraer y clasificar User-Agents
2. Identificar el UA anómalo
3. Analizar el patrón de comunicación del host sospechoso
4. Extraer IOCs
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
import random
import time
import base64
import os

OUTPUT_FILE = "/pcap/http_useragent_lab.pcap"

# Configuración
VICTIM_IP = "10.0.1.50"
C2_SERVER_IP = "203.0.113.100"
LEGIT_SERVERS = ["172.217.14.99", "151.101.1.69", "104.16.132.229", "13.107.42.14"]

# User-Agents legítimos
LEGIT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# User-Agent del C2 (anómalo)
C2_UA = "WinHTTP/1.0"

# URIs legítimas
LEGIT_URIS = [
    "/search?q=weather+santiago",
    "/images/logo.png",
    "/api/v2/news/latest",
    "/assets/js/main.js",
    "/favicon.ico",
    "/login",
    "/dashboard",
    "/api/notifications",
    "/static/css/style.css",
    "/products/catalog",
]

# URIs del C2
C2_URIS = [
    "/api/status",
    "/api/tasks",
    "/api/config",
]


def create_http_request(src_ip, dst_ip, sport, dport, host, uri, user_agent, method="GET"):
    """Crea un paquete HTTP request."""
    http_payload = (
        f"{method} {uri} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        f"Accept-Language: es-CL,es;q=0.9,en;q=0.8\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='PA', seq=random.randint(1000, 50000), ack=random.randint(1000, 50000)) / Raw(load=http_payload.encode())
    return pkt


def create_http_response(src_ip, dst_ip, sport, dport, status="200 OK", content_type="text/html", body=""):
    """Crea un paquete HTTP response."""
    http_payload = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Server: nginx/1.24.0\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='PA', seq=random.randint(1000, 50000), ack=random.randint(1000, 50000)) / Raw(load=http_payload.encode())
    return pkt


def generate_legit_traffic(count=40):
    """Genera tráfico HTTP legítimo."""
    packets = []
    for i in range(count):
        dst_ip = random.choice(LEGIT_SERVERS)
        ua = random.choice(LEGIT_UAS)
        uri = random.choice(LEGIT_URIS)
        sport = random.randint(49152, 65535)
        host = f"www.site{random.randint(1,5)}.com"
        
        # Request
        req = create_http_request(VICTIM_IP, dst_ip, sport, 80, host, uri, ua)
        packets.append(req)
        
        # Response
        body = f"<html><body>Page content {i}</body></html>"
        resp = create_http_response(dst_ip, VICTIM_IP, 80, sport, body=body)
        packets.append(resp)
    
    return packets


def generate_c2_traffic(beacon_count=25, interval_base=45):
    """Genera tráfico C2 con beaconing regular."""
    packets = []
    
    # Comandos C2 simulados (encoded en Base64)
    c2_commands = [
        base64.b64encode(b"whoami").decode(),
        base64.b64encode(b"hostname").decode(),
        base64.b64encode(b"ipconfig /all").decode(),
        base64.b64encode(b"tasklist").decode(),
        base64.b64encode(b"net user").decode(),
        base64.b64encode(b"NOOP").decode(),  # No operation (keep-alive)
    ]
    
    c2_responses = [
        base64.b64encode(b"CORP\\carlos.mendez").decode(),
        base64.b64encode(b"WS-CMENDEZ01").decode(),
        base64.b64encode(b"10.0.1.50/24 GW:10.0.1.1 DNS:10.0.1.1").decode(),
        base64.b64encode(b"chrome.exe PID:4521\nsvchost.exe PID:892\noutlook.exe PID:3344").decode(),
        base64.b64encode(b"Administrator\ncarlos.mendez\nGuest").decode(),
        base64.b64encode(b"OK").decode(),
    ]
    
    for i in range(beacon_count):
        sport = random.randint(49152, 65535)
        uri = random.choice(C2_URIS)
        
        # Beacon request (GET con UA anómalo)
        req = create_http_request(
            VICTIM_IP, C2_SERVER_IP, sport, 80,
            "cdn-update-service.com", uri, C2_UA
        )
        packets.append(req)
        
        # C2 response con comando encoded
        cmd_idx = i % len(c2_commands)
        body = f'{{"status":"ok","data":"{c2_commands[cmd_idx]}","id":{i}}}'
        resp = create_http_response(
            C2_SERVER_IP, VICTIM_IP, 80, sport,
            content_type="application/json", body=body
        )
        packets.append(resp)
        
        # Si hay comando real (no NOOP), el implant responde
        if c2_commands[cmd_idx] != base64.b64encode(b"NOOP").decode():
            post_body = f'{{"id":{i},"result":"{c2_responses[cmd_idx]}"}}'
            post_payload = (
                f"POST /api/results HTTP/1.1\r\n"
                f"Host: cdn-update-service.com\r\n"
                f"User-Agent: {C2_UA}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(post_body)}\r\n"
                f"\r\n"
                f"{post_body}"
            )
            post_pkt = IP(src=VICTIM_IP, dst=C2_SERVER_IP) / TCP(sport=sport+1, dport=80, flags='PA', seq=random.randint(1000, 50000), ack=random.randint(1000, 50000)) / Raw(load=post_payload.encode())
            packets.append(post_pkt)
    
    return packets


def generate_pcap():
    """Genera el PCAP completo."""
    print("[+] Generando tráfico HTTP legítimo (40 requests)...")
    legit_packets = generate_legit_traffic(40)
    
    print("[+] Generando tráfico C2 (25 beacons con UA anómalo)...")
    c2_packets = generate_c2_traffic(25)
    
    # Mezclar tráfico (intercalar C2 entre legítimo)
    all_packets = []
    c2_idx = 0
    legit_idx = 0
    
    for i in range(len(legit_packets) + len(c2_packets)):
        # Insertar C2 cada ~3 paquetes legítimos
        if c2_idx < len(c2_packets) and (i % 3 == 0 or legit_idx >= len(legit_packets)):
            all_packets.append(c2_packets[c2_idx])
            c2_idx += 1
        elif legit_idx < len(legit_packets):
            all_packets.append(legit_packets[legit_idx])
            legit_idx += 1
    
    # Agregar paquetes restantes
    all_packets.extend(c2_packets[c2_idx:])
    all_packets.extend(legit_packets[legit_idx:])
    
    print(f"[+] Total paquetes: {len(all_packets)}")
    print(f"[+] Guardando PCAP en {OUTPUT_FILE}...")
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    wrpcap(OUTPUT_FILE, all_packets)
    print("[+] Lab 4 listo para análisis")


if __name__ == "__main__":
    generate_pcap()
