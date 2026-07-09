#!/usr/bin/env python3
"""
ioc_extractor.py
================
Extrae IOCs (Indicators of Compromise) del PCAP del incidente.

Uso: ioc_extractor /data/lab8_incident.pcap

Curso MAR404 - Clase 4 - Evaluación
"""

import sys
import re
from collections import Counter
from scapy.all import rdpcap, TCP, UDP, DNS, DNSQR, Raw, IP


def extract_iocs(pcap_file):
    """Extrae IOCs del PCAP."""
    print(f"[*] Extrayendo IOCs de: {pcap_file}")
    print("=" * 70)
    
    packets = rdpcap(pcap_file)
    
    # Colecciones de IOCs
    suspicious_ips = Counter()
    suspicious_domains = []
    suspicious_uris = []
    suspicious_ports = Counter()
    credentials_found = []
    files_uploaded = []
    
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        
        src = pkt[IP].src
        dst = pkt[IP].dst
        
        # IPs con actividad sospechosa
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            
            # NOP sled = IP atacante
            if b"\x90" * 16 in payload:
                suspicious_ips[src] += 5
            
            # LFI/RFI
            if b"../" in payload or b"php://" in payload:
                suspicious_ips[src] += 3
                uri_match = re.search(rb'(GET|POST)\s+([^\s]+)', payload)
                if uri_match:
                    suspicious_uris.append(uri_match.group(2).decode('latin-1')[:200])
            
            # Web shell
            if b"cmd=" in payload:
                suspicious_ips[src] += 4
                uri_match = re.search(rb'GET\s+([^\s]+)', payload)
                if uri_match:
                    suspicious_uris.append(uri_match.group(1).decode('latin-1')[:200])
            
            # File upload
            if b"filename=" in payload:
                fn_match = re.search(rb'filename="([^"]+)"', payload)
                if fn_match:
                    files_uploaded.append(fn_match.group(1).decode('latin-1'))
                    suspicious_ips[src] += 3
            
            # Credentials in traffic
            cred_patterns = [
                rb'(DB_PASS|password|passwd|pwd)\s*[=:]\s*([^\s\r\n;]+)',
                rb'(\$6\$[a-zA-Z0-9./]+)',
            ]
            for pattern in cred_patterns:
                matches = re.findall(pattern, payload)
                for m in matches:
                    if isinstance(m, tuple):
                        credentials_found.append(f"{m[0].decode('latin-1')}={m[1].decode('latin-1')}")
                    else:
                        credentials_found.append(m.decode('latin-1'))
        
        # DNS sospechoso
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else str(pkt[DNSQR].qname)
            if len(qname) > 50 or any(x in qname for x in ["evil", "data.", "exfil"]):
                suspicious_domains.append(qname.rstrip("."))
                suspicious_ips[src] += 2
        
        # Puertos sospechosos (reverse shell)
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            if pkt[TCP].dport in [4443, 4444, 4445, 5555, 6666, 7777, 8888, 9999]:
                suspicious_ports[pkt[TCP].dport] += 1
                suspicious_ips[src] += 3
    
    # Reportar IOCs
    print("\n[IOC] IPs SOSPECHOSAS (por score de actividad):")
    print("-" * 50)
    for ip, score in suspicious_ips.most_common(10):
        print(f"  {ip:<20} Score: {score}")
    
    if suspicious_domains:
        print(f"\n[IOC] DOMINIOS SOSPECHOSOS ({len(suspicious_domains)}):")
        print("-" * 50)
        unique_domains = list(set(suspicious_domains))
        for d in unique_domains[:10]:
            print(f"  {d}")
    
    if suspicious_uris:
        print(f"\n[IOC] URIs MALICIOSAS ({len(suspicious_uris)}):")
        print("-" * 50)
        for u in list(set(suspicious_uris)):
            print(f"  {u}")
    
    if suspicious_ports:
        print(f"\n[IOC] PUERTOS C2/REVERSE SHELL:")
        print("-" * 50)
        for port, count in suspicious_ports.most_common():
            print(f"  Puerto {port}: {count} conexiones")
    
    if files_uploaded:
        print(f"\n[IOC] ARCHIVOS SUBIDOS:")
        print("-" * 50)
        for f in files_uploaded:
            print(f"  {f}")
    
    if credentials_found:
        print(f"\n[IOC] CREDENCIALES EXPUESTAS:")
        print("-" * 50)
        for c in list(set(credentials_found)):
            print(f"  {c}")
    
    print("\n" + "=" * 70)
    print("NOTA: Estos IOCs deben ser validados y correlacionados manualmente.")
    print("Usar la plantilla de reporte en /plantilla/reporte_forense.md")
    print("=" * 70)


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "/data/lab8_incident.pcap"
    extract_iocs(pcap)
