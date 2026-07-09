#!/usr/bin/env python3
"""
timeline_builder.py
===================
Construye una timeline de eventos del incidente a partir del PCAP.
Identifica automáticamente las fases del ataque.

Uso: timeline_builder /data/lab8_incident.pcap

Curso MAR404 - Clase 4 - Evaluación
"""

import sys
from scapy.all import rdpcap, TCP, UDP, DNS, DNSQR, Raw, IP


def build_timeline(pcap_file):
    """Construye timeline del incidente."""
    print(f"[*] Construyendo timeline de: {pcap_file}")
    print("=" * 80)
    
    packets = rdpcap(pcap_file)
    events = []
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(IP):
            continue
        
        src = pkt[IP].src
        dst = pkt[IP].dst
        event = None
        
        # Detectar SYN scan
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            if pkt[TCP].dport in [21, 22, 25, 80, 443, 445, 3306, 8080, 8443, 9200]:
                event = {
                    "phase": "RECON",
                    "desc": f"SYN scan → {dst}:{pkt[TCP].dport}",
                    "src": src, "dst": dst,
                    "severity": "LOW"
                }
        
        # Detectar NOP sled (exploit)
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if b"\x90" * 32 in payload:
                event = {
                    "phase": "EXPLOIT",
                    "desc": f"Buffer overflow (NOP sled {payload.count(0x90)} bytes) → {dst}:{pkt[TCP].dport}",
                    "src": src, "dst": dst,
                    "severity": "CRITICAL"
                }
            elif b"cmd=" in payload or b"system(" in payload:
                event = {
                    "phase": "EXECUTION",
                    "desc": f"Web shell execution → {dst}",
                    "src": src, "dst": dst,
                    "severity": "HIGH"
                }
            elif b"multipart/form-data" in payload and b"filename=" in payload:
                event = {
                    "phase": "PERSISTENCE",
                    "desc": f"File upload (posible web shell) → {dst}",
                    "src": src, "dst": dst,
                    "severity": "HIGH"
                }
            elif b"../" in payload or b"php://" in payload:
                event = {
                    "phase": "DISCOVERY",
                    "desc": f"LFI attempt → {dst}",
                    "src": src, "dst": dst,
                    "severity": "MEDIUM"
                }
        
        # Detectar reverse shell (conexión a puerto 4443/4444)
        if pkt.haslayer(TCP) and pkt[TCP].dport in [4443, 4444] and pkt[TCP].flags == "S":
            event = {
                "phase": "C2",
                "desc": f"Reverse shell connection → {dst}:{pkt[TCP].dport}",
                "src": src, "dst": dst,
                "severity": "CRITICAL"
            }
        
        # Detectar SMB lateral movement
        if pkt.haslayer(TCP) and pkt[TCP].dport == 445 and pkt[TCP].flags == "S":
            if src not in ["192.168.10.50", "192.168.10.51", "192.168.10.52"]:
                event = {
                    "phase": "LATERAL",
                    "desc": f"SMB connection (lateral movement) → {dst}:445",
                    "src": src, "dst": dst,
                    "severity": "HIGH"
                }
        
        # Detectar DNS tunneling
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
            if len(qname) > 50 or "data." in qname or "evil" in qname:
                event = {
                    "phase": "EXFIL",
                    "desc": f"DNS tunneling: {qname[:60]}...",
                    "src": src, "dst": dst,
                    "severity": "CRITICAL"
                }
        
        if event:
            event["packet"] = i + 1
            events.append(event)
    
    # Imprimir timeline
    phase_order = {"RECON": 1, "EXPLOIT": 2, "C2": 3, "LATERAL": 4, "PERSISTENCE": 5, "EXECUTION": 6, "DISCOVERY": 7, "EXFIL": 8}
    severity_colors = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  ", "LOW": ".  "}
    
    print(f"\n{'PKT':<6} {'SEVERITY':<10} {'PHASE':<12} {'SRC':<18} {'DST':<18} {'DESCRIPCIÓN'}")
    print("-" * 100)
    
    for e in events:
        sev = severity_colors.get(e["severity"], "   ")
        print(f"{e['packet']:<6} {sev}{e['severity']:<7} {e['phase']:<12} {e['src']:<18} {e['dst']:<18} {e['desc'][:50]}")
    
    # Resumen
    print("\n" + "=" * 80)
    print("RESUMEN DEL INCIDENTE:")
    print(f"  Total eventos sospechosos: {len(events)}")
    phases_found = set(e["phase"] for e in events)
    print(f"  Fases detectadas: {', '.join(sorted(phases_found, key=lambda x: phase_order.get(x, 99)))}")
    
    attackers = set(e["src"] for e in events if e["severity"] in ["CRITICAL", "HIGH"])
    print(f"  IPs atacantes: {', '.join(attackers)}")
    
    victims = set(e["dst"] for e in events if e["severity"] in ["CRITICAL", "HIGH"])
    print(f"  IPs víctimas: {', '.join(victims)}")
    print("=" * 80)


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "/data/lab8_incident.pcap"
    build_timeline(pcap)
