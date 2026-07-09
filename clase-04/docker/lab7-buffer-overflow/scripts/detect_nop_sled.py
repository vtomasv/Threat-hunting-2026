#!/usr/bin/env python3
"""
detect_nop_sled.py
==================
Analiza un PCAP buscando NOP sleds (secuencias de 0x90) que indican
posibles exploits de buffer overflow.

Uso: detect_nop_sled /data/lab7_bof_upload.pcap [min_nop_length]

Curso MAR404 - Clase 4
"""

import sys
from scapy.all import rdpcap, TCP, Raw, IP


def find_nop_sleds(pcap_file, min_length=16):
    """Busca NOP sleds en payloads TCP."""
    print(f"[*] Analizando: {pcap_file}")
    print(f"[*] Longitud mínima de NOP sled: {min_length} bytes")
    print("=" * 70)
    
    packets = rdpcap(pcap_file)
    findings = []
    
    for i, pkt in enumerate(packets):
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = bytes(pkt[Raw].load)
            
            # Buscar secuencias de NOP (0x90)
            nop_count = 0
            max_nop = 0
            nop_start = -1
            
            for j, byte in enumerate(payload):
                if byte == 0x90:
                    if nop_count == 0:
                        nop_start = j
                    nop_count += 1
                    max_nop = max(max_nop, nop_count)
                else:
                    if nop_count >= min_length:
                        findings.append({
                            "packet": i + 1,
                            "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                            "dst": pkt[IP].dst if pkt.haslayer(IP) else "?",
                            "sport": pkt[TCP].sport,
                            "dport": pkt[TCP].dport,
                            "nop_offset": nop_start,
                            "nop_length": nop_count,
                            "payload_length": len(payload),
                            "post_nop_bytes": payload[nop_start + nop_count:nop_start + nop_count + 32].hex()
                        })
                    nop_count = 0
            
            # Check final sequence
            if nop_count >= min_length:
                findings.append({
                    "packet": i + 1,
                    "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                    "dst": pkt[IP].dst if pkt.haslayer(IP) else "?",
                    "sport": pkt[TCP].sport,
                    "dport": pkt[TCP].dport,
                    "nop_offset": nop_start,
                    "nop_length": nop_count,
                    "payload_length": len(payload),
                    "post_nop_bytes": payload[nop_start + nop_count:nop_start + nop_count + 32].hex()
                })
    
    if findings:
        print(f"\n[!] ALERTA: {len(findings)} NOP sled(s) detectado(s)!\n")
        for f in findings:
            print(f"  Paquete #{f['packet']}:")
            print(f"    Origen:      {f['src']}:{f['sport']}")
            print(f"    Destino:     {f['dst']}:{f['dport']}")
            print(f"    NOP offset:  byte {f['nop_offset']}")
            print(f"    NOP length:  {f['nop_length']} bytes")
            print(f"    Payload:     {f['payload_length']} bytes total")
            print(f"    Post-NOP:    {f['post_nop_bytes'][:64]}...")
            print(f"    [POSIBLE SHELLCODE después del NOP sled]")
            print()
    else:
        print("\n[+] No se detectaron NOP sleds significativos.")
    
    return findings


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "/data/lab7_bof_upload.pcap"
    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    find_nop_sleds(pcap, min_len)
