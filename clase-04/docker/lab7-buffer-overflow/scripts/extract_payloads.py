#!/usr/bin/env python3
"""
extract_payloads.py
===================
Extrae y analiza payloads HTTP de un PCAP, buscando:
- File uploads (multipart/form-data)
- Web shell executions (parámetros cmd/exec/system)
- LFI/RFI patterns en URLs
- Archivos polyglot (magic bytes + código)

Uso: extract_payloads /data/lab7_bof_upload.pcap

Curso MAR404 - Clase 4
"""

import sys
import os
import re
from scapy.all import rdpcap, TCP, Raw, IP


def extract_http_uploads(pcap_file):
    """Extrae archivos subidos via HTTP POST multipart."""
    print(f"[*] Extrayendo uploads de: {pcap_file}")
    print("=" * 70)
    
    packets = rdpcap(pcap_file)
    uploads = []
    lfi_attempts = []
    webshell_execs = []
    
    for i, pkt in enumerate(packets):
        if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
            continue
        
        payload = bytes(pkt[Raw].load)
        payload_str = payload.decode('latin-1')
        
        # Detectar file uploads
        if b"multipart/form-data" in payload and b"filename=" in payload:
            # Extraer filename
            fn_match = re.search(r'filename="([^"]+)"', payload_str)
            ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', payload_str)
            
            filename = fn_match.group(1) if fn_match else "unknown"
            content_type = ct_match.group(1) if ct_match else "unknown"
            
            # Detectar magic bytes
            magic_bytes = ""
            if b"GIF89a" in payload or b"GIF87a" in payload:
                magic_bytes = "GIF"
            elif b"\x89PNG" in payload:
                magic_bytes = "PNG"
            elif b"\xff\xd8\xff" in payload:
                magic_bytes = "JPEG"
            
            # Detectar código embebido
            has_php = b"<?php" in payload or b"<?" in payload
            has_asp = b"<%@" in payload or b"<%" in payload
            has_jsp = b"<%@page" in payload
            
            suspicious = has_php or has_asp or has_jsp
            polyglot = magic_bytes and suspicious
            
            uploads.append({
                "packet": i + 1,
                "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                "dst": pkt[IP].dst if pkt.haslayer(IP) else "?",
                "filename": filename,
                "content_type": content_type,
                "magic_bytes": magic_bytes,
                "has_code": suspicious,
                "polyglot": polyglot,
                "size": len(payload)
            })
        
        # Detectar LFI/RFI
        if b"GET " in payload or b"POST " in payload:
            lfi_patterns = [b"../", b"..%2f", b"..%2F", b"....//", b"php://", b"file://", b"expect://"]
            for pattern in lfi_patterns:
                if pattern in payload:
                    uri_match = re.search(r'(GET|POST)\s+([^\s]+)', payload_str)
                    uri = uri_match.group(2) if uri_match else "?"
                    lfi_attempts.append({
                        "packet": i + 1,
                        "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                        "uri": uri[:200],
                        "pattern": pattern.decode('latin-1')
                    })
                    break
        
        # Detectar web shell execution
        if b"GET " in payload:
            shell_patterns = [b"?cmd=", b"?exec=", b"?system=", b"?command=", b"?c=", b"?shell="]
            for pattern in shell_patterns:
                if pattern in payload:
                    uri_match = re.search(r'GET\s+([^\s]+)', payload_str)
                    uri = uri_match.group(1) if uri_match else "?"
                    webshell_execs.append({
                        "packet": i + 1,
                        "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                        "uri": uri[:200]
                    })
                    break
    
    # Reportar uploads
    if uploads:
        print(f"\n[!] FILE UPLOADS DETECTADOS: {len(uploads)}\n")
        for u in uploads:
            status = "MALICIOSO" if u["polyglot"] else ("SOSPECHOSO" if u["has_code"] else "NORMAL")
            print(f"  [{status}] Paquete #{u['packet']}")
            print(f"    Origen:       {u['src']}")
            print(f"    Filename:     {u['filename']}")
            print(f"    Content-Type: {u['content_type']}")
            print(f"    Magic bytes:  {u['magic_bytes'] or 'Ninguno'}")
            print(f"    Código embed: {'SÍ' if u['has_code'] else 'No'}")
            print(f"    Polyglot:     {'SÍ - ARCHIVO POLYGLOT!' if u['polyglot'] else 'No'}")
            print()
    
    # Reportar LFI
    if lfi_attempts:
        print(f"\n[!] LFI/RFI ATTEMPTS: {len(lfi_attempts)}\n")
        for l in lfi_attempts:
            print(f"  Paquete #{l['packet']} | {l['src']}")
            print(f"    URI:     {l['uri']}")
            print(f"    Patrón:  {l['pattern']}")
            print()
    
    # Reportar web shell
    if webshell_execs:
        print(f"\n[!] WEB SHELL EXECUTIONS: {len(webshell_execs)}\n")
        for w in webshell_execs:
            print(f"  Paquete #{w['packet']} | {w['src']}")
            print(f"    URI: {w['uri']}")
            print()
    
    if not uploads and not lfi_attempts and not webshell_execs:
        print("\n[+] No se detectaron uploads maliciosos ni LFI/RFI.")


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "/data/lab7_bof_upload.pcap"
    extract_http_uploads(pcap)
