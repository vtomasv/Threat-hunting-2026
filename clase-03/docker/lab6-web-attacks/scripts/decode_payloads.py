#!/usr/bin/env python3
"""
MAR404 - Clase 3 - Lab 6
Decodifica payloads URL-encoded de ataques web encontrados en el PCAP.
Extrae y presenta los intentos de SQLi y comandos de web shell.
"""
import subprocess
import urllib.parse
import sys

PCAP = "/pcap/web_attack_lab.pcap"


def extract_requests():
    """Extrae HTTP requests del PCAP."""
    cmd = f"tshark -r {PCAP} -Y 'http.request' -T fields -e frame.number -e frame.time_relative -e ip.src -e http.request.method -e http.request.full_uri -e http.file_data"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    requests = []
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 5:
                requests.append({
                    'frame': parts[0],
                    'time': parts[1],
                    'src': parts[2],
                    'method': parts[3],
                    'uri': parts[4],
                    'body': parts[5] if len(parts) > 5 else ''
                })
    return requests


def classify_request(req):
    """Clasifica un request por tipo de ataque."""
    uri_decoded = urllib.parse.unquote(req['uri'])
    body_decoded = urllib.parse.unquote(req['body']) if req['body'] else ''
    
    # SQL Injection indicators
    sqli_patterns = ['UNION', 'SELECT', 'FROM', 'ORDER BY', "' OR ", '--', 'information_schema']
    if any(p.lower() in uri_decoded.lower() for p in sqli_patterns):
        return 'SQLi'
    
    # Web shell indicators
    if '/uploads/' in uri_decoded and req['method'] == 'POST':
        return 'WebShell'
    
    # File upload
    if 'multipart' in req.get('content_type', '') or '/upload' in uri_decoded:
        return 'Upload'
    
    # Login attempt
    if '/login' in uri_decoded and req['method'] == 'POST':
        return 'Login'
    
    return 'Normal'


def analyze():
    """Análisis principal."""
    requests = extract_requests()
    
    if not requests:
        print("[!] No se encontraron requests HTTP")
        return
    
    print(f"\n{'='*70}")
    print(f" ANÁLISIS DE PAYLOADS WEB - Lab 6")
    print(f"{'='*70}")
    print(f"\n[+] Total HTTP requests: {len(requests)}")
    
    # Clasificar
    categories = {}
    for req in requests:
        cat = classify_request(req)
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(req)
    
    print(f"\n[+] Clasificación:")
    for cat, reqs in sorted(categories.items()):
        print(f"    {cat}: {len(reqs)} requests")
    
    # Mostrar SQLi
    if 'SQLi' in categories:
        print(f"\n{'='*70}")
        print(f" SQL INJECTION ATTEMPTS")
        print(f"{'='*70}")
        for req in categories['SQLi']:
            decoded = urllib.parse.unquote(req['uri'])
            print(f"\n  Frame #{req['frame']} [{req['time']}s]")
            print(f"  URI (decoded): {decoded}")
    
    # Mostrar Web Shell
    if 'WebShell' in categories:
        print(f"\n{'='*70}")
        print(f" WEB SHELL COMMANDS")
        print(f"{'='*70}")
        for req in categories['WebShell']:
            body_decoded = urllib.parse.unquote(req['body']) if req['body'] else '(no body captured)'
            print(f"\n  Frame #{req['frame']} [{req['time']}s]")
            print(f"  URI: {req['uri']}")
            print(f"  Command: {body_decoded}")
    
    # Mostrar Upload
    if 'Upload' in categories:
        print(f"\n{'='*70}")
        print(f" FILE UPLOADS")
        print(f"{'='*70}")
        for req in categories['Upload']:
            print(f"\n  Frame #{req['frame']} [{req['time']}s]")
            print(f"  URI: {req['uri']}")
    
    # Reconstruir cadena de ataque
    print(f"\n{'='*70}")
    print(f" CADENA DE ATAQUE RECONSTRUIDA")
    print(f"{'='*70}")
    print(f"\n  1. RECONOCIMIENTO: {len(categories.get('Normal', []))} requests de navegación normal")
    print(f"  2. SQL INJECTION: {len(categories.get('SQLi', []))} intentos de inyección")
    print(f"  3. LOGIN: {len(categories.get('Login', []))} intentos con credenciales robadas")
    print(f"  4. UPLOAD: {len(categories.get('Upload', []))} uploads de archivos")
    print(f"  5. WEB SHELL: {len(categories.get('WebShell', []))} comandos ejecutados")


if __name__ == "__main__":
    analyze()
