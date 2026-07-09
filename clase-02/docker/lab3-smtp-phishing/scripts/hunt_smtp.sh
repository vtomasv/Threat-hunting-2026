#!/bin/bash
# =============================================================================
# MAR404 - Clase 2 - Lab 3: Helper de Hunting SMTP
# =============================================================================
# Este script proporciona comandos útiles para el análisis del PCAP.
# Uso: hunt_smtp [comando]
# =============================================================================

PCAP="/pcap/smtp_phishing_lab.pcap"

case "$1" in
    sessions)
        echo "=== Sesiones SMTP encontradas ==="
        tshark -r $PCAP -Y "smtp" -T fields -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    from)
        echo "=== MAIL FROM (envelope senders) ==="
        tshark -r $PCAP -Y 'smtp.req.command == "MAIL"' -T fields -e ip.src -e smtp.req.parameter 2>/dev/null
        ;;
    
    to)
        echo "=== RCPT TO (recipients) ==="
        tshark -r $PCAP -Y 'smtp.req.command == "RCPT"' -T fields -e ip.src -e smtp.req.parameter 2>/dev/null
        ;;
    
    headers)
        echo "=== Headers de emails (buscar en DATA) ==="
        tshark -r $PCAP -Y "smtp.data.fragment" -T fields -e tcp.payload 2>/dev/null | head -50
        ;;
    
    dns)
        echo "=== Consultas DNS ==="
        tshark -r $PCAP -Y "dns.qry.name" -T fields -e frame.time_relative -e ip.src -e dns.qry.name -e dns.a 2>/dev/null
        ;;
    
    ips)
        echo "=== IPs origen en sesiones SMTP ==="
        tshark -r $PCAP -Y "tcp.dstport == 25" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    extract)
        echo "=== Extrayendo objetos SMTP del PCAP ==="
        mkdir -p /output/smtp_objects
        tshark -r $PCAP --export-objects "imf,/output/smtp_objects" 2>/dev/null
        echo "Objetos guardados en /output/smtp_objects/"
        ls -la /output/smtp_objects/ 2>/dev/null
        ;;
    
    subjects)
        echo "=== Subjects de emails ==="
        tshark -r $PCAP -Y "imf.subject" -T fields -e imf.subject 2>/dev/null
        ;;
    
    stats)
        echo "=== Estadísticas generales del PCAP ==="
        echo ""
        echo "Total de paquetes:"
        tshark -r $PCAP 2>/dev/null | wc -l
        echo ""
        echo "Protocolos:"
        tshark -r $PCAP -T fields -e frame.protocols 2>/dev/null | sort | uniq -c | sort -rn
        echo ""
        echo "IPs más activas:"
        tshark -r $PCAP -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -10
        ;;
    
    *)
        echo "=== MAR404 Lab 3 - SMTP Phishing Hunt Helper ==="
        echo ""
        echo "Uso: hunt_smtp [comando]"
        echo ""
        echo "Comandos disponibles:"
        echo "  sessions  - Listar sesiones SMTP"
        echo "  from      - Mostrar MAIL FROM (envelope senders)"
        echo "  to        - Mostrar RCPT TO (destinatarios)"
        echo "  headers   - Extraer headers de emails"
        echo "  dns       - Mostrar consultas DNS"
        echo "  ips       - IPs que envían correo"
        echo "  extract   - Extraer objetos SMTP del PCAP"
        echo "  subjects  - Listar subjects de emails"
        echo "  stats     - Estadísticas generales"
        echo ""
        echo "PCAP: $PCAP"
        echo ""
        echo "Tip: Use tshark directamente para queries personalizadas:"
        echo "  tshark -r $PCAP -Y 'filtro' -T fields -e campo"
        ;;
esac
