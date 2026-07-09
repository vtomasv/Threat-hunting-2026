#!/bin/bash
# =============================================================================
# MAR404 - Clase 3 - Lab 6: Helper de Hunting Web Attacks
# =============================================================================

PCAP="/pcap/web_attack_lab.pcap"

case "$1" in
    requests)
        echo "=== HTTP Requests ==="
        tshark -r $PCAP -Y "http.request" -T fields -e frame.number -e ip.src -e http.request.method -e http.request.uri 2>/dev/null
        ;;
    
    sqli)
        echo "=== Posibles SQL Injection (caracteres sospechosos en URI) ==="
        tshark -r $PCAP -Y "http.request.uri contains \"%27\" || http.request.uri contains \"UNION\" || http.request.uri contains \"SELECT\" || http.request.uri contains \"--\"" -T fields -e frame.number -e http.request.uri 2>/dev/null
        ;;
    
    uploads)
        echo "=== File Uploads (POST con multipart) ==="
        tshark -r $PCAP -Y "http.request.method == \"POST\" && http.content_type contains \"multipart\"" -T fields -e frame.number -e ip.src -e http.request.uri 2>/dev/null
        ;;
    
    webshell)
        echo "=== Posible Web Shell (POST a /uploads/) ==="
        tshark -r $PCAP -Y "http.request.method == \"POST\" && http.request.uri contains \"/uploads/\"" -T fields -e frame.number -e ip.src -e http.request.uri 2>/dev/null
        ;;
    
    responses)
        echo "=== HTTP Responses con contenido sospechoso ==="
        tshark -r $PCAP -Y "http.response && (http.file_data contains \"root:\" || http.file_data contains \"www-data\" || http.file_data contains \"uid=\")" -T fields -e frame.number -e http.response.code 2>/dev/null
        ;;
    
    errors)
        echo "=== HTTP Errors (4xx, 5xx) ==="
        tshark -r $PCAP -Y "http.response.code >= 400" -T fields -e frame.number -e http.response.code -e http.response.phrase 2>/dev/null
        ;;
    
    payload)
        if [ -z "$2" ]; then
            echo "Uso: hunt_web payload <frame_number>"
            echo "Ejemplo: hunt_web payload 15"
            exit 1
        fi
        echo "=== Payload del frame $2 ==="
        tshark -r $PCAP -Y "frame.number == $2" -T fields -e http.file_data 2>/dev/null
        tshark -r $PCAP -Y "frame.number == $2" -V 2>/dev/null | grep -A 50 "Hypertext Transfer"
        ;;
    
    timeline)
        echo "=== Timeline del ataque ==="
        tshark -r $PCAP -Y "http.request" -T fields -e frame.time_relative -e ip.src -e http.request.method -e http.request.uri 2>/dev/null
        ;;
    
    stats)
        echo "=== Estadísticas ==="
        echo ""
        echo "Total paquetes:"
        tshark -r $PCAP 2>/dev/null | wc -l
        echo ""
        echo "HTTP Methods:"
        tshark -r $PCAP -Y "http.request" -T fields -e http.request.method 2>/dev/null | sort | uniq -c | sort -rn
        echo ""
        echo "Response codes:"
        tshark -r $PCAP -Y "http.response" -T fields -e http.response.code 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    *)
        echo "=== MAR404 Lab 6 - Web Attack Hunt Helper ==="
        echo ""
        echo "Uso: hunt_web [comando]"
        echo ""
        echo "Comandos:"
        echo "  requests     - Listar HTTP requests"
        echo "  sqli         - Detectar posibles SQL Injection"
        echo "  uploads      - Detectar file uploads"
        echo "  webshell     - Detectar uso de web shell"
        echo "  responses    - Responses con contenido sospechoso"
        echo "  errors       - HTTP errors (4xx, 5xx)"
        echo "  payload <N>  - Ver payload de un frame específico"
        echo "  timeline     - Timeline completa del ataque"
        echo "  stats        - Estadísticas generales"
        echo ""
        echo "Herramienta avanzada:"
        echo "  decode_payloads  - Decodificar payloads URL-encoded"
        ;;
esac
