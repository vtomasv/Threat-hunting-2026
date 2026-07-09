#!/bin/bash
# =============================================================================
# MAR404 - Clase 2 - Lab 4: Helper de Hunting HTTP
# =============================================================================

PCAP="/pcap/http_useragent_lab.pcap"

case "$1" in
    useragents|ua)
        echo "=== User-Agents únicos ==="
        tshark -r $PCAP -Y "http.user_agent" -T fields -e http.user_agent 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    requests)
        echo "=== HTTP Requests ==="
        tshark -r $PCAP -Y "http.request" -T fields -e frame.time_relative -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.user_agent 2>/dev/null | head -50
        ;;
    
    hosts)
        echo "=== Hosts destino (por frecuencia) ==="
        tshark -r $PCAP -Y "http.request" -T fields -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    timing)
        echo "=== Análisis temporal (requests por IP destino) ==="
        echo "Formato: tiempo_relativo | src | dst | URI"
        tshark -r $PCAP -Y "http.request" -T fields -e frame.time_relative -e ip.src -e ip.dst -e http.request.uri 2>/dev/null
        ;;
    
    c2check)
        echo "=== Verificación de beaconing (intervalos entre requests al mismo destino) ==="
        echo ""
        echo "Requests a cada IP destino con timestamps:"
        for ip in $(tshark -r $PCAP -Y "http.request" -T fields -e ip.dst 2>/dev/null | sort -u); do
            count=$(tshark -r $PCAP -Y "http.request && ip.dst==$ip" -T fields -e frame.time_relative 2>/dev/null | wc -l)
            echo ""
            echo "--- $ip ($count requests) ---"
            tshark -r $PCAP -Y "http.request && ip.dst==$ip" -T fields -e frame.time_relative -e http.request.uri -e http.user_agent 2>/dev/null | head -10
        done
        ;;
    
    responses)
        echo "=== HTTP Responses (Content-Type y tamaño) ==="
        tshark -r $PCAP -Y "http.response" -T fields -e ip.src -e http.response.code -e http.content_type -e http.content_length 2>/dev/null | head -30
        ;;
    
    payload)
        if [ -z "$2" ]; then
            echo "Uso: hunt_http payload <IP_destino>"
            echo "Ejemplo: hunt_http payload 203.0.113.100"
            exit 1
        fi
        echo "=== Payload HTTP hacia $2 ==="
        tshark -r $PCAP -Y "http && ip.dst==$2" -T fields -e http.file_data 2>/dev/null
        ;;
    
    stats)
        echo "=== Estadísticas del PCAP ==="
        echo ""
        echo "Total paquetes:"
        tshark -r $PCAP 2>/dev/null | wc -l
        echo ""
        echo "HTTP Requests:"
        tshark -r $PCAP -Y "http.request" 2>/dev/null | wc -l
        echo ""
        echo "HTTP Responses:"
        tshark -r $PCAP -Y "http.response" 2>/dev/null | wc -l
        echo ""
        echo "Métodos HTTP:"
        tshark -r $PCAP -Y "http.request" -T fields -e http.request.method 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    *)
        echo "=== MAR404 Lab 4 - HTTP User-Agent Hunt Helper ==="
        echo ""
        echo "Uso: hunt_http [comando]"
        echo ""
        echo "Comandos:"
        echo "  ua|useragents  - Listar User-Agents únicos con frecuencia"
        echo "  requests       - Mostrar HTTP requests"
        echo "  hosts          - IPs destino por frecuencia"
        echo "  timing         - Análisis temporal de requests"
        echo "  c2check        - Verificar patrones de beaconing"
        echo "  responses      - HTTP responses (tipo y tamaño)"
        echo "  payload <IP>   - Extraer payload hacia una IP"
        echo "  stats          - Estadísticas generales"
        echo ""
        echo "Herramienta avanzada:"
        echo "  analyze_ua     - Script Python de análisis de anomalías"
        ;;
esac
