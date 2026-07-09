#!/bin/bash
# =============================================================================
# MAR404 - Clase 3 - Lab 5: Helper de Hunting DNS Tunnel
# =============================================================================

PCAP="/pcap/dns_tunnel_lab.pcap"

case "$1" in
    stats)
        echo "=== Estadísticas DNS ==="
        echo ""
        echo "Total queries:"
        tshark -r $PCAP -Y "dns.flags.response == 0" 2>/dev/null | wc -l
        echo ""
        echo "Tipos de query:"
        tshark -r $PCAP -Y "dns.flags.response == 0" -T fields -e dns.qry.type 2>/dev/null | sort | uniq -c | sort -rn
        ;;
    
    domains)
        echo "=== Dominios consultados (por frecuencia) ==="
        tshark -r $PCAP -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | \
            awk -F'.' '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20
        ;;
    
    long)
        echo "=== Queries con subdominios largos (>50 chars) ==="
        tshark -r $PCAP -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | \
            awk '{if(length($0) > 50) print length($0), $0}' | sort -rn | head -20
        ;;
    
    tunnel)
        if [ -z "$2" ]; then
            echo "Uso: hunt_dns tunnel <dominio_base>"
            echo "Ejemplo: hunt_dns tunnel exfil-tunnel.net"
            exit 1
        fi
        echo "=== Queries al dominio: $2 ==="
        tshark -r $PCAP -Y "dns.qry.name contains \"$2\"" -T fields -e frame.time_relative -e dns.qry.name 2>/dev/null
        ;;
    
    extract)
        if [ -z "$2" ]; then
            echo "Uso: hunt_dns extract <dominio_base>"
            echo "Ejemplo: hunt_dns extract exfil-tunnel.net"
            exit 1
        fi
        echo "=== Extrayendo subdominios de: $2 ==="
        tshark -r $PCAP -Y "dns.qry.name contains \"$2\" && dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | \
            sed "s/\.$2//" | sort -t'.' -k1 -n
        ;;
    
    entropy)
        echo "=== Ejecutando análisis de entropía ==="
        entropy_analyzer
        ;;
    
    responses)
        echo "=== Respuestas DNS (IPs resueltas) ==="
        tshark -r $PCAP -Y "dns.flags.response == 1" -T fields -e dns.qry.name -e dns.a 2>/dev/null | head -30
        ;;
    
    *)
        echo "=== MAR404 Lab 5 - DNS Tunnel Hunt Helper ==="
        echo ""
        echo "Uso: hunt_dns [comando]"
        echo ""
        echo "Comandos:"
        echo "  stats          - Estadísticas generales de DNS"
        echo "  domains        - Dominios por frecuencia"
        echo "  long           - Queries con subdominios largos (>50 chars)"
        echo "  tunnel <dom>   - Filtrar queries a un dominio específico"
        echo "  extract <dom>  - Extraer subdominios de un dominio"
        echo "  entropy        - Análisis de entropía (detecta tunneling)"
        echo "  responses      - Ver respuestas DNS"
        echo ""
        echo "Herramienta avanzada:"
        echo "  entropy_analyzer  - Script Python completo de análisis"
        ;;
esac
