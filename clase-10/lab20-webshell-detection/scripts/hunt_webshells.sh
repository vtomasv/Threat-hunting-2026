#!/bin/bash
# =============================================================================
# hunt_webshells.sh - Script auxiliar de Hunting de Web Shells
# Lab 20 - MAR404
# =============================================================================

WEBROOT="/evidence/server-image/var/www/html"
LOGS="/evidence/server-image/var/log/apache2"
FINDINGS="/investigation/findings"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$FINDINGS"

case "${1:-help}" in
    grep-shells)
        echo -e "${RED}═══ Búsqueda de funciones peligrosas en PHP ═══${NC}"
        echo ""
        echo -e "${YELLOW}Buscando eval(), system(), shell_exec(), exec(), passthru():${NC}"
        grep -RnE "(eval|system|shell_exec|passthru|exec)\s*\(" "$WEBROOT" --include="*.php*" 2>/dev/null
        echo ""
        echo -e "${YELLOW}Buscando base64_decode y str_rot13:${NC}"
        grep -RnE "(base64_decode|str_rot13|gzinflate)" "$WEBROOT" --include="*.php*" 2>/dev/null
        echo ""
        echo -e "${YELLOW}Buscando acceso a superglobales (\$_POST, \$_GET, \$_REQUEST):${NC}"
        grep -RnE '(\$_POST|\$_GET|\$_REQUEST|\$_COOKIE)\[' "$WEBROOT" --include="*.php*" 2>/dev/null
        ;;
    
    find-recent)
        echo -e "${CYAN}═══ Archivos PHP modificados en los últimos 7 días ═══${NC}"
        find "$WEBROOT" -name "*.php*" -mtime -7 -ls 2>/dev/null
        ;;
    
    find-hidden)
        echo -e "${CYAN}═══ Archivos ocultos y .htaccess ═══${NC}"
        echo ""
        echo -e "${YELLOW}.htaccess files:${NC}"
        find "$WEBROOT" -name ".htaccess" -exec echo "Found: {}" \; -exec cat {} \;
        echo ""
        echo -e "${YELLOW}Archivos ocultos (dot files):${NC}"
        find "$WEBROOT" -name ".*" -not -name ".htaccess" -ls 2>/dev/null
        echo ""
        echo -e "${YELLOW}Archivos con doble extensión:${NC}"
        find "$WEBROOT" -name "*.php.*" -ls 2>/dev/null
        ;;
    
    log-posts)
        echo -e "${RED}═══ Requests POST en los logs ═══${NC}"
        echo ""
        echo -e "${YELLOW}POST requests a archivos PHP (excluyendo formularios normales):${NC}"
        grep "POST" "$LOGS/access.log" | grep -v "login\|contact\|upload.php" | head -30
        echo ""
        echo -e "${YELLOW}IPs con más POST requests:${NC}"
        grep "POST" "$LOGS/access.log" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
        ;;
    
    log-external)
        echo -e "${RED}═══ Accesos desde IPs externas ═══${NC}"
        grep -v "^10\.\|^192\.168\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[0-1]\." "$LOGS/access.log" | head -40
        ;;
    
    log-errors)
        echo -e "${YELLOW}═══ Error Log de Apache ═══${NC}"
        cat "$LOGS/error.log" 2>/dev/null
        ;;
    
    permissions)
        echo -e "${CYAN}═══ Archivos PHP con permisos de escritura ═══${NC}"
        find "$WEBROOT" -name "*.php*" -perm -o+w -ls 2>/dev/null
        echo ""
        echo -e "${CYAN}═══ Archivos propiedad de www-data en dirs inusuales ═══${NC}"
        find "$WEBROOT" -user www-data -name "*.php*" -ls 2>/dev/null
        ;;
    
    crontab)
        echo -e "${RED}═══ Crontabs del servidor ═══${NC}"
        echo ""
        echo -e "${YELLOW}Crontab de www-data:${NC}"
        cat /evidence/server-image/var/spool/cron/www-data 2>/dev/null
        ;;
    
    summary)
        echo -e "${GREEN}═══ RESUMEN RÁPIDO DE HALLAZGOS ═══${NC}"
        echo ""
        echo -e "Archivos PHP totales: $(find $WEBROOT -name '*.php*' | wc -l)"
        echo -e "Archivos con eval():  $(grep -rl 'eval(' $WEBROOT --include='*.php*' 2>/dev/null | wc -l)"
        echo -e "Archivos con system(): $(grep -rl 'system(' $WEBROOT --include='*.php*' 2>/dev/null | wc -l)"
        echo -e ".htaccess files:      $(find $WEBROOT -name '.htaccess' | wc -l)"
        echo -e "Doble extensión:      $(find $WEBROOT -name '*.php.*' | wc -l)"
        echo -e "IPs externas en logs: $(grep -v '^10\.\|^192\.168\.\|^172\.1' $LOGS/access.log 2>/dev/null | awk '{print $1}' | sort -u | wc -l)"
        echo -e "POST requests total:  $(grep -c 'POST' $LOGS/access.log 2>/dev/null)"
        ;;
    
    help|*)
        echo -e "${CYAN}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║       WEB SHELL HUNTING HELPER — Lab 20                    ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo "Uso: hunt_webshells.sh <comando>"
        echo ""
        echo "  grep-shells   - Busca funciones peligrosas en archivos PHP"
        echo "  find-recent   - Archivos PHP modificados recientemente"
        echo "  find-hidden   - Archivos ocultos, .htaccess, doble extensión"
        echo "  log-posts     - Analiza POST requests en logs"
        echo "  log-external  - Accesos desde IPs externas"
        echo "  log-errors    - Muestra error log de Apache"
        echo "  permissions   - Archivos con permisos anómalos"
        echo "  crontab       - Revisa crontabs del servidor"
        echo "  summary       - Resumen rápido de hallazgos"
        echo ""
        ;;
esac
