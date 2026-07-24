#!/bin/bash
# =============================================================================
# hunt_helper.sh - Script auxiliar de Threat Hunting
# Lab 19 - Análisis Forense de Artefactos Windows
# =============================================================================

CASE_DIR="/cases/SRV-FIN-01"
TOOLS_DIR="/tools/parsers"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║          THREAT HUNTING HELPER — Lab 19                        ║"
    echo "║          Caso: IR-2026-0715-001 | Host: SRV-FIN-01            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_help() {
    show_banner
    echo -e "${GREEN}Comandos disponibles:${NC}"
    echo ""
    echo "  hunt_helper.sh status      - Estado del caso y evidencia disponible"
    echo "  hunt_helper.sh briefing    - Muestra el briefing del caso"
    echo "  hunt_helper.sh evidence    - Lista toda la evidencia recolectada"
    echo "  hunt_helper.sh quick-wins  - Búsqueda rápida de indicadores obvios"
    echo "  hunt_helper.sh iocs        - Muestra IOCs identificados"
    echo "  hunt_helper.sh report      - Genera reporte del caso"
    echo ""
    echo -e "${YELLOW}Herramientas de análisis:${NC}"
    echo ""
    echo "  python3 $TOOLS_DIR/prefetch_parser.py [--help]"
    echo "  python3 $TOOLS_DIR/amcache_parser.py [--help]"
    echo "  python3 $TOOLS_DIR/userassist_decoder.py [--help]"
    echo "  python3 $TOOLS_DIR/mft_analyzer.py [--help]"
    echo "  python3 $TOOLS_DIR/timestomp_detector.py [--help]"
    echo "  python3 $TOOLS_DIR/timeline_builder.py [--help]"
    echo ""
}

show_status() {
    show_banner
    echo -e "${GREEN}Estado de la evidencia:${NC}"
    echo ""
    
    for dir in prefetch amcache userassist mft timeline iocs context reports; do
        count=$(find "$CASE_DIR/$dir" -type f 2>/dev/null | wc -l)
        if [ "$count" -gt 0 ]; then
            echo -e "  ${GREEN}✓${NC} $dir/: $count archivos"
        else
            echo -e "  ${RED}✗${NC} $dir/: vacío"
        fi
    done
    
    echo ""
    echo -e "${CYAN}Estructura del caso:${NC}"
    tree -L 2 "$CASE_DIR" 2>/dev/null || find "$CASE_DIR" -maxdepth 2 -type f
}

show_briefing() {
    if [ -f "$CASE_DIR/context/CASO_BRIEFING.txt" ]; then
        cat "$CASE_DIR/context/CASO_BRIEFING.txt"
    else
        echo -e "${RED}Briefing no encontrado${NC}"
    fi
}

show_evidence() {
    echo -e "${CYAN}Evidencia disponible para análisis:${NC}"
    echo ""
    echo "PREFETCH:"
    ls -la "$CASE_DIR/prefetch/" 2>/dev/null
    echo ""
    echo "AMCACHE:"
    ls -la "$CASE_DIR/amcache/" 2>/dev/null
    echo ""
    echo "USERASSIST:"
    ls -la "$CASE_DIR/userassist/" 2>/dev/null
    echo ""
    echo "MFT:"
    ls -la "$CASE_DIR/mft/" 2>/dev/null
}

quick_wins() {
    echo -e "${RED}═══ QUICK WINS — Búsqueda Rápida de IOCs ═══${NC}"
    echo ""
    
    echo -e "${YELLOW}[1] Archivos en paths sospechosos (Prefetch):${NC}"
    cat "$CASE_DIR/prefetch/prefetch_parsed.json" 2>/dev/null | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data:
    if 'Public' in e.get('full_path','') or ('TEMP' in e.get('full_path','').upper() and e['category'] != 'legitimate'):
        print(f\"  [!] {e['executable']} → {e['full_path']}\")
"
    
    echo ""
    echo -e "${YELLOW}[2] Binarios sin firma (Amcache):${NC}"
    cat "$CASE_DIR/amcache/amcache_parsed.json" 2>/dev/null | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data:
    if not e['is_signed']:
        print(f\"  [!] {e['name']} → {e['full_path']} (SHA1: {e['sha1'][:20]}...)\")
"
    
    echo ""
    echo -e "${YELLOW}[3] Timestomping detectado (MFT):${NC}"
    cat "$CASE_DIR/mft/mft_parsed.json" 2>/dev/null | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data:
    if e['timestomp_detected']:
        print(f\"  [!] {e['filename']} → SI:{e['si_created'][:10]} vs FN:{e['fn_created'][:10]}\")
"
    
    echo ""
    echo -e "${YELLOW}[4] Ejecuciones en background (UserAssist):${NC}"
    cat "$CASE_DIR/userassist/userassist_parsed.json" 2>/dev/null | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data:
    if e['focus_count'] == 0 and e['category'] == 'malicious':
        print(f\"  [!] {e['program']} → {e['run_count']} ejecuciones SIN foco (background)\")
"
}

show_iocs() {
    if [ -f "$CASE_DIR/iocs/iocs_complete.json" ]; then
        echo -e "${RED}═══ INDICADORES DE COMPROMISO (IOCs) ═══${NC}"
        cat "$CASE_DIR/iocs/iocs_complete.json" | python3 -m json.tool
    fi
}

# Main
case "${1:-help}" in
    status)   show_status ;;
    briefing) show_briefing ;;
    evidence) show_evidence ;;
    quick-wins) quick_wins ;;
    iocs)     show_iocs ;;
    help|*)   show_help ;;
esac
