#!/bin/bash
###############################################################################
# hunt_bof.sh - Helper de Hunting para Lab 7
# Curso MAR404 - Cacería de Amenazas - Clase 4
###############################################################################

PCAP="/data/lab7_bof_upload.pcap"

echo "============================================================"
echo "  LAB 7: Hunting de Buffer Overflow + File Upload"
echo "  Curso MAR404 - Cacería de Amenazas"
echo "============================================================"
echo ""
echo "PCAP: $PCAP"
echo ""

echo "--- [1] Resumen del PCAP ---"
echo ""
tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null | head -30
echo ""

echo "--- [2] Buscar NOP sleds (\\x90 repetidos) ---"
echo ""
tshark -r "$PCAP" -Y "tcp.payload contains 90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90" \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport -e tcp.len 2>/dev/null
echo ""

echo "--- [3] Buscar File Uploads (multipart/form-data) ---"
echo ""
tshark -r "$PCAP" -Y "http.request.method == POST && http.content_type contains multipart" \
  -T fields -e frame.number -e ip.src -e http.request.uri -e http.content_type 2>/dev/null
echo ""

echo "--- [4] Buscar LFI patterns (../) ---"
echo ""
tshark -r "$PCAP" -Y "http.request.uri contains \"../\"" \
  -T fields -e frame.number -e ip.src -e http.request.full_uri 2>/dev/null
echo ""

echo "--- [5] Buscar Web Shell execution (?cmd=) ---"
echo ""
tshark -r "$PCAP" -Y "http.request.uri contains \"cmd=\" || http.request.uri contains \"exec=\"" \
  -T fields -e frame.number -e ip.src -e http.request.full_uri 2>/dev/null
echo ""

echo "--- [6] Buscar Reverse Shell (conexiones al puerto 4444) ---"
echo ""
tshark -r "$PCAP" -Y "tcp.dstport == 4444" \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.flags.str 2>/dev/null
echo ""

echo "--- [7] Conexiones a puertos no estándar ---"
echo ""
tshark -r "$PCAP" -Y "tcp.dstport > 1024 && tcp.dstport != 8080 && tcp.flags.syn == 1" \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null
echo ""

echo "============================================================"
echo "  SCRIPTS ADICIONALES:"
echo "  - detect_nop_sled $PCAP     (análisis detallado de NOP sleds)"
echo "  - extract_payloads $PCAP    (extracción de uploads y LFI)"
echo "============================================================"
