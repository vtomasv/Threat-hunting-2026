#!/bin/bash
###############################################################################
# hunt_processes.sh - Helper de Hunting para Lab 9
# Curso MAR404 - Cacería de Amenazas - Clase 5
###############################################################################

echo "============================================================"
echo "  LAB 9: Hunting de Procesos en Memoria"
echo "  Curso MAR404 - Cacería de Amenazas"
echo "============================================================"
echo ""
echo "Archivos disponibles en /data:"
echo ""
ls -la /data/*.txt /data/*.json 2>/dev/null
echo ""

echo "--- [1] Procesos (simula vol -f mem.raw windows.pslist) ---"
echo ""
cat /data/vol3_pslist.txt
echo ""

echo "--- [2] Árbol de procesos (simula vol -f mem.raw windows.pstree) ---"
echo ""
cat /data/vol3_pstree.txt
echo ""

echo "--- [3] Líneas de comando (simula vol -f mem.raw windows.cmdline) ---"
echo ""
cat /data/vol3_cmdline.txt
echo ""

echo "--- [4] Conexiones de red (simula vol -f mem.raw windows.netscan) ---"
echo ""
cat /data/vol3_netscan.txt
echo ""

echo "============================================================"
echo "  SIGUIENTE PASO: Ejecute find_evil_checker para análisis automático"
echo "  O analice manualmente los archivos JSON en /data/"
echo "============================================================"
