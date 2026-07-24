#!/bin/bash
# =============================================================================
# Lab 19 - Entrypoint Script
# Inicia VNC Server + noVNC + genera evidencia forense
# =============================================================================

set -e

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  LAB 19 - Análisis Forense de Artefactos Windows                   ║"
echo "║  MAR404 - Cacería de Amenazas (Threat Hunter)                      ║"
echo "║  Universidad Mayor 2026                                            ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ─── Configurar VNC password (en runtime, no en build) ───
echo "[*] Configurando VNC..."
mkdir -p /home/analyst/.vnc
# tigervnc en Ubuntu 22.04 usa 'tigervncpasswd' (no 'vncpasswd')
printf '%s\n%s\nn\n' "hunter2026" "hunter2026" | tigervncpasswd /home/analyst/.vnc/passwd 2>/dev/null || \
    printf '%s\n%s\n\n' "hunter2026" "hunter2026" | vncpasswd /home/analyst/.vnc/passwd 2>/dev/null || true
chmod 600 /home/analyst/.vnc/passwd 2>/dev/null || true
chown -R analyst:analyst /home/analyst/.vnc

# ─── Generar la evidencia forense del caso ───
echo "[*] Generando artefactos forenses del caso SRV-FIN-01..."
cd /opt/lab19/scripts
python3 generate_attack_simulation.py
echo "[+] Evidencia forense generada exitosamente."
echo ""

# ─── Copiar herramientas de análisis al escritorio ───
echo "[*] Preparando herramientas de análisis..."
mkdir -p /tools/{parsers,yara-rules,scripts}
mkdir -p /cases/SRV-FIN-01/{prefetch,amcache,userassist,mft,timeline,reports}
mkdir -p /home/analyst/Desktop/Lab19-ForensicArtifacts
cp /opt/lab19/scripts/artifact_analyzer.py /tools/parsers/
cp /opt/lab19/scripts/prefetch_parser.py /tools/parsers/
cp /opt/lab19/scripts/amcache_parser.py /tools/parsers/
cp /opt/lab19/scripts/mft_analyzer.py /tools/parsers/
cp /opt/lab19/scripts/userassist_decoder.py /tools/parsers/
cp /opt/lab19/scripts/timeline_builder.py /tools/parsers/
cp /opt/lab19/scripts/timestomp_detector.py /tools/parsers/
cp /opt/lab19/scripts/hunt_helper.sh /tools/scripts/
chmod +x /tools/parsers/*.py /tools/scripts/*.sh

# Crear enlace simbólico en el escritorio
ln -sf /cases /home/analyst/Desktop/Lab19-ForensicArtifacts/cases
ln -sf /tools /home/analyst/Desktop/Lab19-ForensicArtifacts/tools

# ─── Crear archivo README en el escritorio ───
cat > /home/analyst/Desktop/Lab19-ForensicArtifacts/INSTRUCCIONES.txt << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                    LAB 19 - ANÁLISIS FORENSE DE ARTEFACTOS                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  HIPÓTESIS DE CAZA:                                                        ║
║  El equipo de SOC ha detectado actividad anómala en el endpoint Windows    ║
║  SRV-FIN-01. Las alertas indican posibles ejecuciones de herramientas de   ║
║  post-explotación y descargas sospechosas.                                 ║
║                                                                            ║
║  TU MISIÓN:                                                                ║
║  Analizar los artefactos forenses (Prefetch, Amcache, UserAssist, MFT)     ║
║  para reconstruir la línea de tiempo del ataque, identificar herramientas  ║
║  del adversario y descubrir técnicas de evasión (timestomping).            ║
║                                                                            ║
║  ESTRUCTURA:                                                               ║
║  /cases/SRV-FIN-01/    → Evidencia recolectada del endpoint                ║
║  /tools/parsers/       → Scripts de análisis forense                       ║
║  /tools/scripts/       → Scripts auxiliares de hunting                      ║
║                                                                            ║
║  INICIO:                                                                   ║
║  Abre una terminal (clic derecho > Terminal) y sigue la guía del profesor. ║
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

chown -R analyst:analyst /home/analyst /cases /tools

# ─── Iniciar VNC Server ───
echo "[*] Iniciando servidor VNC..."
# tigervnc en Ubuntu 22.04 usa 'tigervncserver' (no 'vncserver')
su - analyst -c "tigervncserver :1 -geometry 1280x800 -depth 24 -localhost no" 2>/dev/null || \
    su - analyst -c "tigervncserver :1 -geometry 1280x800 -depth 24" 2>/dev/null || \
    su - analyst -c "vncserver :1 -geometry 1280x800 -depth 24" 2>/dev/null || true

# Esperar a que VNC inicie
sleep 2

# ─── Iniciar noVNC ───
echo "[*] Iniciando noVNC en puerto 6080..."
echo "[+] Accede al laboratorio en: http://localhost:6080/vnc.html"
echo "[+] Password VNC: hunter2026"
echo ""
echo "[✓] Laboratorio listo. Esperando conexiones..."

# websockify conecta noVNC al VNC server
# Buscar la ruta correcta de novnc
NOVNC_PATH="/usr/share/novnc"
if [ ! -d "$NOVNC_PATH" ]; then
    NOVNC_PATH="/usr/share/noVNC"
fi

websockify --web="$NOVNC_PATH" 6080 localhost:5901
