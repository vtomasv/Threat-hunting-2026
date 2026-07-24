#!/bin/bash
# =============================================================================
# Lab 20 - Entrypoint Script
# Inicia VNC + noVNC + Apache comprometido + genera evidencia
# =============================================================================

set -e

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  LAB 20 - Detección de Web Shells en Servidor Comprometido         ║"
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

# ─── Generar el servidor web comprometido ───
echo "[*] Desplegando servidor web comprometido..."
cd /opt/lab20/scripts
python3 generate_compromised_server.py
echo "[+] Servidor comprometido desplegado."
echo ""

# ─── Configurar Apache para servir el webroot comprometido ───
echo "[*] Configurando Apache..."
cat > /etc/apache2/sites-available/000-default.conf << 'APACHECONF'
<VirtualHost *:8080>
    ServerName webserver.corpfinance.local
    DocumentRoot /evidence/server-image/var/www/html
    
    <Directory /evidence/server-image/var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog /evidence/server-image/var/log/apache2/error.log
    CustomLog /evidence/server-image/var/log/apache2/access.log combined
</VirtualHost>
APACHECONF

# Cambiar puerto de Apache a 8080
sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf
service apache2 start 2>/dev/null || true
echo "[+] Apache configurado en puerto 8080"

# ─── Copiar herramientas de análisis ───
echo "[*] Preparando herramientas de detección..."
cp /opt/lab20/scripts/webshell_hunter.py /investigation/tools/
cp /opt/lab20/scripts/log_analyzer.py /investigation/tools/
cp /opt/lab20/scripts/entropy_scanner.py /investigation/tools/
cp /opt/lab20/scripts/yara_scanner.py /investigation/tools/
cp /opt/lab20/scripts/ioc_extractor.py /investigation/tools/
cp /opt/lab20/scripts/hunt_webshells.sh /investigation/tools/
cp /opt/lab20/yara-rules/*.yar /investigation/yara-rules/ 2>/dev/null || true
chmod +x /investigation/tools/*.py /investigation/tools/*.sh

# Crear enlaces en el escritorio
ln -sf /investigation /home/analyst/Desktop/Lab20-WebShells/investigation
ln -sf /evidence/server-image /home/analyst/Desktop/Lab20-WebShells/server-image

# ─── Crear archivo README en el escritorio ───
cat > /home/analyst/Desktop/Lab20-WebShells/INSTRUCCIONES.txt << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                LAB 20 - DETECCIÓN DE WEB SHELLS                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  HIPÓTESIS DE CAZA:                                                        ║
║  El SOC ha recibido alertas sobre tráfico anómalo del servidor web         ║
║  corporativo. Se sospecha que un atacante ha instalado múltiples web       ║
║  shells ocultas para mantener acceso persistente.                          ║
║                                                                            ║
║  TU MISIÓN:                                                                ║
║  1. Identificar las 4 web shells (incluyendo variantes ofuscadas)          ║
║  2. Rastrear la IP del atacante                                            ║
║  3. Determinar el alcance de la intrusión                                  ║
║  4. Escribir reglas YARA para detección                                    ║
║                                                                            ║
║  ESTRUCTURA:                                                               ║
║  /evidence/server-image/    → Imagen del servidor comprometido             ║
║  /investigation/tools/      → Herramientas de detección                    ║
║  /investigation/yara-rules/ → Reglas YARA                                  ║
║  /investigation/findings/   → Guarda aquí tus hallazgos                    ║
║                                                                            ║
║  El servidor Apache está corriendo en http://localhost:8080                 ║
║  (puedes navegar al sitio comprometido desde Firefox)                      ║
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

chown -R analyst:analyst /home/analyst /investigation /evidence

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
echo "[+] Servidor web comprometido: http://localhost:8080"
echo ""
echo "[✓] Laboratorio listo. Esperando conexiones..."

# Buscar la ruta correcta de novnc
NOVNC_PATH="/usr/share/novnc"
if [ ! -d "$NOVNC_PATH" ]; then
    NOVNC_PATH="/usr/share/noVNC"
fi

websockify --web="$NOVNC_PATH" 6080 localhost:5901
