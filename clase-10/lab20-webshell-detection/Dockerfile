# =============================================================================
# LAB 20 - Detección de Web Shells en Servidor Comprometido
# Curso MAR404 - Cacería de Amenazas (Threat Hunter)
# Universidad Mayor 2026
#
# Entorno completo con noVNC + Apache + herramientas de detección
# Compatible con ARM64 (Apple Silicon) y AMD64 (Intel/Windows)
# =============================================================================
FROM ubuntu:22.04

LABEL maintainer="MAR404 - Threat Hunting Lab"
LABEL description="Lab 20: Web Shell Detection with noVNC"
LABEL version="2.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Santiago

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1: Instalación de paquetes base y escritorio XFCE
# ─────────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Escritorio XFCE4 ligero
    xfce4 \
    xfce4-terminal \
    dbus-x11 \
    # VNC Server
    tigervnc-standalone-server \
    tigervnc-common \
    # noVNC
    novnc \
    websockify \
    # Servidor Web Apache + PHP (para simular el servidor comprometido)
    apache2 \
    php \
    libapache2-mod-php \
    # Herramientas de sistema
    sudo \
    curl \
    wget \
    git \
    vim \
    nano \
    less \
    file \
    tree \
    htop \
    net-tools \
    iputils-ping \
    iproute2 \
    # Herramientas de análisis
    jq \
    xxd \
    binutils \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Fuentes
    fonts-liberation \
    fonts-dejavu-core \
    # Navegador
    firefox \
    # ClamAV (antivirus para escaneo)
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────────────
# FASE 2: Herramientas Python para detección de web shells
# ─────────────────────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    yara-python \
    colorama \
    tabulate \
    rich \
    pandas \
    requests \
    netifaces

# ─────────────────────────────────────────────────────────────────────────────
# FASE 3: Configuración del usuario analista
# ─────────────────────────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash -G sudo analyst && \
    echo "analyst:hunter2026" | chpasswd && \
    echo "analyst ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# ─────────────────────────────────────────────────────────────────────────────
# FASE 4: Configuración de VNC y noVNC
# ─────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /home/analyst/.vnc && \
    echo "hunter2026" | vncpasswd -f > /home/analyst/.vnc/passwd && \
    chmod 600 /home/analyst/.vnc/passwd && \
    chown -R analyst:analyst /home/analyst/.vnc

RUN echo '#!/bin/bash\n\
export DISPLAY=:1\n\
unset SESSION_MANAGER\n\
unset DBUS_SESSION_BUS_ADDRESS\n\
exec startxfce4 &' > /home/analyst/.vnc/xstartup && \
    chmod +x /home/analyst/.vnc/xstartup && \
    chown analyst:analyst /home/analyst/.vnc/xstartup

# ─────────────────────────────────────────────────────────────────────────────
# FASE 5: Copiar scripts y herramientas del laboratorio
# ─────────────────────────────────────────────────────────────────────────────
COPY scripts/ /opt/lab20/scripts/
COPY config/ /opt/lab20/config/
COPY webroot-template/ /opt/lab20/webroot-template/
COPY yara-rules/ /opt/lab20/yara-rules/

RUN chmod +x /opt/lab20/scripts/*.py /opt/lab20/scripts/*.sh 2>/dev/null; true

# ─────────────────────────────────────────────────────────────────────────────
# FASE 6: Crear estructura de directorios
# ─────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /investigation/{logs,findings,yara-rules,reports,tools} && \
    mkdir -p /home/analyst/Desktop/Lab20-WebShells && \
    mkdir -p /evidence/server-image && \
    chown -R analyst:analyst /investigation /home/analyst /evidence

# ─────────────────────────────────────────────────────────────────────────────
# FASE 7: Script de inicio
# ─────────────────────────────────────────────────────────────────────────────
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 6080 5901 8080

ENTRYPOINT ["/entrypoint.sh"]
