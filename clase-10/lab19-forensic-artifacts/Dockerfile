# =============================================================================
# LAB 19 - Análisis Forense de Artefactos Windows
# Curso MAR404 - Cacería de Amenazas (Threat Hunter)
# Universidad Mayor 2026
# 
# Entorno completo con noVNC + herramientas forenses + simulación de ataque
# Compatible con ARM64 (Apple Silicon) y AMD64 (Intel/Windows)
# =============================================================================
FROM ubuntu:22.04

LABEL maintainer="MAR404 - Threat Hunting Lab"
LABEL description="Lab 19: Windows Forensic Artifacts Analysis with noVNC"
LABEL version="2.1"

# Evitar prompts interactivos durante la instalación
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Santiago

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1: Instalación de paquetes base y escritorio XFCE ligero
# ─────────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    xfce4 \
    xfce4-terminal \
    dbus-x11 \
    x11-xserver-utils \
    tigervnc-standalone-server \
    tigervnc-common \
    tigervnc-tools \
    novnc \
    websockify \
    python3-websockify \
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
    xxd \
    hexedit \
    binutils \
    sleuthkit \
    python3 \
    python3-pip \
    jq \
    sqlite3 \
    p7zip-full \
    unzip \
    fonts-liberation \
    fonts-dejavu-core \
    firefox \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────────────
# FASE 2: Instalación de herramientas Python para análisis forense
# ─────────────────────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    yara-python \
    pefile \
    lief \
    python-registry \
    construct \
    hexdump \
    colorama \
    tabulate \
    rich \
    pandas \
    openpyxl \
    matplotlib

# ─────────────────────────────────────────────────────────────────────────────
# FASE 3: Configuración del usuario analista
# ─────────────────────────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash -G sudo analyst && \
    echo "analyst:hunter2026" | chpasswd && \
    echo "analyst ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# ─────────────────────────────────────────────────────────────────────────────
# FASE 4: Configuración de VNC y noVNC
# La contraseña VNC se configura en el entrypoint para evitar problemas
# con vncpasswd durante el build (no requiere TTY)
# ─────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /home/analyst/.vnc && \
    chown -R analyst:analyst /home/analyst/.vnc

# Configuración de inicio de VNC (xstartup)
RUN printf '#!/bin/bash\nexport DISPLAY=:1\nunset SESSION_MANAGER\nunset DBUS_SESSION_BUS_ADDRESS\nexec startxfce4 &\n' > /home/analyst/.vnc/xstartup && \
    chmod +x /home/analyst/.vnc/xstartup && \
    chown analyst:analyst /home/analyst/.vnc/xstartup

# ─────────────────────────────────────────────────────────────────────────────
# FASE 5: Copiar scripts y herramientas del laboratorio
# ─────────────────────────────────────────────────────────────────────────────
COPY scripts/ /opt/lab19/scripts/
COPY config/ /opt/lab19/config/
COPY evidence-templates/ /opt/lab19/evidence-templates/

RUN chmod +x /opt/lab19/scripts/*.py /opt/lab19/scripts/*.sh 2>/dev/null; true

# ─────────────────────────────────────────────────────────────────────────────
# FASE 6: Crear estructura de directorios de evidencia
# ─────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /cases/SRV-FIN-01/{prefetch,amcache,userassist,mft,timeline,reports} && \
    mkdir -p /tools/{parsers,yara-rules,scripts} && \
    mkdir -p /home/analyst/Desktop/Lab19-ForensicArtifacts && \
    mkdir -p /home/analyst/Documents/references && \
    chown -R analyst:analyst /cases /tools /home/analyst

# ─────────────────────────────────────────────────────────────────────────────
# FASE 7: Script de inicio
# ─────────────────────────────────────────────────────────────────────────────
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 6080 5901

ENTRYPOINT ["/entrypoint.sh"]
