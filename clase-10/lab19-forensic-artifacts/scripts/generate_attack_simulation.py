#!/usr/bin/env python3
"""
=============================================================================
generate_attack_simulation.py
=============================================================================
Genera artefactos forenses REALISTAS que simulan un ataque APT completo
contra el servidor SRV-FIN-01 (Windows Server 2019).

Escenario del ataque:
1. Acceso inicial via spearphishing (macro en documento)
2. Descarga de herramientas con certutil y bitsadmin (T1105)
3. Ejecución de beacon Cobalt Strike disfrazado como svchost.exe (T1036.005)
4. Escalación de privilegios con PrintSpoofer (T1068)
5. Credential dumping con Mimikatz (T1003.001)
6. Movimiento lateral con PsExec (T1021.002)
7. Exfiltración de datos (T1041)
8. Timestomping para evasión (T1070.006)
9. Limpieza parcial de logs (T1070.001)

Cada artefacto simula el formato REAL de Windows:
- Prefetch: Formato .pf con metadata de ejecución
- Amcache: Formato de registro con hashes SHA1
- UserAssist: Entradas ROT13 del registro
- MFT: Entradas $STANDARD_INFORMATION y $FILE_NAME con timestamps

Autor: MAR404 - Cacería de Amenazas
Fecha: 2026
=============================================================================
"""

import json
import os
import struct
import hashlib
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

# ─── Configuración del escenario ────────────────────────────────────────────
CASE_DIR = "/cases/SRV-FIN-01"
ATTACK_START = datetime(2026, 7, 15, 9, 23, 45)  # Inicio del ataque

# IP del atacante (APT simulado)
ATTACKER_IP = "185.220.101.34"
C2_DOMAIN = "update-service.cloudfront-cdn.com"
C2_IP = "104.21.45.67"

# Hashes de herramientas maliciosas (simulados pero realistas)
MALWARE_HASHES = {
    "beacon_svchost": {
        "sha1": "a1b2c3d4e5f6789012345678901234567890abcd",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5": "d41d8cd98f00b204e9800998ecf8427e"
    },
    "mimikatz": {
        "sha1": "b2c3d4e5f67890123456789012345678901abcde",
        "sha256": "f4a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234",
        "md5": "e52d98f00b204e9800998ecf8427e123"
    },
    "printspoofer": {
        "sha1": "c3d4e5f6789012345678901234567890abcdef12",
        "sha256": "a5b6c7d8e9f0123456789012345678901234567890abcdef1234567890abcdef",
        "md5": "f63e98f00b204e9800998ecf8427e456"
    },
    "psexec": {
        "sha1": "d4e5f67890123456789012345678901abcdef123",
        "sha256": "b6c7d8e9f01234567890123456789012345678901234567890abcdef12345678",
        "md5": "074e98f00b204e9800998ecf8427e789"
    },
    "procdump": {
        "sha1": "e5f678901234567890123456789012abcdef1234",
        "sha256": "c7d8e9f0123456789012345678901234567890123456789012345678901234ab",
        "md5": "185f98f00b204e9800998ecf8427eabc"
    },
    "rclone_exfil": {
        "sha1": "f6789012345678901234567890123abcdef12345",
        "sha256": "d8e9f012345678901234567890123456789012345678901234567890123456cd",
        "md5": "296098f00b204e9800998ecf8427edef"
    }
}


def create_directories():
    """Crea la estructura de directorios del caso."""
    dirs = [
        f"{CASE_DIR}/prefetch",
        f"{CASE_DIR}/prefetch/raw",
        f"{CASE_DIR}/amcache",
        f"{CASE_DIR}/amcache/raw",
        f"{CASE_DIR}/userassist",
        f"{CASE_DIR}/userassist/raw",
        f"{CASE_DIR}/mft",
        f"{CASE_DIR}/mft/raw",
        f"{CASE_DIR}/timeline",
        f"{CASE_DIR}/reports",
        f"{CASE_DIR}/iocs",
        f"{CASE_DIR}/context",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def generate_case_context():
    """Genera el contexto del caso (briefing para el analista)."""
    context = {
        "case_id": "IR-2026-0715-001",
        "case_name": "Compromiso de SRV-FIN-01 - APT Sospechado",
        "hostname": "SRV-FIN-01",
        "os": "Windows Server 2019 Standard (Build 17763)",
        "ip_address": "10.50.25.101",
        "domain": "CORPFINANCE.local",
        "role": "Servidor de aplicaciones financieras",
        "owner": "Departamento de Finanzas",
        "collection_time": "2026-07-15T18:30:00Z",
        "collector": "IR Team - Analyst J. Martinez",
        "collection_method": "KAPE (Kroll Artifact Parser and Extractor) v1.3",
        "chain_of_custody": "COC-2026-0715-001",
        "initial_alert": {
            "source": "CrowdStrike Falcon",
            "alert_id": "ALT-78923",
            "severity": "Critical",
            "description": "Suspicious process execution: svchost.exe spawned from unusual parent (WINWORD.EXE)",
            "timestamp": "2026-07-15T09:45:12Z",
            "mitre_techniques": ["T1059.001", "T1036.005"]
        },
        "additional_alerts": [
            {
                "source": "Palo Alto Cortex XDR",
                "description": "certutil.exe downloading executable from external IP",
                "timestamp": "2026-07-15T09:28:33Z"
            },
            {
                "source": "Microsoft Defender for Endpoint",
                "description": "Credential access attempt detected - LSASS memory read",
                "timestamp": "2026-07-15T11:15:45Z"
            },
            {
                "source": "Darktrace",
                "description": "Unusual data transfer to external cloud storage",
                "timestamp": "2026-07-15T14:22:18Z"
            }
        ],
        "artifacts_collected": [
            "Prefetch files (C:\\Windows\\Prefetch\\)",
            "Amcache.hve (C:\\Windows\\AppCompat\\Programs\\Amcache.hve)",
            "NTUSER.DAT (UserAssist keys)",
            "MFT ($MFT from C: drive)",
            "Event Logs (Security, System, PowerShell)"
        ],
        "notes": "El servidor fue aislado de la red a las 18:00 UTC. Se realizó imagen forense completa con FTK Imager antes de la recolección selectiva con KAPE."
    }
    
    with open(f"{CASE_DIR}/context/case_briefing.json", "w") as f:
        json.dump(context, f, indent=2)
    
    # Crear versión legible
    with open(f"{CASE_DIR}/context/CASO_BRIEFING.txt", "w") as f:
        f.write("=" * 78 + "\n")
        f.write("  CASO: IR-2026-0715-001 — Compromiso de SRV-FIN-01\n")
        f.write("=" * 78 + "\n\n")
        f.write(f"  Hostname:        {context['hostname']}\n")
        f.write(f"  Sistema:         {context['os']}\n")
        f.write(f"  IP:              {context['ip_address']}\n")
        f.write(f"  Dominio:         {context['domain']}\n")
        f.write(f"  Rol:             {context['role']}\n")
        f.write(f"  Recolección:     {context['collection_time']}\n")
        f.write(f"  Método:          {context['collection_method']}\n\n")
        f.write("  ALERTA INICIAL:\n")
        f.write(f"  {context['initial_alert']['description']}\n")
        f.write(f"  Fuente: {context['initial_alert']['source']}\n")
        f.write(f"  Severidad: {context['initial_alert']['severity']}\n\n")
        f.write("  ALERTAS ADICIONALES:\n")
        for alert in context['additional_alerts']:
            f.write(f"  • [{alert['source']}] {alert['description']}\n")
            f.write(f"    Timestamp: {alert['timestamp']}\n")
        f.write("\n" + "=" * 78 + "\n")


def generate_prefetch_artifacts():
    """
    Genera artefactos Prefetch realistas.
    
    En Windows real, los archivos Prefetch (.pf) contienen:
    - Nombre del ejecutable
    - Hash del path (8 caracteres hex)
    - Número de ejecuciones
    - Timestamps de las últimas 8 ejecuciones
    - Lista de archivos y directorios accedidos
    - Volúmenes utilizados
    
    Aquí simulamos el output parseado (como lo haría PECmd.exe o prefetch-parser).
    """
    
    # Timeline del ataque completo
    t = ATTACK_START
    
    prefetch_entries = [
        # ─── Actividad legítima (baseline) ───
        {
            "filename": "SVCHOST.EXE-3530F672.pf",
            "executable": "SVCHOST.EXE",
            "hash": "3530F672",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\SVCHOST.EXE",
            "run_count": 1847,
            "last_run_times": [
                (t + timedelta(hours=8)).isoformat(),
                (t + timedelta(hours=7)).isoformat(),
                (t + timedelta(hours=6)).isoformat(),
            ],
            "size": 51688,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(hours=8)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\EN-US\\"
            ],
            "category": "legitimate",
            "notes": "Proceso legítimo de Windows - alta frecuencia de ejecución normal"
        },
        {
            "filename": "EXPLORER.EXE-7A3328DA.pf",
            "executable": "EXPLORER.EXE",
            "hash": "7A3328DA",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\EXPLORER.EXE",
            "run_count": 523,
            "last_run_times": [
                (t + timedelta(hours=8)).isoformat(),
            ],
            "size": 4826624,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(hours=8)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\ADMIN.CORPFINANCE\\"
            ],
            "category": "legitimate",
            "notes": "Shell de Windows - actividad normal"
        },
        # ─── Fase 1: Acceso inicial - Documento malicioso ───
        {
            "filename": "WINWORD.EXE-A2B3C4D5.pf",
            "executable": "WINWORD.EXE",
            "hash": "A2B3C4D5",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\PROGRAM FILES\\MICROSOFT OFFICE\\ROOT\\OFFICE16\\WINWORD.EXE",
            "run_count": 45,
            "last_run_times": [
                (t + timedelta(minutes=0)).isoformat(),
            ],
            "size": 2461696,
            "created": (t - timedelta(days=90)).isoformat(),
            "modified": (t + timedelta(minutes=0)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\PROGRAM FILES\\MICROSOFT OFFICE\\ROOT\\OFFICE16\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\ADMIN.CORPFINANCE\\DOCUMENTS\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\ADMIN.CORPFINANCE\\APPDATA\\LOCAL\\TEMP\\"
            ],
            "category": "suspicious",
            "notes": "Word abierto justo antes del inicio del ataque - posible documento con macro maliciosa"
        },
        # ─── Fase 2: Descarga de herramientas (T1105) ───
        {
            "filename": "CERTUTIL.EXE-3F8B1A2C.pf",
            "executable": "CERTUTIL.EXE",
            "hash": "3F8B1A2C",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\CERTUTIL.EXE",
            "run_count": 4,
            "last_run_times": [
                (t + timedelta(minutes=5)).isoformat(),
                (t + timedelta(minutes=7)).isoformat(),
                (t + timedelta(minutes=9)).isoformat(),
                (t + timedelta(minutes=12)).isoformat(),
            ],
            "size": 1654784,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(minutes=12)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\PUBLIC\\DOWNLOADS\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\"
            ],
            "category": "malicious",
            "notes": "CERTUTIL ejecutado 4 veces en 7 minutos - LOLBIN usado para descarga (T1105). Accede a Public\\Downloads y Windows\\Temp - descarga de herramientas del atacante"
        },
        {
            "filename": "BITSADMIN.EXE-4C7D2E9F.pf",
            "executable": "BITSADMIN.EXE",
            "hash": "4C7D2E9F",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\BITSADMIN.EXE",
            "run_count": 2,
            "last_run_times": [
                (t + timedelta(minutes=14)).isoformat(),
                (t + timedelta(minutes=16)).isoformat(),
            ],
            "size": 315392,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(minutes=16)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\PROGRAMDATA\\MICROSOFT\\NETWORK\\"
            ],
            "category": "malicious",
            "notes": "BITSADMIN como método alternativo de descarga (T1197) - transferencia en background"
        },
        # ─── Fase 3: Ejecución del beacon (T1036.005) ───
        {
            "filename": "SVCHOST.EXE-1A2B3C4D.pf",
            "executable": "SVCHOST.EXE",
            "hash": "1A2B3C4D",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\PUBLIC\\DOWNLOADS\\SVCHOST.EXE",
            "run_count": 3,
            "last_run_times": [
                (t + timedelta(minutes=20)).isoformat(),
                (t + timedelta(hours=2)).isoformat(),
                (t + timedelta(hours=5)).isoformat(),
            ],
            "size": 45056,
            "created": (t + timedelta(minutes=18)).isoformat(),
            "modified": (t + timedelta(hours=5)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\PUBLIC\\DOWNLOADS\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\"
            ],
            "category": "malicious",
            "notes": "¡ALERTA! svchost.exe ejecutado desde \\Users\\Public\\Downloads\\ - NO es la ruta legítima (C:\\Windows\\System32\\). Hash diferente al legítimo. Beacon Cobalt Strike disfrazado (T1036.005 - Masquerading)"
        },
        # ─── Fase 4: Escalación de privilegios (T1068) ───
        {
            "filename": "PRINTSPOOFER64.EXE-5E6F7A8B.pf",
            "executable": "PRINTSPOOFER64.EXE",
            "hash": "5E6F7A8B",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\PRINTSPOOFER64.EXE",
            "run_count": 1,
            "last_run_times": [
                (t + timedelta(minutes=35)).isoformat(),
            ],
            "size": 27648,
            "created": (t + timedelta(minutes=33)).isoformat(),
            "modified": (t + timedelta(minutes=35)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\SPOOLSV.EXE"
            ],
            "category": "malicious",
            "notes": "PrintSpoofer - herramienta de escalación de privilegios que explota impersonation de tokens (T1068). Ejecutado una sola vez = explotación exitosa"
        },
        # ─── Fase 5: Credential Dumping (T1003.001) ───
        {
            "filename": "MIMIKATZ.EXE-6F7A8B9C.pf",
            "executable": "MIMIKATZ.EXE",
            "hash": "6F7A8B9C",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\MIMIKATZ.EXE",
            "run_count": 2,
            "last_run_times": [
                (t + timedelta(hours=1, minutes=45)).isoformat(),
                (t + timedelta(hours=2, minutes=10)).isoformat(),
            ],
            "size": 1250816,
            "created": (t + timedelta(hours=1, minutes=40)).isoformat(),
            "modified": (t + timedelta(hours=2, minutes=10)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\LSASS.EXE"
            ],
            "category": "malicious",
            "notes": "Mimikatz - herramienta de volcado de credenciales (T1003.001). Accede a LSASS.EXE para extraer hashes NTLM y tickets Kerberos"
        },
        {
            "filename": "PROCDUMP64.EXE-7A8B9C0D.pf",
            "executable": "PROCDUMP64.EXE",
            "hash": "7A8B9C0D",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\PROCDUMP64.EXE",
            "run_count": 1,
            "last_run_times": [
                (t + timedelta(hours=2, minutes=5)).isoformat(),
            ],
            "size": 714752,
            "created": (t + timedelta(hours=2)).isoformat(),
            "modified": (t + timedelta(hours=2, minutes=5)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\LSASS.DMP"
            ],
            "category": "malicious",
            "notes": "ProcDump usado para volcar LSASS a disco (T1003.001) - técnica alternativa a Mimikatz directo. Output: lsass.dmp"
        },
        # ─── Fase 6: Movimiento lateral (T1021.002) ───
        {
            "filename": "PSEXEC.EXE-8B9C0D1E.pf",
            "executable": "PSEXEC.EXE",
            "hash": "8B9C0D1E",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\PSEXEC.EXE",
            "run_count": 3,
            "last_run_times": [
                (t + timedelta(hours=3)).isoformat(),
                (t + timedelta(hours=3, minutes=15)).isoformat(),
                (t + timedelta(hours=3, minutes=30)).isoformat(),
            ],
            "size": 833024,
            "created": (t + timedelta(hours=2, minutes=55)).isoformat(),
            "modified": (t + timedelta(hours=3, minutes=30)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\"
            ],
            "category": "malicious",
            "notes": "PsExec - movimiento lateral a otros hosts (T1021.002). 3 ejecuciones = 3 hosts comprometidos"
        },
        # ─── Fase 7: Reconocimiento interno ───
        {
            "filename": "NLTEST.EXE-9C0D1E2F.pf",
            "executable": "NLTEST.EXE",
            "hash": "9C0D1E2F",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\NLTEST.EXE",
            "run_count": 2,
            "last_run_times": [
                (t + timedelta(minutes=40)).isoformat(),
                (t + timedelta(minutes=42)).isoformat(),
            ],
            "size": 73216,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(minutes=42)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\"
            ],
            "category": "suspicious",
            "notes": "nltest.exe - enumeración de domain trusts (T1482). Usado para reconocimiento del dominio"
        },
        {
            "filename": "NET.EXE-0D1E2F3A.pf",
            "executable": "NET.EXE",
            "hash": "0D1E2F3A",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\NET.EXE",
            "run_count": 8,
            "last_run_times": [
                (t + timedelta(minutes=38)).isoformat(),
                (t + timedelta(minutes=39)).isoformat(),
                (t + timedelta(minutes=41)).isoformat(),
            ],
            "size": 49664,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(minutes=41)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\"
            ],
            "category": "suspicious",
            "notes": "net.exe - enumeración de usuarios, grupos y shares (T1087, T1135). Múltiples ejecuciones rápidas = reconocimiento automatizado"
        },
        # ─── Fase 8: Exfiltración (T1041) ───
        {
            "filename": "RCLONE.EXE-1E2F3A4B.pf",
            "executable": "RCLONE.EXE",
            "hash": "1E2F3A4B",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\RCLONE.EXE",
            "run_count": 1,
            "last_run_times": [
                (t + timedelta(hours=5)).isoformat(),
            ],
            "size": 55000000,
            "created": (t + timedelta(hours=4, minutes=50)).isoformat(),
            "modified": (t + timedelta(hours=5)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\ADMIN.CORPFINANCE\\DOCUMENTS\\FINANCIAL\\"
            ],
            "category": "malicious",
            "notes": "rclone - herramienta de sincronización cloud usada para exfiltración (T1567.002). Accede a documentos financieros"
        },
        # ─── Fase 9: Evasión - PowerShell (T1059.001) ───
        {
            "filename": "POWERSHELL.EXE-2F3A4B5C.pf",
            "executable": "POWERSHELL.EXE",
            "hash": "2F3A4B5C",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
            "run_count": 12,
            "last_run_times": [
                (t + timedelta(minutes=3)).isoformat(),
                (t + timedelta(minutes=15)).isoformat(),
                (t + timedelta(hours=1)).isoformat(),
                (t + timedelta(hours=5, minutes=30)).isoformat(),
            ],
            "size": 452608,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(hours=5, minutes=30)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\TEMP\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\USERS\\PUBLIC\\DOWNLOADS\\"
            ],
            "category": "suspicious",
            "notes": "PowerShell con alta frecuencia de ejecución durante el ataque - usado para staging, descarga y ejecución de payloads (T1059.001)"
        },
        # ─── Fase 10: Limpieza parcial (T1070.001) ───
        {
            "filename": "WEVTUTIL.EXE-3A4B5C6D.pf",
            "executable": "WEVTUTIL.EXE",
            "hash": "3A4B5C6D",
            "full_path": "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\WEVTUTIL.EXE",
            "run_count": 3,
            "last_run_times": [
                (t + timedelta(hours=5, minutes=35)).isoformat(),
                (t + timedelta(hours=5, minutes=36)).isoformat(),
                (t + timedelta(hours=5, minutes=37)).isoformat(),
            ],
            "size": 159232,
            "created": (t - timedelta(days=180)).isoformat(),
            "modified": (t + timedelta(hours=5, minutes=37)).isoformat(),
            "volume_path": "\\VOLUME{01d8a7b2c3d4e5f6}",
            "volume_serial": "A4F2-8B1C",
            "directories_accessed": [
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\",
                "\\VOLUME{01d8a7b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\WINEVT\\LOGS\\"
            ],
            "category": "malicious",
            "notes": "wevtutil.exe - limpieza de Event Logs (T1070.001). 3 ejecuciones = limpieza de Security, System y PowerShell logs"
        },
    ]
    
    # Guardar en formato JSON parseado
    with open(f"{CASE_DIR}/prefetch/prefetch_parsed.json", "w") as f:
        json.dump(prefetch_entries, f, indent=2)
    
    # Generar archivos .pf simulados (binarios con headers realistas)
    for entry in prefetch_entries:
        pf_path = f"{CASE_DIR}/prefetch/raw/{entry['filename']}"
        generate_fake_pf_file(pf_path, entry)
    
    # Generar resumen CSV para análisis rápido
    with open(f"{CASE_DIR}/prefetch/prefetch_summary.csv", "w") as f:
        f.write("Filename,Executable,Path,RunCount,LastRun,Category,Notes\n")
        for entry in prefetch_entries:
            last_run = entry['last_run_times'][0] if entry['last_run_times'] else "N/A"
            notes = entry.get('notes', '').replace(',', ';')
            f.write(f"{entry['filename']},{entry['executable']},{entry['full_path']},{entry['run_count']},{last_run},{entry['category']},{notes}\n")
    
    return prefetch_entries


def generate_fake_pf_file(path, entry):
    """Genera un archivo .pf con header binario realista de Windows 10/2019."""
    # Windows 10 Prefetch header (MAM format, version 30)
    header = struct.pack('<4s', b'MAM\x00')  # Signature
    header += struct.pack('<I', 30)  # Version (Win10)
    header += struct.pack('<I', random.randint(50000, 200000))  # File size
    # Nombre del ejecutable en Unicode (60 bytes)
    exe_name = entry['executable'].encode('utf-16-le')[:58].ljust(58, b'\x00')
    header += exe_name
    header += struct.pack('<I', int(entry['hash'], 16))  # Path hash
    header += struct.pack('<I', entry['run_count'])  # Run count
    # Padding con datos aleatorios para simular el resto del archivo
    padding = os.urandom(random.randint(1000, 5000))
    
    with open(path, 'wb') as f:
        f.write(header + padding)


def generate_amcache_artifacts():
    """
    Genera artefactos Amcache realistas.
    
    Amcache.hve es un registry hive que registra información sobre aplicaciones
    ejecutadas, incluyendo:
    - Path completo del ejecutable
    - SHA1 hash del archivo
    - Tamaño del archivo
    - Publisher (si está firmado)
    - Versión del producto
    - Timestamp de primera ejecución
    - Información del compilador (link date)
    """
    
    t = ATTACK_START
    
    amcache_entries = [
        # ─── Binarios legítimos (baseline) ───
        {
            "key_path": "Root\\InventoryApplicationFile\\svchost.exe|c:\\windows\\system32",
            "file_id": "0000a1b2c3d4e5f6",
            "name": "svchost.exe",
            "full_path": "C:\\Windows\\System32\\svchost.exe",
            "sha1": "7fd065bac18c5278777ae44908101cdfed72d26e",
            "size": 51688,
            "publisher": "Microsoft Windows",
            "version": "10.0.17763.1",
            "product_name": "Microsoft Windows Operating System",
            "language": "English (United States)",
            "link_date": "2019-03-19T07:00:00Z",
            "first_run": (t - timedelta(days=180)).isoformat(),
            "pe_header_checksum": "0x0000D4A8",
            "binary_type": "PE64_AMD64",
            "is_signed": True,
            "signer": "Microsoft Windows",
            "category": "legitimate",
            "notes": "svchost.exe legítimo firmado por Microsoft"
        },
        # ─── Beacon disfrazado como svchost.exe ───
        {
            "key_path": "Root\\InventoryApplicationFile\\svchost.exe|c:\\users\\public\\downloads",
            "file_id": "0000f1e2d3c4b5a6",
            "name": "svchost.exe",
            "full_path": "C:\\Users\\Public\\Downloads\\svchost.exe",
            "sha1": MALWARE_HASHES["beacon_svchost"]["sha1"],
            "size": 45056,
            "publisher": "",
            "version": "",
            "product_name": "",
            "language": "",
            "link_date": "2026-07-10T14:22:33Z",
            "first_run": (t + timedelta(minutes=20)).isoformat(),
            "pe_header_checksum": "0x00000000",
            "binary_type": "PE64_AMD64",
            "is_signed": False,
            "signer": "",
            "category": "malicious",
            "notes": "¡FALSO svchost.exe! Sin firma digital, sin publisher, sin versión. Path anómalo (Users\\Public\\Downloads). Link date reciente (10 Jul 2026) = compilado días antes del ataque. Checksum 0x0 = no calculado (típico de herramientas custom)"
        },
        # ─── Mimikatz ───
        {
            "key_path": "Root\\InventoryApplicationFile\\mimikatz.exe|c:\\windows\\temp",
            "file_id": "0000a2b3c4d5e6f7",
            "name": "mimikatz.exe",
            "full_path": "C:\\Windows\\Temp\\mimikatz.exe",
            "sha1": MALWARE_HASHES["mimikatz"]["sha1"],
            "size": 1250816,
            "publisher": "",
            "version": "2.2.0",
            "product_name": "mimikatz",
            "language": "French (France)",
            "link_date": "2026-06-15T08:00:00Z",
            "first_run": (t + timedelta(hours=1, minutes=45)).isoformat(),
            "pe_header_checksum": "0x00134A2C",
            "binary_type": "PE64_AMD64",
            "is_signed": False,
            "signer": "",
            "category": "malicious",
            "notes": "Mimikatz v2.2.0 - herramienta de credential dumping. Language: French (autor Benjamin Delpy es francés). Sin firma digital. Ubicación en Windows\\Temp = dropped por atacante"
        },
        # ─── PrintSpoofer ───
        {
            "key_path": "Root\\InventoryApplicationFile\\printspoofer64.exe|c:\\windows\\temp",
            "file_id": "0000b3c4d5e6f7a8",
            "name": "PrintSpoofer64.exe",
            "full_path": "C:\\Windows\\Temp\\PrintSpoofer64.exe",
            "sha1": MALWARE_HASHES["printspoofer"]["sha1"],
            "size": 27648,
            "publisher": "",
            "version": "",
            "product_name": "",
            "language": "",
            "link_date": "2026-05-20T12:00:00Z",
            "first_run": (t + timedelta(minutes=35)).isoformat(),
            "pe_header_checksum": "0x00000000",
            "binary_type": "PE64_AMD64",
            "is_signed": False,
            "signer": "",
            "category": "malicious",
            "notes": "PrintSpoofer - exploit de escalación de privilegios via Print Spooler. Tamaño pequeño (27KB) típico de exploits compilados"
        },
        # ─── PsExec ───
        {
            "key_path": "Root\\InventoryApplicationFile\\psexec.exe|c:\\windows\\temp",
            "file_id": "0000c4d5e6f7a8b9",
            "name": "PsExec.exe",
            "full_path": "C:\\Windows\\Temp\\PsExec.exe",
            "sha1": MALWARE_HASHES["psexec"]["sha1"],
            "size": 833024,
            "publisher": "Sysinternals - www.sysinternals.com",
            "version": "2.43",
            "product_name": "Sysinternals PsExec",
            "language": "English (United States)",
            "link_date": "2024-01-15T10:00:00Z",
            "first_run": (t + timedelta(hours=3)).isoformat(),
            "pe_header_checksum": "0x000CB8F4",
            "binary_type": "PE64_AMD64",
            "is_signed": True,
            "signer": "Microsoft Corporation",
            "category": "suspicious",
            "notes": "PsExec legítimo de Sysinternals (firmado por Microsoft) pero ubicado en Windows\\Temp = traído por atacante para movimiento lateral. Herramienta dual-use"
        },
        # ─── ProcDump ───
        {
            "key_path": "Root\\InventoryApplicationFile\\procdump64.exe|c:\\windows\\temp",
            "file_id": "0000d5e6f7a8b9c0",
            "name": "procdump64.exe",
            "full_path": "C:\\Windows\\Temp\\procdump64.exe",
            "sha1": MALWARE_HASHES["procdump"]["sha1"],
            "size": 714752,
            "publisher": "Sysinternals - www.sysinternals.com",
            "version": "11.0",
            "product_name": "Sysinternals ProcDump",
            "language": "English (United States)",
            "link_date": "2023-11-01T10:00:00Z",
            "first_run": (t + timedelta(hours=2)).isoformat(),
            "pe_header_checksum": "0x000AE2B0",
            "binary_type": "PE64_AMD64",
            "is_signed": True,
            "signer": "Microsoft Corporation",
            "category": "suspicious",
            "notes": "ProcDump legítimo pero usado para volcar LSASS (T1003.001). Ubicación en Temp indica uso por atacante"
        },
        # ─── Rclone (exfiltración) ───
        {
            "key_path": "Root\\InventoryApplicationFile\\rclone.exe|c:\\windows\\temp",
            "file_id": "0000e6f7a8b9c0d1",
            "name": "rclone.exe",
            "full_path": "C:\\Windows\\Temp\\rclone.exe",
            "sha1": MALWARE_HASHES["rclone_exfil"]["sha1"],
            "size": 55000000,
            "publisher": "https://rclone.org",
            "version": "1.67.0",
            "product_name": "Rclone",
            "language": "",
            "link_date": "2026-06-01T10:00:00Z",
            "first_run": (t + timedelta(hours=5)).isoformat(),
            "pe_header_checksum": "0x034A5B6C",
            "binary_type": "PE64_AMD64",
            "is_signed": False,
            "signer": "",
            "category": "malicious",
            "notes": "Rclone - herramienta de sincronización cloud. Usada por ransomware y APTs para exfiltración masiva de datos (T1567.002). Tamaño grande (55MB) = binario Go completo"
        },
        # ─── Herramienta de timestomping ───
        {
            "key_path": "Root\\InventoryApplicationFile\\timestomp.exe|c:\\windows\\temp",
            "file_id": "0000f7a8b9c0d1e2",
            "name": "timestomp.exe",
            "full_path": "C:\\Windows\\Temp\\timestomp.exe",
            "sha1": "a8b9c0d1e2f3456789012345678901234567890a",
            "size": 15360,
            "publisher": "",
            "version": "",
            "product_name": "",
            "language": "",
            "link_date": "2026-07-12T09:00:00Z",
            "first_run": (t + timedelta(hours=5, minutes=30)).isoformat(),
            "pe_header_checksum": "0x00000000",
            "binary_type": "PE64_AMD64",
            "is_signed": False,
            "signer": "",
            "category": "malicious",
            "notes": "Herramienta de timestomping (T1070.006) - modifica $STANDARD_INFORMATION timestamps para evadir análisis forense. Muy pequeño (15KB) = herramienta custom del atacante"
        },
    ]
    
    # Guardar en formato JSON
    with open(f"{CASE_DIR}/amcache/amcache_parsed.json", "w") as f:
        json.dump(amcache_entries, f, indent=2)
    
    # Generar archivo de hashes para búsqueda en VT/MISP
    with open(f"{CASE_DIR}/iocs/file_hashes.txt", "w") as f:
        f.write("# IOCs extraídos de Amcache - Caso IR-2026-0715-001\n")
        f.write("# Formato: SHA1 | Filename | Path | Category\n")
        f.write("#" + "=" * 76 + "\n")
        for entry in amcache_entries:
            if entry['category'] in ('malicious', 'suspicious'):
                f.write(f"{entry['sha1']} | {entry['name']} | {entry['full_path']} | {entry['category']}\n")
    
    # Generar resumen CSV
    with open(f"{CASE_DIR}/amcache/amcache_summary.csv", "w") as f:
        f.write("Name,Path,SHA1,Size,Publisher,Signed,FirstRun,Category\n")
        for entry in amcache_entries:
            f.write(f"{entry['name']},{entry['full_path']},{entry['sha1']},{entry['size']},{entry.get('publisher','')},{entry['is_signed']},{entry['first_run']},{entry['category']}\n")
    
    return amcache_entries


def generate_userassist_artifacts():
    """
    Genera artefactos UserAssist realistas.
    
    UserAssist es una clave del registro de Windows que rastrea programas
    ejecutados por el usuario a través del shell (Explorer). Los datos están
    codificados en ROT13 y contienen:
    - Nombre del programa (codificado en ROT13)
    - Número de ejecuciones
    - Tiempo de foco (focus time en milisegundos)
    - Última ejecución (timestamp FILETIME)
    """
    
    t = ATTACK_START
    
    # Función helper para ROT13
    def rot13(text):
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    userassist_entries = [
        # ─── Entradas legítimas ───
        {
            "value_name_encoded": rot13("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Microsoft\\Office\\root\\Office16\\WINWORD.EXE"),
            "value_name_decoded": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Microsoft\\Office\\root\\Office16\\WINWORD.EXE",
            "program": "WINWORD.EXE",
            "run_count": 45,
            "focus_count": 42,
            "focus_time_ms": 14400000,
            "focus_time_human": "4 hours",
            "last_execution": (t + timedelta(minutes=0)).isoformat(),
            "category": "legitimate",
            "notes": "Microsoft Word - uso normal del usuario. Última ejecución coincide con inicio del ataque (apertura de documento malicioso)"
        },
        {
            "value_name_encoded": rot13("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Microsoft\\Office\\root\\Office16\\EXCEL.EXE"),
            "value_name_decoded": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Microsoft\\Office\\root\\Office16\\EXCEL.EXE",
            "program": "EXCEL.EXE",
            "run_count": 128,
            "focus_count": 125,
            "focus_time_ms": 86400000,
            "focus_time_human": "24 hours",
            "last_execution": (t - timedelta(hours=2)).isoformat(),
            "category": "legitimate",
            "notes": "Microsoft Excel - uso intensivo (servidor financiero)"
        },
        # ─── Entradas sospechosas/maliciosas ───
        {
            "value_name_encoded": rot13("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Windows\\System32\\cmd.exe"),
            "value_name_decoded": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Windows\\System32\\cmd.exe",
            "program": "cmd.exe",
            "run_count": 23,
            "focus_count": 18,
            "focus_time_ms": 7200000,
            "focus_time_human": "2 hours",
            "last_execution": (t + timedelta(hours=5, minutes=35)).isoformat(),
            "category": "suspicious",
            "notes": "CMD con uso elevado durante el período del ataque - 23 ejecuciones es inusual para un servidor"
        },
        {
            "value_name_encoded": rot13("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            "value_name_decoded": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "program": "powershell.exe",
            "run_count": 15,
            "focus_count": 12,
            "focus_time_ms": 5400000,
            "focus_time_human": "1.5 hours",
            "last_execution": (t + timedelta(hours=5, minutes=30)).isoformat(),
            "category": "suspicious",
            "notes": "PowerShell con alto uso - posible ejecución de scripts maliciosos"
        },
        {
            "value_name_encoded": rot13("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Users\\Public\\Downloads\\svchost.exe"),
            "value_name_decoded": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Users\\Public\\Downloads\\svchost.exe",
            "program": "svchost.exe (FALSO)",
            "run_count": 3,
            "focus_count": 0,
            "focus_time_ms": 0,
            "focus_time_human": "0 seconds",
            "last_execution": (t + timedelta(hours=5)).isoformat(),
            "category": "malicious",
            "notes": "¡CRÍTICO! svchost.exe desde Users\\Public\\Downloads - NO es el legítimo. Focus time = 0 indica ejecución en background (beacon C2). 3 ejecuciones = reinicio del beacon"
        },
        {
            "value_name_encoded": rot13("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Windows\\Temp\\mimikatz.exe"),
            "value_name_decoded": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Windows\\Temp\\mimikatz.exe",
            "program": "mimikatz.exe",
            "run_count": 2,
            "focus_count": 2,
            "focus_time_ms": 120000,
            "focus_time_human": "2 minutes",
            "last_execution": (t + timedelta(hours=2, minutes=10)).isoformat(),
            "category": "malicious",
            "notes": "Mimikatz ejecutado interactivamente (focus_count > 0). 2 minutos de uso = ejecución de comandos sekurlsa::logonpasswords y lsadump::sam"
        },
        {
            "value_name_encoded": rot13("{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Windows\\Temp\\rclone.exe"),
            "value_name_decoded": "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Windows\\Temp\\rclone.exe",
            "program": "rclone.exe",
            "run_count": 1,
            "focus_count": 0,
            "focus_time_ms": 0,
            "focus_time_human": "0 seconds",
            "last_execution": (t + timedelta(hours=5)).isoformat(),
            "category": "malicious",
            "notes": "Rclone ejecutado sin foco (background) = exfiltración automatizada. GUID diferente indica ejecución desde contexto diferente (posiblemente SYSTEM)"
        },
    ]
    
    # Guardar JSON
    with open(f"{CASE_DIR}/userassist/userassist_parsed.json", "w") as f:
        json.dump(userassist_entries, f, indent=2)
    
    # Guardar versión RAW (codificada en ROT13) para que el estudiante la decodifique
    raw_entries = []
    for entry in userassist_entries:
        raw_entry = {
            "value_name": entry["value_name_encoded"],
            "run_count": entry["run_count"],
            "focus_count": entry["focus_count"],
            "focus_time_ms": entry["focus_time_ms"],
            "last_execution_filetime": int((datetime.fromisoformat(entry["last_execution"]) - datetime(1601, 1, 1)).total_seconds() * 10000000)
        }
        raw_entries.append(raw_entry)
    
    with open(f"{CASE_DIR}/userassist/raw/userassist_raw.json", "w") as f:
        json.dump(raw_entries, f, indent=2)
    
    return userassist_entries


def generate_mft_artifacts():
    """
    Genera artefactos MFT realistas con evidencia de TIMESTOMPING.
    
    La MFT (Master File Table) contiene dos atributos de tiempo por archivo:
    - $STANDARD_INFORMATION (SI): Timestamps que pueden ser modificados por APIs de usuario
    - $FILE_NAME (FN): Timestamps que solo el kernel puede modificar
    
    Cuando SI.Created < FN.Created, o SI timestamps son inconsistentes,
    es un fuerte indicador de TIMESTOMPING (T1070.006).
    """
    
    t = ATTACK_START
    
    mft_entries = [
        # ─── Archivos legítimos del sistema (referencia) ───
        {
            "mft_entry": 38421,
            "sequence": 1,
            "filename": "svchost.exe",
            "full_path": "C:\\Windows\\System32\\svchost.exe",
            "parent_path": "C:\\Windows\\System32\\",
            "size": 51688,
            "si_created": "2019-03-19T07:14:22.000000Z",
            "si_modified": "2019-03-19T07:14:22.000000Z",
            "si_accessed": (t + timedelta(hours=8)).isoformat() + "Z",
            "si_entry_modified": "2019-03-19T07:14:22.000000Z",
            "fn_created": "2019-03-19T07:14:22.000000Z",
            "fn_modified": "2019-03-19T07:14:22.000000Z",
            "fn_accessed": "2019-03-19T07:14:22.000000Z",
            "fn_entry_modified": "2019-03-19T07:14:22.000000Z",
            "flags": "Archive",
            "is_allocated": True,
            "category": "legitimate",
            "timestomp_detected": False,
            "notes": "svchost.exe legítimo - timestamps SI y FN coinciden (instalación original del OS)"
        },
        # ─── Beacon disfrazado - CON TIMESTOMPING ───
        {
            "mft_entry": 198234,
            "sequence": 1,
            "filename": "svchost.exe",
            "full_path": "C:\\Users\\Public\\Downloads\\svchost.exe",
            "parent_path": "C:\\Users\\Public\\Downloads\\",
            "size": 45056,
            "si_created": "2019-03-19T07:14:22.000000Z",
            "si_modified": "2019-03-19T07:14:22.000000Z",
            "si_accessed": "2019-03-19T07:14:22.000000Z",
            "si_entry_modified": "2019-03-19T07:14:22.000000Z",
            "fn_created": (t + timedelta(minutes=18)).isoformat() + "Z",
            "fn_modified": (t + timedelta(minutes=18)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(minutes=18)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(minutes=18)).isoformat() + "Z",
            "flags": "Archive, Hidden",
            "is_allocated": True,
            "category": "malicious",
            "timestomp_detected": True,
            "notes": "¡¡¡TIMESTOMPING DETECTADO!!! SI timestamps (2019) NO coinciden con FN timestamps (2026-07-15). El atacante copió los timestamps del svchost.exe legítimo para camuflar su beacon. FN revela la fecha REAL de creación del archivo."
        },
        # ─── Mimikatz - CON TIMESTOMPING ───
        {
            "mft_entry": 198567,
            "sequence": 1,
            "filename": "mimikatz.exe",
            "full_path": "C:\\Windows\\Temp\\mimikatz.exe",
            "parent_path": "C:\\Windows\\Temp\\",
            "size": 1250816,
            "si_created": "2020-01-15T10:30:00.000000Z",
            "si_modified": "2020-01-15T10:30:00.000000Z",
            "si_accessed": "2020-01-15T10:30:00.000000Z",
            "si_entry_modified": "2020-01-15T10:30:00.000000Z",
            "fn_created": (t + timedelta(hours=1, minutes=40)).isoformat() + "Z",
            "fn_modified": (t + timedelta(hours=1, minutes=40)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(hours=1, minutes=45)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(hours=1, minutes=40)).isoformat() + "Z",
            "flags": "Archive, Hidden, System",
            "is_allocated": True,
            "category": "malicious",
            "timestomp_detected": True,
            "notes": "TIMESTOMPING: SI muestra enero 2020, FN muestra julio 2026. Además tiene flags Hidden+System para ocultarse. El atacante intentó hacer parecer que el archivo existía desde hace años."
        },
        # ─── PrintSpoofer - SIN timestomping (el atacante no lo ocultó) ───
        {
            "mft_entry": 198890,
            "sequence": 1,
            "filename": "PrintSpoofer64.exe",
            "full_path": "C:\\Windows\\Temp\\PrintSpoofer64.exe",
            "parent_path": "C:\\Windows\\Temp\\",
            "size": 27648,
            "si_created": (t + timedelta(minutes=33)).isoformat() + "Z",
            "si_modified": (t + timedelta(minutes=33)).isoformat() + "Z",
            "si_accessed": (t + timedelta(minutes=35)).isoformat() + "Z",
            "si_entry_modified": (t + timedelta(minutes=33)).isoformat() + "Z",
            "fn_created": (t + timedelta(minutes=33)).isoformat() + "Z",
            "fn_modified": (t + timedelta(minutes=33)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(minutes=35)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(minutes=33)).isoformat() + "Z",
            "flags": "Archive",
            "is_allocated": False,
            "category": "malicious",
            "timestomp_detected": False,
            "notes": "PrintSpoofer NO tiene timestomping (SI == FN). El atacante no lo ocultó, probablemente porque lo eliminó después de usarlo (is_allocated=False = archivo borrado pero recuperable de MFT)"
        },
        # ─── PsExec - CON TIMESTOMPING parcial ───
        {
            "mft_entry": 199012,
            "sequence": 1,
            "filename": "PsExec.exe",
            "full_path": "C:\\Windows\\Temp\\PsExec.exe",
            "parent_path": "C:\\Windows\\Temp\\",
            "size": 833024,
            "si_created": "2024-01-15T10:00:00.000000Z",
            "si_modified": "2024-01-15T10:00:00.000000Z",
            "si_accessed": (t + timedelta(hours=3, minutes=30)).isoformat() + "Z",
            "si_entry_modified": (t + timedelta(hours=3, minutes=30)).isoformat() + "Z",
            "fn_created": (t + timedelta(hours=2, minutes=55)).isoformat() + "Z",
            "fn_modified": (t + timedelta(hours=2, minutes=55)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(hours=3, minutes=30)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(hours=2, minutes=55)).isoformat() + "Z",
            "flags": "Archive",
            "is_allocated": True,
            "category": "suspicious",
            "timestomp_detected": True,
            "notes": "TIMESTOMPING PARCIAL: SI.Created/Modified muestran 2024 pero SI.Accessed y SI.EntryModified son de 2026. El atacante solo modificó Created y Modified pero olvidó los otros campos. FN revela la fecha real."
        },
        # ─── Rclone config (exfiltración) ───
        {
            "mft_entry": 199345,
            "sequence": 1,
            "filename": "rclone.conf",
            "full_path": "C:\\Windows\\Temp\\rclone.conf",
            "parent_path": "C:\\Windows\\Temp\\",
            "size": 256,
            "si_created": (t + timedelta(hours=4, minutes=45)).isoformat() + "Z",
            "si_modified": (t + timedelta(hours=4, minutes=45)).isoformat() + "Z",
            "si_accessed": (t + timedelta(hours=5)).isoformat() + "Z",
            "si_entry_modified": (t + timedelta(hours=4, minutes=45)).isoformat() + "Z",
            "fn_created": (t + timedelta(hours=4, minutes=45)).isoformat() + "Z",
            "fn_modified": (t + timedelta(hours=4, minutes=45)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(hours=5)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(hours=4, minutes=45)).isoformat() + "Z",
            "flags": "Archive, Hidden",
            "is_allocated": False,
            "category": "malicious",
            "timestomp_detected": False,
            "notes": "Archivo de configuración de rclone (eliminado). Contiene credenciales del destino de exfiltración. Archivo borrado pero recuperable"
        },
        # ─── Staging directory ───
        {
            "mft_entry": 199456,
            "sequence": 1,
            "filename": "financial_data_Q2_2026.7z",
            "full_path": "C:\\Windows\\Temp\\staging\\financial_data_Q2_2026.7z",
            "parent_path": "C:\\Windows\\Temp\\staging\\",
            "size": 157286400,
            "si_created": (t + timedelta(hours=4, minutes=30)).isoformat() + "Z",
            "si_modified": (t + timedelta(hours=4, minutes=55)).isoformat() + "Z",
            "si_accessed": (t + timedelta(hours=5)).isoformat() + "Z",
            "si_entry_modified": (t + timedelta(hours=4, minutes=55)).isoformat() + "Z",
            "fn_created": (t + timedelta(hours=4, minutes=30)).isoformat() + "Z",
            "fn_modified": (t + timedelta(hours=4, minutes=55)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(hours=5)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(hours=4, minutes=55)).isoformat() + "Z",
            "flags": "Archive",
            "is_allocated": False,
            "category": "malicious",
            "timestomp_detected": False,
            "notes": "Archivo comprimido con datos financieros (150MB). Staging para exfiltración. Eliminado después de la transferencia con rclone"
        },
        # ─── LSASS dump ───
        {
            "mft_entry": 199567,
            "sequence": 1,
            "filename": "debug.dmp",
            "full_path": "C:\\Windows\\Temp\\debug.dmp",
            "parent_path": "C:\\Windows\\Temp\\",
            "size": 67108864,
            "si_created": (t + timedelta(hours=2, minutes=5)).isoformat() + "Z",
            "si_modified": (t + timedelta(hours=2, minutes=6)).isoformat() + "Z",
            "si_accessed": (t + timedelta(hours=2, minutes=10)).isoformat() + "Z",
            "si_entry_modified": (t + timedelta(hours=2, minutes=6)).isoformat() + "Z",
            "fn_created": (t + timedelta(hours=2, minutes=5)).isoformat() + "Z",
            "fn_modified": (t + timedelta(hours=2, minutes=6)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(hours=2, minutes=10)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(hours=2, minutes=5)).isoformat() + "Z",
            "flags": "Archive",
            "is_allocated": False,
            "category": "malicious",
            "timestomp_detected": False,
            "notes": "Volcado de LSASS renombrado como 'debug.dmp' para evadir detección. 64MB es tamaño típico de dump de LSASS. Creado por procdump64.exe"
        },
        # ─── Timestomp tool ───
        {
            "mft_entry": 199678,
            "sequence": 1,
            "filename": "timestomp.exe",
            "full_path": "C:\\Windows\\Temp\\timestomp.exe",
            "parent_path": "C:\\Windows\\Temp\\",
            "size": 15360,
            "si_created": "2019-06-15T08:00:00.000000Z",
            "si_modified": "2019-06-15T08:00:00.000000Z",
            "si_accessed": "2019-06-15T08:00:00.000000Z",
            "si_entry_modified": "2019-06-15T08:00:00.000000Z",
            "fn_created": (t + timedelta(hours=5, minutes=25)).isoformat() + "Z",
            "fn_modified": (t + timedelta(hours=5, minutes=25)).isoformat() + "Z",
            "fn_accessed": (t + timedelta(hours=5, minutes=30)).isoformat() + "Z",
            "fn_entry_modified": (t + timedelta(hours=5, minutes=25)).isoformat() + "Z",
            "flags": "Archive, Hidden",
            "is_allocated": False,
            "category": "malicious",
            "timestomp_detected": True,
            "notes": "¡LA HERRAMIENTA DE TIMESTOMPING EN SÍ MISMA FUE TIMESTOMPED! Ironía: el atacante usó la herramienta para modificar sus propios timestamps y luego la eliminó. FN revela que fue creada durante el ataque."
        },
    ]
    
    # Guardar JSON completo
    with open(f"{CASE_DIR}/mft/mft_parsed.json", "w") as f:
        json.dump(mft_entries, f, indent=2)
    
    # Generar archivo de timeline (bodyfile format para mactime)
    with open(f"{CASE_DIR}/mft/mft_bodyfile.txt", "w") as f:
        f.write("# MFT Bodyfile - Formato compatible con mactime (Sleuth Kit)\n")
        f.write("# MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime\n")
        for entry in mft_entries:
            # Usar FN timestamps (los reales)
            fn_c = entry['fn_created'].replace('Z', '').replace('T', ' ')
            fn_m = entry['fn_modified'].replace('Z', '').replace('T', ' ')
            fn_a = entry['fn_accessed'].replace('Z', '').replace('T', ' ')
            f.write(f"0|{entry['full_path']}|{entry['mft_entry']}|-/-rwxrwxrwx|0|0|{entry['size']}|{fn_a}|{fn_m}|{fn_c}|{fn_c}\n")
    
    return mft_entries


def generate_timeline():
    """Genera una línea de tiempo consolidada del ataque."""
    t = ATTACK_START
    
    timeline = [
        {"time": t.isoformat(), "phase": "Initial Access", "technique": "T1566.001", "description": "Usuario abre documento Word malicioso (spearphishing attachment)", "evidence": "Prefetch: WINWORD.EXE", "severity": "HIGH"},
        {"time": (t + timedelta(minutes=3)).isoformat(), "phase": "Execution", "technique": "T1059.001", "description": "Macro ejecuta PowerShell para descargar stage 2", "evidence": "Prefetch: POWERSHELL.EXE", "severity": "HIGH"},
        {"time": (t + timedelta(minutes=5)).isoformat(), "phase": "Command and Control", "technique": "T1105", "description": "certutil descarga beacon desde C2 (185.220.101.34)", "evidence": "Prefetch: CERTUTIL.EXE (run 1/4)", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=7)).isoformat(), "phase": "Command and Control", "technique": "T1105", "description": "certutil descarga mimikatz", "evidence": "Prefetch: CERTUTIL.EXE (run 2/4)", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=9)).isoformat(), "phase": "Command and Control", "technique": "T1105", "description": "certutil descarga PrintSpoofer", "evidence": "Prefetch: CERTUTIL.EXE (run 3/4)", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=12)).isoformat(), "phase": "Command and Control", "technique": "T1105", "description": "certutil descarga PsExec", "evidence": "Prefetch: CERTUTIL.EXE (run 4/4)", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=14)).isoformat(), "phase": "Command and Control", "technique": "T1197", "description": "bitsadmin como método alternativo de descarga", "evidence": "Prefetch: BITSADMIN.EXE", "severity": "HIGH"},
        {"time": (t + timedelta(minutes=18)).isoformat(), "phase": "Defense Evasion", "technique": "T1036.005", "description": "Beacon renombrado como svchost.exe en Users\\Public\\Downloads", "evidence": "MFT: FN.Created, Amcache: path anómalo", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=20)).isoformat(), "phase": "Execution", "technique": "T1036.005", "description": "Beacon (falso svchost.exe) ejecutado - C2 establecido", "evidence": "Prefetch: SVCHOST.EXE-1A2B3C4D (path anómalo)", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=33)).isoformat(), "phase": "Privilege Escalation", "technique": "T1068", "description": "PrintSpoofer descargado a Windows\\Temp", "evidence": "MFT: PrintSpoofer64.exe created", "severity": "HIGH"},
        {"time": (t + timedelta(minutes=35)).isoformat(), "phase": "Privilege Escalation", "technique": "T1068", "description": "PrintSpoofer ejecutado - escalación a SYSTEM", "evidence": "Prefetch: PRINTSPOOFER64.EXE (run_count=1)", "severity": "CRITICAL"},
        {"time": (t + timedelta(minutes=38)).isoformat(), "phase": "Discovery", "technique": "T1087", "description": "Enumeración de usuarios y grupos con net.exe", "evidence": "Prefetch: NET.EXE (8 ejecuciones)", "severity": "MEDIUM"},
        {"time": (t + timedelta(minutes=40)).isoformat(), "phase": "Discovery", "technique": "T1482", "description": "Enumeración de domain trusts con nltest", "evidence": "Prefetch: NLTEST.EXE", "severity": "MEDIUM"},
        {"time": (t + timedelta(hours=1, minutes=40)).isoformat(), "phase": "Credential Access", "technique": "T1003.001", "description": "Mimikatz descargado a Windows\\Temp", "evidence": "MFT: mimikatz.exe, Amcache: first_run", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=1, minutes=45)).isoformat(), "phase": "Credential Access", "technique": "T1003.001", "description": "Mimikatz ejecutado - sekurlsa::logonpasswords", "evidence": "Prefetch: MIMIKATZ.EXE, UserAssist: 2min focus", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=2)).isoformat(), "phase": "Credential Access", "technique": "T1003.001", "description": "ProcDump usado para volcar LSASS a disco", "evidence": "Prefetch: PROCDUMP64.EXE, MFT: debug.dmp (64MB)", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=2, minutes=10)).isoformat(), "phase": "Credential Access", "technique": "T1003.001", "description": "Segunda ejecución de Mimikatz sobre el dump", "evidence": "Prefetch: MIMIKATZ.EXE (run 2)", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=2, minutes=55)).isoformat(), "phase": "Lateral Movement", "technique": "T1021.002", "description": "PsExec preparado para movimiento lateral", "evidence": "MFT: PsExec.exe created in Temp", "severity": "HIGH"},
        {"time": (t + timedelta(hours=3)).isoformat(), "phase": "Lateral Movement", "technique": "T1021.002", "description": "PsExec → Host 1 (10.50.25.102)", "evidence": "Prefetch: PSEXEC.EXE (run 1/3)", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=3, minutes=15)).isoformat(), "phase": "Lateral Movement", "technique": "T1021.002", "description": "PsExec → Host 2 (10.50.25.103)", "evidence": "Prefetch: PSEXEC.EXE (run 2/3)", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=3, minutes=30)).isoformat(), "phase": "Lateral Movement", "technique": "T1021.002", "description": "PsExec → Host 3 (10.50.25.104)", "evidence": "Prefetch: PSEXEC.EXE (run 3/3)", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=4, minutes=30)).isoformat(), "phase": "Collection", "technique": "T1560.001", "description": "Datos financieros comprimidos en staging directory", "evidence": "MFT: financial_data_Q2_2026.7z (150MB)", "severity": "HIGH"},
        {"time": (t + timedelta(hours=4, minutes=45)).isoformat(), "phase": "Exfiltration", "technique": "T1567.002", "description": "Configuración de rclone creada para exfiltración", "evidence": "MFT: rclone.conf", "severity": "HIGH"},
        {"time": (t + timedelta(hours=5)).isoformat(), "phase": "Exfiltration", "technique": "T1567.002", "description": "Exfiltración de datos via rclone a cloud storage", "evidence": "Prefetch: RCLONE.EXE, UserAssist: background exec", "severity": "CRITICAL"},
        {"time": (t + timedelta(hours=5, minutes=25)).isoformat(), "phase": "Defense Evasion", "technique": "T1070.006", "description": "Herramienta timestomp desplegada", "evidence": "MFT: timestomp.exe (FN vs SI mismatch)", "severity": "HIGH"},
        {"time": (t + timedelta(hours=5, minutes=30)).isoformat(), "phase": "Defense Evasion", "technique": "T1070.006", "description": "Timestomping aplicado a beacon y mimikatz", "evidence": "MFT: SI timestamps antiguos vs FN recientes", "severity": "HIGH"},
        {"time": (t + timedelta(hours=5, minutes=35)).isoformat(), "phase": "Defense Evasion", "technique": "T1070.001", "description": "Limpieza de Security Event Log", "evidence": "Prefetch: WEVTUTIL.EXE (run 1/3)", "severity": "HIGH"},
        {"time": (t + timedelta(hours=5, minutes=36)).isoformat(), "phase": "Defense Evasion", "technique": "T1070.001", "description": "Limpieza de System Event Log", "evidence": "Prefetch: WEVTUTIL.EXE (run 2/3)", "severity": "HIGH"},
        {"time": (t + timedelta(hours=5, minutes=37)).isoformat(), "phase": "Defense Evasion", "technique": "T1070.001", "description": "Limpieza de PowerShell Event Log", "evidence": "Prefetch: WEVTUTIL.EXE (run 3/3)", "severity": "HIGH"},
    ]
    
    with open(f"{CASE_DIR}/timeline/attack_timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)
    
    # Generar versión CSV
    with open(f"{CASE_DIR}/timeline/attack_timeline.csv", "w") as f:
        f.write("Timestamp,Phase,MITRE_Technique,Description,Evidence,Severity\n")
        for entry in timeline:
            desc = entry['description'].replace(',', ';')
            ev = entry['evidence'].replace(',', ';')
            f.write(f"{entry['time']},{entry['phase']},{entry['technique']},{desc},{ev},{entry['severity']}\n")


def generate_iocs():
    """Genera lista de IOCs del caso."""
    iocs = {
        "case_id": "IR-2026-0715-001",
        "generated": datetime.now().isoformat(),
        "network_iocs": [
            {"type": "ip", "value": ATTACKER_IP, "context": "IP origen del atacante (descarga de herramientas)"},
            {"type": "ip", "value": C2_IP, "context": "IP del servidor C2 (beacon callbacks)"},
            {"type": "domain", "value": C2_DOMAIN, "context": "Dominio C2 (resuelve a 104.21.45.67)"},
            {"type": "ip", "value": "10.50.25.102", "context": "Host interno comprometido via PsExec"},
            {"type": "ip", "value": "10.50.25.103", "context": "Host interno comprometido via PsExec"},
            {"type": "ip", "value": "10.50.25.104", "context": "Host interno comprometido via PsExec"},
        ],
        "file_iocs": [
            {"type": "sha1", "value": MALWARE_HASHES["beacon_svchost"]["sha1"], "filename": "svchost.exe (beacon)", "context": "Cobalt Strike beacon disfrazado"},
            {"type": "sha1", "value": MALWARE_HASHES["mimikatz"]["sha1"], "filename": "mimikatz.exe", "context": "Credential dumping tool"},
            {"type": "sha1", "value": MALWARE_HASHES["printspoofer"]["sha1"], "filename": "PrintSpoofer64.exe", "context": "Privilege escalation exploit"},
            {"type": "sha1", "value": MALWARE_HASHES["rclone_exfil"]["sha1"], "filename": "rclone.exe", "context": "Data exfiltration tool"},
        ],
        "behavioral_iocs": [
            "certutil.exe descargando ejecutables de IPs externas",
            "svchost.exe ejecutándose desde C:\\Users\\Public\\Downloads\\",
            "Múltiples ejecuciones de net.exe y nltest.exe en corto período",
            "ProcDump accediendo a LSASS",
            "wevtutil.exe limpiando múltiples logs en secuencia",
            "Archivos con timestamps $SI inconsistentes con $FN",
        ]
    }
    
    with open(f"{CASE_DIR}/iocs/iocs_complete.json", "w") as f:
        json.dump(iocs, f, indent=2)


# ─── MAIN ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Generando escenario de ataque APT para Lab 19...")
    print(f"[*] Caso: IR-2026-0715-001 | Host: SRV-FIN-01")
    print(f"[*] Directorio de evidencia: {CASE_DIR}")
    print()
    
    create_directories()
    print("[+] Estructura de directorios creada")
    
    generate_case_context()
    print("[+] Contexto del caso generado")
    
    prefetch = generate_prefetch_artifacts()
    print(f"[+] Prefetch: {len(prefetch)} entradas generadas ({len([p for p in prefetch if p['category']=='malicious'])} maliciosas)")
    
    amcache = generate_amcache_artifacts()
    print(f"[+] Amcache: {len(amcache)} entradas generadas ({len([a for a in amcache if a['category']=='malicious'])} maliciosas)")
    
    userassist = generate_userassist_artifacts()
    print(f"[+] UserAssist: {len(userassist)} entradas generadas ({len([u for u in userassist if u['category']=='malicious'])} maliciosas)")
    
    mft = generate_mft_artifacts()
    print(f"[+] MFT: {len(mft)} entradas generadas ({len([m for m in mft if m['timestomp_detected']])} con timestomping)")
    
    generate_timeline()
    print("[+] Timeline del ataque generada")
    
    generate_iocs()
    print("[+] IOCs del caso generados")
    
    print()
    print("=" * 70)
    print("  EVIDENCIA FORENSE LISTA PARA ANÁLISIS")
    print("=" * 70)
    print(f"  Prefetch:    /cases/SRV-FIN-01/prefetch/")
    print(f"  Amcache:     /cases/SRV-FIN-01/amcache/")
    print(f"  UserAssist:  /cases/SRV-FIN-01/userassist/")
    print(f"  MFT:         /cases/SRV-FIN-01/mft/")
    print(f"  Timeline:    /cases/SRV-FIN-01/timeline/")
    print(f"  IOCs:        /cases/SRV-FIN-01/iocs/")
    print(f"  Contexto:    /cases/SRV-FIN-01/context/")
    print("=" * 70)
