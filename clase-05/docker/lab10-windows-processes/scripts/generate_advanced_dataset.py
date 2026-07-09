#!/usr/bin/env python3
"""
generate_advanced_dataset.py
============================
Genera un dataset avanzado para el Lab 10 con técnicas más sofisticadas:
1. Process Hollowing (proceso legítimo con código inyectado)
2. DLL Side-Loading (DLL maliciosa en path de aplicación legítima)
3. Parent PID Spoofing (proceso con parent falsificado)
4. Token Manipulation (proceso de usuario con privilegios SYSTEM)
5. Timestomping (proceso con timestamp modificado)

Curso MAR404 - Cacería de Amenazas - Clase 5
"""

import json
import os
from datetime import datetime, timedelta

OUTPUT_DIR = "/data"


def generate_scenario():
    """Genera el escenario avanzado."""
    boot_time = datetime(2025, 4, 10, 7, 30, 0)
    
    processes = [
        # === PROCESOS LEGÍTIMOS ===
        {"pid": 4, "ppid": 0, "name": "System", "path": "N/A", "user": "NT AUTHORITY\\SYSTEM",
         "create_time": boot_time.isoformat(), "cmdline": "", "threads": 180, "handles": 2500,
         "is_malicious": False, "vad_suspicious": False},
        {"pid": 380, "ppid": 4, "name": "smss.exe", "path": "C:\\Windows\\System32\\smss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot_time.isoformat(),
         "cmdline": "\\SystemRoot\\System32\\smss.exe", "threads": 2, "handles": 30,
         "is_malicious": False, "vad_suspicious": False},
        {"pid": 480, "ppid": 380, "name": "csrss.exe", "path": "C:\\Windows\\System32\\csrss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot_time.isoformat(),
         "cmdline": "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows",
         "threads": 12, "handles": 500, "is_malicious": False, "vad_suspicious": False},
        {"pid": 540, "ppid": 380, "name": "wininit.exe", "path": "C:\\Windows\\System32\\wininit.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot_time.isoformat(),
         "cmdline": "wininit.exe", "threads": 3, "handles": 80,
         "is_malicious": False, "vad_suspicious": False},
        {"pid": 600, "ppid": 540, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot_time.isoformat(),
         "cmdline": "C:\\Windows\\system32\\services.exe", "threads": 8, "handles": 300,
         "is_malicious": False, "vad_suspicious": False},
        {"pid": 620, "ppid": 540, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot_time.isoformat(),
         "cmdline": "C:\\Windows\\system32\\lsass.exe", "threads": 10, "handles": 800,
         "is_malicious": False, "vad_suspicious": False},
        {"pid": 700, "ppid": 600, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot_time.isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
         "threads": 25, "handles": 1200, "is_malicious": False, "vad_suspicious": False},
        {"pid": 800, "ppid": 600, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\NETWORK SERVICE", "create_time": boot_time.isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
         "threads": 40, "handles": 1800, "is_malicious": False, "vad_suspicious": False},
        {"pid": 900, "ppid": 600, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\LOCAL SERVICE", "create_time": boot_time.isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalService -p",
         "threads": 15, "handles": 600, "is_malicious": False, "vad_suspicious": False},
        {"pid": 2100, "ppid": 2050, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
         "user": "CORP\\john.smith", "create_time": (boot_time + timedelta(minutes=3)).isoformat(),
         "cmdline": "C:\\Windows\\Explorer.EXE", "threads": 35, "handles": 1500,
         "is_malicious": False, "vad_suspicious": False},
        {"pid": 2800, "ppid": 2100, "name": "outlook.exe",
         "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
         "user": "CORP\\john.smith", "create_time": (boot_time + timedelta(minutes=5)).isoformat(),
         "cmdline": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
         "threads": 25, "handles": 800, "is_malicious": False, "vad_suspicious": False},
        
        # === PROCESOS MALICIOSOS ===
        
        # MALICIOSO 1: Process Hollowing en notepad.exe
        # notepad.exe legítimo pero con VAD sospechoso (PAGE_EXECUTE_READWRITE)
        {"pid": 5544, "ppid": 2100, "name": "notepad.exe",
         "path": "C:\\Windows\\System32\\notepad.exe",
         "user": "CORP\\john.smith",
         "create_time": (boot_time + timedelta(minutes=30)).isoformat(),
         "cmdline": "\"C:\\Windows\\System32\\notepad.exe\"",
         "threads": 8, "handles": 250,
         "is_malicious": True, "vad_suspicious": True,
         "technique": "T1055.012 - Process Hollowing",
         "indicators": [
             "VAD con protección PAGE_EXECUTE_READWRITE (RWX) - no normal para notepad",
             "8 threads (notepad normal tiene 3-4)",
             "250 handles (notepad normal tiene ~80)",
             "Conexión de red activa (notepad NO debería tener conexiones)",
             "malfind detectaría código inyectado en las regiones RWX"
         ],
         "malfind_output": "Process: notepad.exe PID: 5544\nVAD: 0x400000 Protection: PAGE_EXECUTE_READWRITE\nMZ header detected - possible injected PE\n4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ.............."},
        
        # MALICIOSO 2: DLL Side-Loading
        # Proceso legítimo cargando DLL maliciosa
        {"pid": 3300, "ppid": 2100, "name": "OneDrive.exe",
         "path": "C:\\Users\\john.smith\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
         "user": "CORP\\john.smith",
         "create_time": (boot_time + timedelta(minutes=6)).isoformat(),
         "cmdline": "\"C:\\Users\\john.smith\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
         "threads": 15, "handles": 400,
         "is_malicious": True, "vad_suspicious": False,
         "technique": "T1574.002 - DLL Side-Loading",
         "indicators": [
             "Carga version.dll desde su propio directorio (no System32)",
             "version.dll en AppData no está firmada por Microsoft",
             "Conexión a IP externa no asociada a Microsoft/OneDrive",
             "El proceso legítimo es abusado como loader"
         ],
         "dlls": [
             {"name": "version.dll", "path": "C:\\Users\\john.smith\\AppData\\Local\\Microsoft\\OneDrive\\version.dll",
              "signed": False, "suspicious": True, "notes": "DLL hijacked - debería cargarse desde System32"}
         ]},
        
        # MALICIOSO 3: Parent PID Spoofing
        # Proceso malicioso que falsifica su parent como services.exe
        {"pid": 4420, "ppid": 600, "name": "svchost.exe",
         "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM",
         "create_time": (boot_time + timedelta(hours=2)).isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
         "threads": 3, "handles": 100,
         "is_malicious": True, "vad_suspicious": True,
         "technique": "T1134.004 - Parent PID Spoofing",
         "indicators": [
             "Creado 2 HORAS después del boot (svchost se crea al boot)",
             "Solo 3 threads (svchost netsvcs normal tiene 40+)",
             "Solo 100 handles (normal: 1800+)",
             "VAD con regiones RWX (no normal para svchost)",
             "Si se verifica con ETW/Sysmon, el parent REAL es diferente"
         ]},
        
        # MALICIOSO 4: Token Manipulation
        # Proceso de usuario que adquirió token SYSTEM
        {"pid": 6100, "ppid": 5544, "name": "cmd.exe",
         "path": "C:\\Windows\\System32\\cmd.exe",
         "user": "NT AUTHORITY\\SYSTEM",
         "create_time": (boot_time + timedelta(minutes=32)).isoformat(),
         "cmdline": "cmd.exe /c whoami > C:\\Users\\john.smith\\Desktop\\priv.txt",
         "threads": 1, "handles": 30,
         "is_malicious": True, "vad_suspicious": False,
         "technique": "T1134.001 - Token Impersonation/Theft",
         "indicators": [
             "cmd.exe corriendo como SYSTEM pero hijo de notepad.exe (hollowed)",
             "notepad.exe no debería spawnar cmd.exe",
             "Comando 'whoami' indica verificación de privilegios post-escalación",
             "Cadena: notepad(hollowed) → cmd.exe(SYSTEM) = privilege escalation"
         ]},
    ]
    
    # Conexiones de red
    connections = [
        {"pid": 2800, "proto": "TCPv4", "local": "192.168.10.50:52100", "remote": "52.96.166.130:443",
         "state": "ESTABLISHED", "is_malicious": False, "notes": "Outlook → Office365 (legítimo)"},
        {"pid": 800, "proto": "TCPv4", "local": "192.168.10.50:49800", "remote": "20.190.159.4:443",
         "state": "ESTABLISHED", "is_malicious": False, "notes": "Windows Update (legítimo)"},
        {"pid": 700, "proto": "TCPv4", "local": "0.0.0.0:135", "remote": "0.0.0.0:0",
         "state": "LISTENING", "is_malicious": False, "notes": "RPC (legítimo)"},
        # Maliciosas
        {"pid": 5544, "proto": "TCPv4", "local": "192.168.10.50:53200", "remote": "185.220.101.45:443",
         "state": "ESTABLISHED", "is_malicious": True,
         "notes": "notepad.exe con conexión HTTPS a IP de Tor exit node - ANOMALÍA"},
        {"pid": 3300, "proto": "TCPv4", "local": "192.168.10.50:54100", "remote": "91.215.85.12:8443",
         "state": "ESTABLISHED", "is_malicious": True,
         "notes": "OneDrive.exe conectado a IP en Rusia (no es infraestructura Microsoft)"},
        {"pid": 4420, "proto": "TCPv4", "local": "192.168.10.50:55000", "remote": "203.0.113.50:4443",
         "state": "ESTABLISHED", "is_malicious": True,
         "notes": "svchost falso con conexión C2 a puerto 4443"},
    ]
    
    return processes, connections


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    processes, connections = generate_scenario()
    
    # Guardar JSON
    with open(f"{OUTPUT_DIR}/processes.json", "w") as f:
        json.dump(processes, f, indent=2)
    
    with open(f"{OUTPUT_DIR}/connections.json", "w") as f:
        json.dump(connections, f, indent=2)
    
    # Generar salida tipo Volatility
    with open(f"{OUTPUT_DIR}/vol3_pslist.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\n")
        f.write("Plugin: windows.pslist.PsList\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<20}{'CreateTime':<28}{'Threads':<10}{'Handles':<10}\n")
        f.write("-" * 90 + "\n")
        for p in processes:
            f.write(f"{p['pid']:<8}{p['ppid']:<8}{p['name']:<20}{p['create_time']:<28}{p['threads']:<10}{p['handles']:<10}\n")
    
    with open(f"{OUTPUT_DIR}/vol3_cmdline.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\n")
        f.write("Plugin: windows.cmdline.CmdLine\n\n")
        f.write(f"{'PID':<8}{'Process':<20}{'Args'}\n")
        f.write("-" * 90 + "\n")
        for p in processes:
            if p['cmdline']:
                f.write(f"{p['pid']:<8}{p['name']:<20}{p['cmdline']}\n")
    
    with open(f"{OUTPUT_DIR}/vol3_netscan.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\n")
        f.write("Plugin: windows.netscan.NetScan\n\n")
        f.write(f"{'Proto':<8}{'LocalAddr':<25}{'ForeignAddr':<25}{'State':<15}{'PID':<8}{'Owner'}\n")
        f.write("-" * 100 + "\n")
        for c in connections:
            owner = next((p['name'] for p in processes if p['pid'] == c['pid']), "Unknown")
            f.write(f"{c['proto']:<8}{c['local']:<25}{c['remote']:<25}{c['state']:<15}{c['pid']:<8}{owner}\n")
    
    # Generar malfind output
    with open(f"{OUTPUT_DIR}/vol3_malfind.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\n")
        f.write("Plugin: windows.malfind.Malfind\n\n")
        for p in processes:
            if p.get("vad_suspicious"):
                f.write(f"PID: {p['pid']} | Process: {p['name']}\n")
                f.write(f"VAD Tag: VadS | Protection: PAGE_EXECUTE_READWRITE\n")
                if p.get("malfind_output"):
                    f.write(f"{p['malfind_output']}\n")
                else:
                    f.write(f"0x00400000  4d 5a 90 00 03 00 00 00  MZ......\n")
                    f.write(f"0x00400008  04 00 00 00 ff ff 00 00  ........\n")
                f.write("\n" + "-" * 60 + "\n\n")
    
    print(f"[+] Dataset avanzado generado en {OUTPUT_DIR}")
    print(f"[+] Procesos totales: {len(processes)}")
    print(f"[+] Procesos maliciosos: {sum(1 for p in processes if p.get('is_malicious'))}")
    print(f"[+] Conexiones: {len(connections)} ({sum(1 for c in connections if c['is_malicious'])} maliciosas)")
    print(f"[+] Técnicas: Process Hollowing, DLL Side-Loading, PPID Spoofing, Token Manipulation")


if __name__ == "__main__":
    main()
