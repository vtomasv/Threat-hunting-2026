#!/usr/bin/env python3
"""
generate_injection_dataset.py
=============================
Genera dataset que simula un memory dump con 3 técnicas de inyección:
1. Classic DLL Injection en explorer.exe (T1055.001)
2. Process Hollowing en svchost.exe (T1055.012)
3. APC Injection en notepad.exe (T1055.004)

Curso MAR404 - Clase 6
"""

import json
import os
from datetime import datetime, timedelta

OUTPUT_DIR = "/data"


def generate_processes():
    boot = datetime(2025, 5, 20, 8, 0, 0)
    return [
        # === PROCESOS LEGÍTIMOS ===
        {"pid": 4, "ppid": 0, "name": "System", "path": "N/A",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 180, "handles": 2500, "is_malicious": False},
        {"pid": 400, "ppid": 4, "name": "smss.exe", "path": "C:\\Windows\\System32\\smss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 2, "handles": 30, "is_malicious": False},
        {"pid": 520, "ppid": 400, "name": "csrss.exe", "path": "C:\\Windows\\System32\\csrss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 12, "handles": 500, "is_malicious": False},
        {"pid": 580, "ppid": 400, "name": "wininit.exe", "path": "C:\\Windows\\System32\\wininit.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 3, "handles": 80, "is_malicious": False},
        {"pid": 640, "ppid": 580, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 8, "handles": 300, "is_malicious": False},
        {"pid": 660, "ppid": 580, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 10, "handles": 800, "is_malicious": False},
        {"pid": 780, "ppid": 640, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
         "threads": 25, "handles": 1200, "is_malicious": False},
        {"pid": 860, "ppid": 640, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\NETWORK SERVICE", "create_time": boot.isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
         "threads": 40, "handles": 1800, "is_malicious": False},
        
        # explorer.exe (target de DLL Injection)
        {"pid": 2200, "ppid": 2100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
         "user": "CORP\\analyst01", "create_time": (boot + timedelta(minutes=3)).isoformat(),
         "threads": 42, "handles": 1600, "is_malicious": False,
         "note": "Proceso legítimo pero INYECTADO con DLL maliciosa"},
        
        # svchost.exe (target de Process Hollowing) - creado por atacante
        {"pid": 3344, "ppid": 640, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": (boot + timedelta(hours=1, minutes=30)).isoformat(),
         "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
         "threads": 4, "handles": 120, "is_malicious": True,
         "technique": "T1055.012 - Process Hollowing",
         "note": "Creado 1.5h post-boot, imagen reemplazada"},
        
        # notepad.exe (target de APC Injection)
        {"pid": 4100, "ppid": 2200, "name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe",
         "user": "CORP\\analyst01", "create_time": (boot + timedelta(hours=1, minutes=25)).isoformat(),
         "threads": 6, "handles": 180, "is_malicious": True,
         "technique": "T1055.004 - APC Injection",
         "note": "Notepad con APC inyectado, 6 threads (normal: 3)"},
        
        # Proceso atacante (dropper)
        {"pid": 5500, "ppid": 2200, "name": "update.exe",
         "path": "C:\\Users\\analyst01\\AppData\\Local\\Temp\\update.exe",
         "user": "CORP\\analyst01", "create_time": (boot + timedelta(hours=1, minutes=20)).isoformat(),
         "cmdline": "C:\\Users\\analyst01\\AppData\\Local\\Temp\\update.exe --silent",
         "threads": 3, "handles": 80, "is_malicious": True,
         "technique": "T1055 - Process Injection (orchestrator)",
         "note": "Dropper que realiza las 3 inyecciones"},
    ]


def generate_vad_data():
    """Genera datos de VAD (Virtual Address Descriptors) por proceso."""
    return {
        # explorer.exe - DLL Injection (DLL maliciosa cargada)
        2200: {
            "vads": [
                {"start": "0x7FFE0000", "end": "0x7FFE0FFF", "protection": "PAGE_READONLY",
                 "type": "Mapped", "file": "\\Windows\\System32\\ntdll.dll", "suspicious": False},
                {"start": "0x77000000", "end": "0x7714FFFF", "protection": "PAGE_EXECUTE_READ",
                 "type": "Mapped", "file": "\\Windows\\System32\\kernel32.dll", "suspicious": False},
                {"start": "0x10000000", "end": "0x1000FFFF", "protection": "PAGE_EXECUTE_READWRITE",
                 "type": "Mapped", "file": "\\Users\\analyst01\\AppData\\Local\\Temp\\msvcrt_ext.dll",
                 "suspicious": True,
                 "notes": "DLL en path temporal con protección RWX - Classic DLL Injection (T1055.001)"},
                {"start": "0x00400000", "end": "0x004FFFFF", "protection": "PAGE_EXECUTE_READ",
                 "type": "Mapped", "file": "\\Windows\\explorer.exe", "suspicious": False},
            ],
            "injected_dll": {
                "name": "msvcrt_ext.dll",
                "path": "C:\\Users\\analyst01\\AppData\\Local\\Temp\\msvcrt_ext.dll",
                "signed": False,
                "size": 65536,
                "exports": ["DllMain", "ServiceMain", "BeaconCallback"],
                "imports": ["ws2_32.dll!connect", "ws2_32.dll!send", "ws2_32.dll!recv",
                           "wininet.dll!HttpSendRequestA", "advapi32.dll!RegSetValueExA"],
                "strings_suspicious": ["http://203.0.113.100/beacon", "Mozilla/5.0 CobaltStrike",
                                      "pipe\\\\msagent_", "ADMIN$"]
            }
        },
        
        # svchost.exe PID 3344 - Process Hollowing
        3344: {
            "vads": [
                {"start": "0x00400000", "end": "0x0045FFFF", "protection": "PAGE_EXECUTE_READWRITE",
                 "type": "Private", "file": None, "suspicious": True,
                 "notes": "Imagen base RWX sin backing file - PROCESS HOLLOWING (T1055.012)",
                 "hex_dump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............\n"
                            "b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......\n"
                            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................\n"
                            "00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00  ................"},
                {"start": "0x7FFE0000", "end": "0x7FFE0FFF", "protection": "PAGE_READONLY",
                 "type": "Mapped", "file": "\\Windows\\System32\\ntdll.dll", "suspicious": False},
                {"start": "0x00600000", "end": "0x0060FFFF", "protection": "PAGE_EXECUTE_READWRITE",
                 "type": "Private", "file": None, "suspicious": True,
                 "notes": "Región adicional RWX - posible shellcode o configuración"},
            ],
            "hollowing_evidence": {
                "original_image": "C:\\Windows\\System32\\svchost.exe",
                "peb_image_base": "0x00400000",
                "actual_content": "PE malicioso (no es svchost.exe)",
                "entry_point_diff": True,
                "section_names": [".text", ".rdata", ".data", ".reloc", ".evil"],
                "notes": "La sección '.evil' no existe en svchost.exe legítimo"
            }
        },
        
        # notepad.exe PID 4100 - APC Injection
        4100: {
            "vads": [
                {"start": "0x00400000", "end": "0x0040FFFF", "protection": "PAGE_EXECUTE_READ",
                 "type": "Mapped", "file": "\\Windows\\System32\\notepad.exe", "suspicious": False},
                {"start": "0x7FFE0000", "end": "0x7FFE0FFF", "protection": "PAGE_READONLY",
                 "type": "Mapped", "file": "\\Windows\\System32\\ntdll.dll", "suspicious": False},
                {"start": "0x02000000", "end": "0x0200FFFF", "protection": "PAGE_EXECUTE_READWRITE",
                 "type": "Private", "file": None, "suspicious": True,
                 "notes": "Shellcode inyectado via APC - no tiene MZ header (T1055.004)",
                 "hex_dump": "fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51  .H........AQAPRQ\n"
                            "56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52  VH1.eH.R`H.R.H.R\n"
                            "20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0   H.rPH..JJM1.H1.\n"
                            "ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed  .<a|., A...A...."},
            ],
            "apc_evidence": {
                "thread_with_apc": 3,
                "apc_target_address": "0x02000000",
                "shellcode_type": "x64 reverse shell (Metasploit pattern)",
                "callback_ip": "203.0.113.100:4444",
                "notes": "Shellcode estándar de Metasploit, sin MZ header (diferencia con PE injection)"
            }
        },
        
        # Dropper update.exe
        5500: {
            "vads": [
                {"start": "0x00400000", "end": "0x0042FFFF", "protection": "PAGE_EXECUTE_READ",
                 "type": "Mapped", "file": "\\Users\\analyst01\\AppData\\Local\\Temp\\update.exe",
                 "suspicious": True,
                 "notes": "Ejecutable en directorio temporal - dropper/injector"},
            ],
            "handles_cross_process": [
                {"target_pid": 2200, "access": "PROCESS_ALL_ACCESS", "notes": "Handle a explorer.exe para DLL injection"},
                {"target_pid": 3344, "access": "PROCESS_ALL_ACCESS", "notes": "Handle a svchost para hollowing"},
                {"target_pid": 4100, "access": "PROCESS_ALL_ACCESS", "notes": "Handle a notepad para APC injection"},
            ]
        }
    }


def generate_threads():
    """Genera datos de threads con anomalías."""
    return {
        2200: [
            {"tid": 2204, "start_address": "0x77012345", "module": "ntdll.dll", "state": "Wait", "suspicious": False},
            {"tid": 2208, "start_address": "0x10001000", "module": "msvcrt_ext.dll",
             "state": "Running", "suspicious": True,
             "notes": "Thread iniciado en DLL inyectada (no es módulo legítimo de explorer)"},
        ],
        3344: [
            {"tid": 3348, "start_address": "0x00401000", "module": "UNKNOWN",
             "state": "Running", "suspicious": True,
             "notes": "Start address en imagen hollowed (no mapea a svchost.exe real)"},
            {"tid": 3352, "start_address": "0x00601000", "module": "UNKNOWN",
             "state": "Wait", "suspicious": True,
             "notes": "Thread en región RWX sin backing file"},
        ],
        4100: [
            {"tid": 4104, "start_address": "0x00401000", "module": "notepad.exe", "state": "Wait", "suspicious": False},
            {"tid": 4108, "start_address": "0x02000000", "module": "UNKNOWN",
             "state": "Running", "suspicious": True,
             "notes": "Thread APC ejecutando shellcode en región inyectada"},
        ],
    }


def generate_connections():
    """Genera conexiones de red."""
    return [
        {"pid": 860, "proto": "TCPv4", "local": "192.168.10.50:49800",
         "remote": "20.190.159.4:443", "state": "ESTABLISHED", "is_malicious": False},
        {"pid": 2200, "proto": "TCPv4", "local": "192.168.10.50:51000",
         "remote": "203.0.113.100:443", "state": "ESTABLISHED", "is_malicious": True,
         "notes": "explorer.exe → C2 via DLL inyectada (Cobalt Strike beacon)"},
        {"pid": 3344, "proto": "TCPv4", "local": "192.168.10.50:52000",
         "remote": "203.0.113.100:8443", "state": "ESTABLISHED", "is_malicious": True,
         "notes": "svchost hollowed → C2 secundario"},
        {"pid": 4100, "proto": "TCPv4", "local": "192.168.10.50:53000",
         "remote": "203.0.113.100:4444", "state": "ESTABLISHED", "is_malicious": True,
         "notes": "notepad.exe → reverse shell (Metasploit)"},
    ]


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    processes = generate_processes()
    vad_data = generate_vad_data()
    threads = generate_threads()
    connections = generate_connections()
    
    with open(f"{OUTPUT_DIR}/processes.json", "w") as f:
        json.dump(processes, f, indent=2)
    with open(f"{OUTPUT_DIR}/vad_data.json", "w") as f:
        json.dump(vad_data, f, indent=2)
    with open(f"{OUTPUT_DIR}/threads.json", "w") as f:
        json.dump(threads, f, indent=2)
    with open(f"{OUTPUT_DIR}/connections.json", "w") as f:
        json.dump(connections, f, indent=2)
    
    # Generar salidas tipo Volatility
    with open(f"{OUTPUT_DIR}/vol3_malfind.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.malfind.Malfind\n\n")
        for pid, data in vad_data.items():
            for vad in data["vads"]:
                if vad["suspicious"]:
                    proc = next((p for p in processes if p["pid"] == pid), None)
                    f.write(f"PID: {pid} | Process: {proc['name'] if proc else 'Unknown'}\n")
                    f.write(f"VAD: {vad['start']} - {vad['end']} | Protection: {vad['protection']}\n")
                    f.write(f"Type: {vad['type']} | File: {vad.get('file', 'N/A')}\n")
                    if vad.get("hex_dump"):
                        f.write(f"\nHex Dump:\n{vad['hex_dump']}\n")
                    f.write(f"\nNotes: {vad['notes']}\n")
                    f.write("-" * 70 + "\n\n")
    
    with open(f"{OUTPUT_DIR}/vol3_pslist.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.pslist.PsList\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<20}{'CreateTime':<28}{'Threads':<10}{'Handles':<10}\n")
        f.write("-" * 90 + "\n")
        for p in processes:
            f.write(f"{p['pid']:<8}{p['ppid']:<8}{p['name']:<20}{p['create_time']:<28}{p['threads']:<10}{p['handles']:<10}\n")
    
    with open(f"{OUTPUT_DIR}/vol3_threads.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.threads (custom)\n\n")
        f.write(f"{'PID':<8}{'TID':<8}{'StartAddress':<18}{'Module':<25}{'State':<12}{'Suspicious'}\n")
        f.write("-" * 90 + "\n")
        for pid, thread_list in threads.items():
            for t in thread_list:
                flag = "[!]" if t["suspicious"] else ""
                f.write(f"{pid:<8}{t['tid']:<8}{t['start_address']:<18}{t['module']:<25}{t['state']:<12}{flag}\n")
    
    print(f"[+] Dataset de Process Injection generado en {OUTPUT_DIR}")
    print(f"[+] Técnicas: DLL Injection, Process Hollowing, APC Injection")
    print(f"[+] Procesos: {len(processes)} ({sum(1 for p in processes if p.get('is_malicious'))} maliciosos)")


if __name__ == "__main__":
    main()
