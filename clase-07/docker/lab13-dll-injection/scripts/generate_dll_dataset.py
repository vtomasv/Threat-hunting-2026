#!/usr/bin/env python3
"""
generate_dll_dataset.py
=======================
Genera dataset simulando DLL Side-Loading + Troyano con múltiples capacidades.
Escenario: OneDriveUpdater.exe carga version.dll maliciosa (side-loading)

Curso MAR404 - Clase 7
"""
import json, os
from datetime import datetime, timedelta

OUTPUT_DIR = "/data"

def generate_processes():
    boot = datetime(2025, 7, 10, 8, 0, 0)
    compromise = boot + timedelta(hours=2, minutes=15)
    return [
        {"pid": 4, "ppid": 0, "name": "System", "path": "N/A",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 400, "ppid": 4, "name": "smss.exe", "path": "C:\\Windows\\System32\\smss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 560, "ppid": 400, "name": "csrss.exe", "path": "C:\\Windows\\System32\\csrss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 680, "ppid": 560, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 700, "ppid": 560, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 800, "ppid": 680, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "cmdline": "svchost.exe -k DcomLaunch -p"},
        {"pid": 2200, "ppid": 2100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
         "user": "CORP\\admin01", "create_time": (boot + timedelta(minutes=3)).isoformat()},
        
        # Proceso legítimo de OneDrive (side-loading target)
        {"pid": 3800, "ppid": 680, "name": "OneDriveUpdater.exe",
         "path": "C:\\Users\\admin01\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveUpdater.exe",
         "user": "CORP\\admin01", "create_time": compromise.isoformat(),
         "cmdline": "OneDriveUpdater.exe /update /silent",
         "threads": 8, "handles": 250,
         "is_malicious": True,
         "technique": "T1574.002 - DLL Side-Loading",
         "note": "Proceso legítimo que cargó version.dll maliciosa (side-loading)"},
        
        # Scheduled task para persistencia
        {"pid": 4200, "ppid": 800, "name": "schtasks.exe",
         "path": "C:\\Windows\\System32\\schtasks.exe",
         "user": "NT AUTHORITY\\SYSTEM",
         "create_time": (compromise + timedelta(minutes=5)).isoformat(),
         "cmdline": "schtasks /create /tn \"OneDrive Update\" /tr \"C:\\Users\\admin01\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveUpdater.exe /update /silent\" /sc hourly",
         "is_malicious": True,
         "technique": "T1053.005 - Scheduled Task",
         "note": "Crea tarea para persistencia del side-loading"},
        
        # Keylogger thread (dentro de OneDriveUpdater)
        {"pid": 4500, "ppid": 3800, "name": "conhost.exe",
         "path": "C:\\Windows\\System32\\conhost.exe",
         "user": "CORP\\admin01",
         "create_time": (compromise + timedelta(minutes=2)).isoformat(),
         "is_malicious": True,
         "note": "Spawned por troyano para captura de clipboard"},
    ]


def generate_dll_data():
    """Genera datos de DLLs cargadas por OneDriveUpdater."""
    return {
        3800: {
            "loaded_dlls": [
                {"name": "ntdll.dll", "path": "C:\\Windows\\System32\\ntdll.dll",
                 "base": "0x7FFE00000000", "size": 2048000, "signed": True,
                 "signer": "Microsoft Windows", "suspicious": False},
                {"name": "kernel32.dll", "path": "C:\\Windows\\System32\\kernel32.dll",
                 "base": "0x7FFE10000000", "size": 1200000, "signed": True,
                 "signer": "Microsoft Windows", "suspicious": False},
                {"name": "version.dll",
                 "path": "C:\\Users\\admin01\\AppData\\Local\\Microsoft\\OneDrive\\version.dll",
                 "base": "0x10000000", "size": 245760, "signed": False,
                 "signer": "N/A",
                 "suspicious": True,
                 "notes": "DLL Side-Loading: version.dll en directorio de OneDrive en lugar de System32",
                 "legitimate_path": "C:\\Windows\\System32\\version.dll",
                 "exports": ["GetFileVersionInfoA", "GetFileVersionInfoW",
                            "VerQueryValueA", "VerQueryValueW",
                            "DllMain", "ServiceCallback", "KeylogStart"],
                 "suspicious_exports": ["ServiceCallback", "KeylogStart"],
                 "imports_suspicious": ["ws2_32.dll!connect", "ws2_32.dll!send",
                                       "user32.dll!SetWindowsHookExA",
                                       "user32.dll!GetClipboardData",
                                       "gdi32.dll!BitBlt",
                                       "advapi32.dll!RegSetValueExA"],
                 "strings": [
                     "http://198.51.100.50/collect",
                     "keylog_%Y%m%d_%H%M.dat",
                     "screenshot_%Y%m%d_%H%M.png",
                     "CORP\\\\",
                     "password", "credential", "token",
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                 ]},
                {"name": "OneDriveClient.dll",
                 "path": "C:\\Users\\admin01\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveClient.dll",
                 "base": "0x20000000", "size": 5000000, "signed": True,
                 "signer": "Microsoft Corporation", "suspicious": False},
            ],
            "vad_suspicious": [
                {"start": "0x10000000", "end": "0x1003BFFF",
                 "protection": "PAGE_EXECUTE_READ",
                 "type": "Mapped",
                 "file": "\\Users\\admin01\\AppData\\Local\\Microsoft\\OneDrive\\version.dll",
                 "notes": "DLL maliciosa cargada - exports legítimos + maliciosos"},
                {"start": "0x30000000", "end": "0x3000FFFF",
                 "protection": "PAGE_EXECUTE_READWRITE",
                 "type": "Private", "file": None,
                 "notes": "Región RWX adicional - posible shellcode o config descifrada",
                 "hex_dump": "48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 ..."},
            ]
        }
    }


def generate_trojan_capabilities():
    """Genera datos de las capacidades del troyano."""
    return {
        "trojan_profile": {
            "name": "SilentDrop RAT",
            "family": "Custom RAT (likely APT-linked)",
            "delivery": "DLL Side-Loading via OneDriveUpdater.exe",
            "capabilities": [
                {
                    "name": "Keylogger",
                    "technique": "SetWindowsHookExA (WH_KEYBOARD_LL)",
                    "mitre": "T1056.001 - Keylogging",
                    "output_file": "C:\\Users\\admin01\\AppData\\Local\\Temp\\~DF8A2B.tmp",
                    "evidence": "Import of user32.dll!SetWindowsHookExA + keylog format string"
                },
                {
                    "name": "Screenshot Capture",
                    "technique": "BitBlt from desktop DC",
                    "mitre": "T1113 - Screen Capture",
                    "output_file": "C:\\Users\\admin01\\AppData\\Local\\Temp\\~DF8A2C.tmp",
                    "evidence": "Import of gdi32.dll!BitBlt + screenshot format string"
                },
                {
                    "name": "Clipboard Monitor",
                    "technique": "GetClipboardData polling",
                    "mitre": "T1115 - Clipboard Data",
                    "output_file": "in-memory buffer",
                    "evidence": "Import of user32.dll!GetClipboardData + conhost.exe child"
                },
                {
                    "name": "Data Exfiltration",
                    "technique": "HTTP POST to C2",
                    "mitre": "T1041 - Exfiltration Over C2 Channel",
                    "c2_url": "http://198.51.100.50/collect",
                    "interval": "every 300 seconds",
                    "encoding": "XOR + Base64"
                },
                {
                    "name": "Persistence",
                    "technique": "Scheduled Task (hourly)",
                    "mitre": "T1053.005 - Scheduled Task",
                    "task_name": "OneDrive Update",
                    "evidence": "schtasks.exe child process with /create flag"
                }
            ]
        },
        "network_connections": [
            {"pid": 3800, "remote": "198.51.100.50:80", "state": "ESTABLISHED",
             "notes": "C2 - exfiltración de keylog/screenshots"},
            {"pid": 3800, "remote": "198.51.100.50:443", "state": "CLOSE_WAIT",
             "notes": "C2 secundario (HTTPS fallback)"},
        ],
        "persistence": [
            {"type": "Scheduled Task", "name": "OneDrive Update",
             "action": "C:\\Users\\admin01\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveUpdater.exe /update /silent",
             "trigger": "Hourly", "suspicious": True},
        ]
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    processes = generate_processes()
    dll_data = generate_dll_data()
    trojan = generate_trojan_capabilities()
    
    with open(f"{OUTPUT_DIR}/processes.json", "w") as f:
        json.dump(processes, f, indent=2)
    with open(f"{OUTPUT_DIR}/dll_data.json", "w") as f:
        json.dump(dll_data, f, indent=2)
    with open(f"{OUTPUT_DIR}/trojan_profile.json", "w") as f:
        json.dump(trojan, f, indent=2)
    
    # Generar salida tipo Volatility
    with open(f"{OUTPUT_DIR}/vol3_pslist.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.pslist.PsList\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<25}{'CreateTime':<28}{'User'}\n")
        f.write("-" * 100 + "\n")
        for p in processes:
            f.write(f"{p['pid']:<8}{p['ppid']:<8}{p['name']:<25}{p['create_time']:<28}{p.get('user','')}\n")
    
    with open(f"{OUTPUT_DIR}/vol3_dlllist.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.dlllist.DllList\n\n")
        for pid, data in dll_data.items():
            proc = next((p for p in processes if p["pid"] == pid), None)
            f.write(f"PID: {pid} ({proc['name'] if proc else 'Unknown'})\n")
            f.write(f"{'Base':<18}{'Size':<12}{'Name':<25}{'Path'}\n")
            f.write("-" * 90 + "\n")
            for dll in data["loaded_dlls"]:
                flag = " [!]" if dll["suspicious"] else ""
                f.write(f"{dll['base']:<18}{dll['size']:<12}{dll['name']:<25}{dll['path']}{flag}\n")
            f.write("\n")
    
    print(f"[+] Dataset de DLL Injection + Trojan generado en {OUTPUT_DIR}")
    print(f"[+] Procesos: {len(processes)}")
    print(f"[+] DLL Side-Loading: version.dll en OneDrive path")
    print(f"[+] Trojan capabilities: {len(trojan['trojan_profile']['capabilities'])}")


if __name__ == "__main__":
    main()
