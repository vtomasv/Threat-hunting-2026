#!/usr/bin/env python3
"""
generate_zeus_dataset.py
========================
Genera dataset simulando infección de Zeus/Zbot en memoria:
- Proceso inyectado (explorer.exe)
- API hooks en ntdll.dll y wininet.dll
- Configuración cifrada con URLs de C2
- Mutex y registry persistence
- Conexiones HTTP a C2

Curso MAR404 - Clase 6
"""
import json, os, base64
from datetime import datetime, timedelta

OUTPUT_DIR = "/data"

def generate_processes():
    boot = datetime(2025, 6, 5, 9, 0, 0)
    return [
        {"pid": 4, "ppid": 0, "name": "System", "path": "N/A",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 180, "handles": 2500},
        {"pid": 400, "ppid": 4, "name": "smss.exe", "path": "C:\\Windows\\System32\\smss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 2, "handles": 30},
        {"pid": 560, "ppid": 400, "name": "csrss.exe", "path": "C:\\Windows\\System32\\csrss.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 12, "handles": 500},
        {"pid": 620, "ppid": 400, "name": "wininit.exe", "path": "C:\\Windows\\System32\\wininit.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 3, "handles": 80},
        {"pid": 680, "ppid": 620, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 8, "handles": 300},
        {"pid": 700, "ppid": 620, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "threads": 10, "handles": 800},
        {"pid": 800, "ppid": 680, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe",
         "user": "NT AUTHORITY\\SYSTEM", "create_time": boot.isoformat(),
         "cmdline": "svchost.exe -k DcomLaunch -p", "threads": 25, "handles": 1200},
        {"pid": 2200, "ppid": 2100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe",
         "user": "BANK\\teller01", "create_time": (boot + timedelta(minutes=3)).isoformat(),
         "threads": 38, "handles": 1700,
         "note": "INFECTADO con Zeus - inyección + API hooks"},
        {"pid": 3100, "ppid": 2200, "name": "iexplore.exe",
         "path": "C:\\Program Files\\Internet Explorer\\iexplore.exe",
         "user": "BANK\\teller01", "create_time": (boot + timedelta(minutes=10)).isoformat(),
         "threads": 20, "handles": 600,
         "note": "Navegador con hooks de Zeus para captura de credenciales"},
        {"pid": 3500, "ppid": 2200, "name": "chrome.exe",
         "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "user": "BANK\\teller01", "create_time": (boot + timedelta(minutes=15)).isoformat(),
         "threads": 30, "handles": 500},
    ]


def generate_hooks():
    """Genera datos de API hooks instalados por Zeus."""
    return {
        "hooked_processes": [2200, 3100],
        "hooks": [
            {
                "pid": 2200,
                "process": "explorer.exe",
                "module": "ntdll.dll",
                "function": "NtQueryDirectoryFile",
                "hook_type": "Inline/Trampoline",
                "original_bytes": "4c 8b d1 b8 35 00 00 00",
                "hooked_bytes": "e9 xx xx xx xx 90 90 90",
                "hook_address": "0x7FFE1234ABCD",
                "destination": "0x02001000 (injected region)",
                "purpose": "Ocultar archivos del malware en disco",
                "mitre": "T1564.001 - Hidden Files and Directories"
            },
            {
                "pid": 3100,
                "process": "iexplore.exe",
                "module": "wininet.dll",
                "function": "HttpSendRequestW",
                "hook_type": "Inline/Trampoline",
                "original_bytes": "48 89 5c 24 08 48 89 6c",
                "hooked_bytes": "e9 xx xx xx xx 90 90 90",
                "hook_address": "0x7FFE5678DCBA",
                "destination": "0x03001000 (injected region)",
                "purpose": "Interceptar credenciales bancarias en formularios HTTP",
                "mitre": "T1056.004 - Credential API Hooking"
            },
            {
                "pid": 3100,
                "process": "iexplore.exe",
                "module": "wininet.dll",
                "function": "InternetReadFile",
                "hook_type": "Inline/Trampoline",
                "original_bytes": "48 83 ec 38 48 8b 44 24",
                "hooked_bytes": "e9 xx xx xx xx 90 90 90",
                "hook_address": "0x7FFE5678EFGH",
                "destination": "0x03002000 (injected region)",
                "purpose": "Modificar respuestas HTTP para inyectar campos en páginas bancarias",
                "mitre": "T1185 - Browser Session Hijacking"
            },
            {
                "pid": 2200,
                "process": "explorer.exe",
                "module": "ntdll.dll",
                "function": "NtCreateFile",
                "hook_type": "Inline/Trampoline",
                "original_bytes": "4c 8b d1 b8 55 00 00 00",
                "hooked_bytes": "e9 xx xx xx xx 90 90 90",
                "hook_address": "0x7FFE1234CDEF",
                "destination": "0x02002000 (injected region)",
                "purpose": "Monitorear acceso a archivos y exfiltrar documentos sensibles",
                "mitre": "T1005 - Data from Local System"
            },
        ]
    }


def generate_zeus_config():
    """Genera la configuración descifrada de Zeus."""
    config = {
        "botnet_id": "zeus_bank_latam_2025",
        "version": "2.1.0.4",
        "encryption": "RC4",
        "rc4_key_hex": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "c2_urls": [
            {"url": "http://185.220.101.45/gate.php", "type": "primary", "status": "active"},
            {"url": "http://91.215.85.100/panel/gate.php", "type": "secondary", "status": "active"},
            {"url": "http://203.0.113.200/zs/gate.php", "type": "fallback", "status": "inactive"},
        ],
        "dga_seed": "zeus2025latam",
        "dga_domains_sample": [
            "xkjr8m2p.com", "q9wn4t5v.net", "m3hb7y6k.org",
            "p2vc8x1n.com", "t7wq3j9f.net"
        ],
        "targets": [
            {"url_pattern": "*banco-estado.cl*", "action": "inject_form", "fields": ["rut", "clave", "coordenadas"]},
            {"url_pattern": "*santander.cl/trx*", "action": "inject_form", "fields": ["rut", "password", "token"]},
            {"url_pattern": "*bci.cl/personas*", "action": "screenshot", "fields": []},
            {"url_pattern": "*bancofalabella.cl*", "action": "inject_form", "fields": ["email", "password"]},
            {"url_pattern": "*paypal.com/signin*", "action": "inject_form", "fields": ["email", "password"]},
        ],
        "persistence": {
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "SysUpdate",
            "registry_data": "C:\\Users\\teller01\\AppData\\Roaming\\Microsoft\\svchost.exe",
            "mutex": "__SYSTEM__91827364",
            "install_path": "C:\\Users\\teller01\\AppData\\Roaming\\Microsoft\\svchost.exe",
        },
        "exfil": {
            "method": "HTTP POST",
            "encoding": "base64 + RC4",
            "interval_seconds": 300,
            "data_types": ["credentials", "screenshots", "keylog", "cookies"],
        }
    }
    return config


def generate_connections():
    return [
        {"pid": 800, "proto": "TCPv4", "local": "192.168.10.100:49800",
         "remote": "20.190.159.4:443", "state": "ESTABLISHED",
         "is_malicious": False, "notes": "Windows Update"},
        {"pid": 3100, "proto": "TCPv4", "local": "192.168.10.100:50100",
         "remote": "142.250.80.46:443", "state": "ESTABLISHED",
         "is_malicious": False, "notes": "Chrome → Google"},
        {"pid": 2200, "proto": "TCPv4", "local": "192.168.10.100:51234",
         "remote": "185.220.101.45:80", "state": "ESTABLISHED",
         "is_malicious": True, "notes": "explorer.exe → Zeus C2 primary (gate.php)"},
        {"pid": 2200, "proto": "TCPv4", "local": "192.168.10.100:51500",
         "remote": "91.215.85.100:80", "state": "CLOSE_WAIT",
         "is_malicious": True, "notes": "explorer.exe → Zeus C2 secondary"},
        {"pid": 3100, "proto": "TCPv4", "local": "192.168.10.100:52000",
         "remote": "200.14.226.20:443", "state": "ESTABLISHED",
         "is_malicious": False, "notes": "iexplore → banco-estado.cl (sesión legítima hookeada)"},
    ]


def generate_registry():
    """Genera artefactos de persistencia en registry."""
    return [
        {
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value": "SysUpdate",
            "data": "C:\\Users\\teller01\\AppData\\Roaming\\Microsoft\\svchost.exe",
            "type": "REG_SZ",
            "suspicious": True,
            "notes": "Persistencia de Zeus - ejecutable en AppData con nombre de sistema"
        },
        {
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value": "OneDrive",
            "data": "C:\\Users\\teller01\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            "type": "REG_SZ",
            "suspicious": False,
            "notes": "OneDrive legítimo"
        },
    ]


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    processes = generate_processes()
    hooks = generate_hooks()
    config = generate_zeus_config()
    connections = generate_connections()
    registry = generate_registry()
    
    with open(f"{OUTPUT_DIR}/processes.json", "w") as f:
        json.dump(processes, f, indent=2)
    with open(f"{OUTPUT_DIR}/hooks.json", "w") as f:
        json.dump(hooks, f, indent=2)
    with open(f"{OUTPUT_DIR}/zeus_config.json", "w") as f:
        json.dump(config, f, indent=2)
    with open(f"{OUTPUT_DIR}/connections.json", "w") as f:
        json.dump(connections, f, indent=2)
    with open(f"{OUTPUT_DIR}/registry.json", "w") as f:
        json.dump(registry, f, indent=2)
    
    # Generar salida tipo Volatility
    with open(f"{OUTPUT_DIR}/vol3_pslist.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.pslist.PsList\n\n")
        f.write(f"{'PID':<8}{'PPID':<8}{'ImageFileName':<20}{'CreateTime':<28}{'Threads':<10}{'Handles'}\n")
        f.write("-" * 90 + "\n")
        for p in processes:
            f.write(f"{p['pid']:<8}{p['ppid']:<8}{p['name']:<20}{p['create_time']:<28}{p['threads']:<10}{p['handles']}\n")
    
    # Simular salida de apihooks
    with open(f"{OUTPUT_DIR}/vol3_apihooks.txt", "w") as f:
        f.write("Volatility 3 Framework 2.5.0\nPlugin: windows.apihooks (custom)\n\n")
        for hook in hooks["hooks"]:
            f.write(f"Process: {hook['process']} (PID {hook['pid']})\n")
            f.write(f"Module: {hook['module']} | Function: {hook['function']}\n")
            f.write(f"Hook Type: {hook['hook_type']}\n")
            f.write(f"Hook Address: {hook['hook_address']}\n")
            f.write(f"Destination: {hook['destination']}\n")
            f.write(f"Original: {hook['original_bytes']}\n")
            f.write(f"Hooked:   {hook['hooked_bytes']}\n")
            f.write("-" * 60 + "\n\n")
    
    # Config cifrada (simulada)
    config_plain = json.dumps(config["c2_urls"] + config["targets"], indent=2)
    config_b64 = base64.b64encode(config_plain.encode()).decode()
    with open(f"{OUTPUT_DIR}/zeus_encrypted_config.bin", "w") as f:
        f.write(f"# Zeus encrypted config blob (RC4 + Base64)\n")
        f.write(f"# Key (hex): {config['rc4_key_hex']}\n")
        f.write(f"# Decoded content saved to zeus_config.json\n\n")
        f.write(config_b64)
    
    print(f"[+] Dataset de Zeus Botnet generado en {OUTPUT_DIR}")
    print(f"[+] Procesos: {len(processes)}")
    print(f"[+] API Hooks: {len(hooks['hooks'])}")
    print(f"[+] C2 URLs: {len(config['c2_urls'])}")
    print(f"[+] Banking targets: {len(config['targets'])}")


if __name__ == "__main__":
    main()
