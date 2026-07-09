#!/usr/bin/env python3
"""
generate_artifacts.py - Genera artefactos forenses simulados de Windows
Curso MAR404 - Clase 10 - Lab 19
"""
import json, os, hashlib
from datetime import datetime, timedelta

EVIDENCE_DIR = "/evidence"
os.makedirs(f"{EVIDENCE_DIR}/prefetch", exist_ok=True)
os.makedirs(f"{EVIDENCE_DIR}/amcache", exist_ok=True)
os.makedirs(f"{EVIDENCE_DIR}/registry", exist_ok=True)
os.makedirs(f"{EVIDENCE_DIR}/mft", exist_ok=True)
os.makedirs(f"{EVIDENCE_DIR}/eventlogs", exist_ok=True)

base_time = datetime(2025, 7, 20, 8, 0, 0)

# === PREFETCH FILES ===
prefetch_entries = [
    {"name": "CHROME.EXE-A1B2C3D4.pf", "exe": "CHROME.EXE", "path": "C:\\PROGRAM FILES\\GOOGLE\\CHROME\\CHROME.EXE", "run_count": 145, "last_run": (base_time + timedelta(hours=2)).isoformat(), "category": "normal"},
    {"name": "OUTLOOK.EXE-E5F6A7B8.pf", "exe": "OUTLOOK.EXE", "path": "C:\\PROGRAM FILES\\MICROSOFT OFFICE\\OUTLOOK.EXE", "run_count": 89, "last_run": (base_time + timedelta(hours=1)).isoformat(), "category": "normal"},
    {"name": "SVCHOST.EXE-C9D0E1F2.pf", "exe": "SVCHOST.EXE", "path": "C:\\USERS\\PUBLIC\\SVCHOST.EXE", "run_count": 3, "last_run": (base_time + timedelta(hours=4)).isoformat(), "category": "malicious", "note": "svchost from non-standard path"},
    {"name": "POWERSHELL.EXE-A3B4C5D6.pf", "exe": "POWERSHELL.EXE", "path": "C:\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE", "run_count": 12, "last_run": (base_time + timedelta(hours=4, minutes=5)).isoformat(), "category": "suspicious", "note": "high frequency in short time"},
    {"name": "CERTUTIL.EXE-E7F8A9B0.pf", "exe": "CERTUTIL.EXE", "path": "C:\\WINDOWS\\SYSTEM32\\CERTUTIL.EXE", "run_count": 2, "last_run": (base_time + timedelta(hours=4, minutes=2)).isoformat(), "category": "malicious", "note": "LOTL binary used for download"},
    {"name": "MIMIKATZ.EXE-F1A2B3C4.pf", "exe": "M.EXE", "path": "C:\\USERS\\ADMIN\\DESKTOP\\M.EXE", "run_count": 1, "last_run": (base_time + timedelta(hours=4, minutes=10)).isoformat(), "category": "malicious", "note": "Mimikatz renamed"},
    {"name": "CMD.EXE-D5E6F7A8.pf", "exe": "CMD.EXE", "path": "C:\\WINDOWS\\SYSTEM32\\CMD.EXE", "run_count": 45, "last_run": (base_time + timedelta(hours=4, minutes=15)).isoformat(), "category": "normal"},
    {"name": "PSEXEC.EXE-B9C0D1E2.pf", "exe": "PSEXEC.EXE", "path": "C:\\WINDOWS\\TEMP\\PSEXEC.EXE", "run_count": 1, "last_run": (base_time + timedelta(hours=5)).isoformat(), "category": "malicious", "note": "PsExec from Temp directory"},
]

with open(f"{EVIDENCE_DIR}/prefetch/prefetch_analysis.json", "w") as f:
    json.dump(prefetch_entries, f, indent=2)

# === AMCACHE ===
amcache_entries = [
    {"path": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "sha1": hashlib.sha1(b"chrome").hexdigest(), "size": 2850000, "first_run": (base_time - timedelta(days=30)).isoformat(), "publisher": "Google LLC", "category": "normal"},
    {"path": "C:\\Users\\Public\\svchost.exe", "sha1": hashlib.sha1(b"fake_svchost").hexdigest(), "size": 45056, "first_run": (base_time + timedelta(hours=3, minutes=55)).isoformat(), "publisher": "", "category": "malicious", "note": "No publisher, recent first_run, small size"},
    {"path": "C:\\Windows\\Temp\\update.dll", "sha1": hashlib.sha1(b"malicious_dll").hexdigest(), "size": 32768, "first_run": (base_time + timedelta(hours=4)).isoformat(), "publisher": "", "category": "malicious"},
    {"path": "C:\\Windows\\Temp\\PsExec.exe", "sha1": hashlib.sha1(b"psexec").hexdigest(), "size": 850000, "first_run": (base_time + timedelta(hours=5)).isoformat(), "publisher": "Sysinternals", "category": "suspicious", "note": "Legitimate tool, suspicious location"},
    {"path": "C:\\Users\\admin\\Desktop\\m.exe", "sha1": hashlib.sha1(b"mimikatz").hexdigest(), "size": 1250000, "first_run": (base_time + timedelta(hours=4, minutes=10)).isoformat(), "publisher": "", "category": "malicious", "note": "Mimikatz"},
]

with open(f"{EVIDENCE_DIR}/amcache/amcache_entries.json", "w") as f:
    json.dump(amcache_entries, f, indent=2)

# === REGISTRY (UserAssist) ===
userassist = [
    {"value_name": "{CEBFF5CD}\\C:\\Program Files\\Google\\Chrome\\chrome.exe", "run_count": 145, "last_run": (base_time + timedelta(hours=2)).isoformat(), "focus_time": 28800, "category": "normal"},
    {"value_name": "{CEBFF5CD}\\C:\\Users\\admin\\Desktop\\m.exe", "run_count": 1, "last_run": (base_time + timedelta(hours=4, minutes=10)).isoformat(), "focus_time": 30, "category": "malicious", "note": "ROT13 decoded: Mimikatz execution by admin"},
    {"value_name": "{CEBFF5CD}\\C:\\Windows\\System32\\cmd.exe", "run_count": 15, "last_run": (base_time + timedelta(hours=5)).isoformat(), "focus_time": 3600, "category": "suspicious"},
]

with open(f"{EVIDENCE_DIR}/registry/userassist.json", "w") as f:
    json.dump(userassist, f, indent=2)

# === MFT TIMELINE ===
mft_entries = [
    {"filename": "svchost.exe", "path": "C:\\Users\\Public\\", "size": 45056, "created": (base_time + timedelta(hours=3, minutes=55)).isoformat(), "modified": (base_time + timedelta(hours=3, minutes=55)).isoformat(), "accessed": (base_time + timedelta(hours=4)).isoformat(), "category": "malicious", "note": "Created same time as modified = dropped file"},
    {"filename": "update.dll", "path": "C:\\Windows\\Temp\\", "size": 32768, "created": (base_time + timedelta(hours=4)).isoformat(), "modified": (base_time + timedelta(hours=4)).isoformat(), "accessed": (base_time + timedelta(hours=4, minutes=1)).isoformat(), "category": "malicious"},
    {"filename": "info.txt", "path": "C:\\Windows\\Temp\\", "size": 2048, "created": (base_time + timedelta(hours=4, minutes=15)).isoformat(), "modified": (base_time + timedelta(hours=4, minutes=15)).isoformat(), "accessed": (base_time + timedelta(hours=4, minutes=16)).isoformat(), "category": "malicious", "note": "Recon output file"},
    {"filename": "PsExec.exe", "path": "C:\\Windows\\Temp\\", "size": 850000, "created": (base_time + timedelta(hours=5)).isoformat(), "modified": (base_time - timedelta(days=365)).isoformat(), "accessed": (base_time + timedelta(hours=5)).isoformat(), "category": "suspicious", "note": "Created timestamp != Modified = copied file (timestomping check)"},
    {"filename": "backup.7z", "path": "C:\\Windows\\Temp\\staging\\", "size": 15000000, "created": (base_time + timedelta(hours=5, minutes=30)).isoformat(), "modified": (base_time + timedelta(hours=5, minutes=30)).isoformat(), "accessed": (base_time + timedelta(hours=5, minutes=31)).isoformat(), "category": "malicious", "note": "Data staging for exfiltration"},
]

with open(f"{EVIDENCE_DIR}/mft/mft_timeline.json", "w") as f:
    json.dump(mft_entries, f, indent=2)

print("[+] Forensic artifacts generated in /evidence/")
print(f"    - Prefetch: {len(prefetch_entries)} entries")
print(f"    - Amcache: {len(amcache_entries)} entries")
print(f"    - UserAssist: {len(userassist)} entries")
print(f"    - MFT: {len(mft_entries)} entries")
