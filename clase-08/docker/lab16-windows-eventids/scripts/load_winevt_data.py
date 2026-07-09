#!/usr/bin/env python3
"""
load_winevt_data.py - Genera y carga Windows Security Events para correlación
Incluye: Brute Force, Pass-the-Hash, Service Install, Log Tampering
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

def generate_events():
    base_time = datetime(2025, 7, 21, 6, 0, 0)
    events = []
    
    # Normal logons (200 events)
    users = ["CORP\\user01", "CORP\\user02", "CORP\\admin", "CORP\\svc_backup"]
    workstations = ["WS-001", "WS-002", "WS-003", "SRV-DC01"]
    
    for i in range(200):
        t = base_time + timedelta(minutes=random.randint(0, 720))
        events.append({
            "event_id": 4624, "timestamp": t.isoformat(),
            "logon_type": random.choice([2, 3, 7, 10]),
            "target_user": random.choice(users),
            "source_workstation": random.choice(workstations),
            "source_ip": f"10.0.1.{random.randint(10,50)}",
            "category": "normal", "severity": "info"
        })
    
    # === ATTACK SCENARIO 1: Brute Force ===
    brute_time = base_time + timedelta(hours=3)
    # 50 failed logons in 2 minutes
    for i in range(50):
        t = brute_time + timedelta(seconds=random.randint(0, 120))
        events.append({
            "event_id": 4625, "timestamp": t.isoformat(),
            "logon_type": 3, "failure_reason": "Unknown user name or bad password",
            "target_user": "CORP\\admin",
            "source_workstation": "UNKNOWN",
            "source_ip": "10.0.1.200",
            "category": "brute_force", "severity": "high",
            "mitre": "T1110.001"
        })
    # Successful logon after brute force
    events.append({
        "event_id": 4624, "timestamp": (brute_time + timedelta(minutes=3)).isoformat(),
        "logon_type": 3,
        "target_user": "CORP\\admin",
        "source_workstation": "UNKNOWN",
        "source_ip": "10.0.1.200",
        "category": "brute_force_success", "severity": "critical",
        "mitre": "T1110.001"
    })
    
    # === ATTACK SCENARIO 2: Pass-the-Hash ===
    pth_time = base_time + timedelta(hours=5)
    events.append({
        "event_id": 4624, "timestamp": pth_time.isoformat(),
        "logon_type": 9, "logon_process": "seclogo",
        "target_user": "CORP\\admin",
        "source_workstation": "WS-001",
        "source_ip": "10.0.1.15",
        "category": "pass_the_hash", "severity": "critical",
        "mitre": "T1550.002",
        "hunt_note": "Logon Type 9 (NewCredentials) + seclogo = Pass-the-Hash indicator"
    })
    events.append({
        "event_id": 4648, "timestamp": (pth_time + timedelta(seconds=2)).isoformat(),
        "subject_user": "CORP\\user01",
        "target_user": "CORP\\admin",
        "target_server": "SRV-DC01",
        "process_name": "C:\\Windows\\System32\\svchost.exe",
        "category": "pass_the_hash", "severity": "critical",
        "mitre": "T1550.002",
        "hunt_note": "Explicit credential logon - user01 using admin credentials"
    })
    
    # === ATTACK SCENARIO 3: Malicious Service ===
    svc_time = base_time + timedelta(hours=6)
    events.append({
        "event_id": 7045, "timestamp": svc_time.isoformat(),
        "service_name": "WindowsUpdateSvc",
        "service_file": "C:\\Windows\\Temp\\svc.exe",
        "service_type": "user mode service",
        "service_start_type": "auto start",
        "service_account": "LocalSystem",
        "category": "persistence", "severity": "critical",
        "mitre": "T1543.003",
        "hunt_note": "Service binary in Temp directory with LocalSystem privileges"
    })
    events.append({
        "event_id": 4697, "timestamp": (svc_time + timedelta(seconds=1)).isoformat(),
        "service_name": "WindowsUpdateSvc",
        "service_file": "C:\\Windows\\Temp\\svc.exe",
        "subject_user": "CORP\\admin",
        "category": "persistence", "severity": "critical",
        "mitre": "T1543.003"
    })
    
    # === ATTACK SCENARIO 4: Log Tampering ===
    events.append({
        "event_id": 1102, "timestamp": (base_time + timedelta(hours=7)).isoformat(),
        "subject_user": "CORP\\admin",
        "subject_domain": "CORP",
        "category": "defense_evasion", "severity": "critical",
        "mitre": "T1070.001",
        "hunt_note": "Security audit log was cleared - anti-forensics"
    })
    
    # === ATTACK SCENARIO 5: Account manipulation ===
    events.append({
        "event_id": 4720, "timestamp": (base_time + timedelta(hours=5, minutes=30)).isoformat(),
        "target_user": "CORP\\svc_update$",
        "subject_user": "CORP\\admin",
        "category": "persistence", "severity": "high",
        "mitre": "T1136.001",
        "hunt_note": "New account created with $ suffix (hidden account)"
    })
    events.append({
        "event_id": 4732, "timestamp": (base_time + timedelta(hours=5, minutes=31)).isoformat(),
        "target_user": "CORP\\svc_update$",
        "group_name": "Administrators",
        "subject_user": "CORP\\admin",
        "category": "privilege_escalation", "severity": "critical",
        "mitre": "T1098",
        "hunt_note": "Hidden account added to Administrators group"
    })
    
    return events

def main():
    es = wait_for_es()
    
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "event_id": {"type": "integer"},
                "logon_type": {"type": "integer"},
                "target_user": {"type": "keyword"},
                "subject_user": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "source_workstation": {"type": "keyword"},
                "service_name": {"type": "keyword"},
                "service_file": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "category": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "mitre": {"type": "keyword"},
            }
        }
    }
    
    es.indices.delete(index=INDEX, ignore=[404])
    es.indices.create(index=INDEX, body=mapping)
    
    events = generate_events()
    for event in events:
        es.index(index=INDEX, document=event)
    
    es.indices.refresh(index=INDEX)
    print(f"[+] Loaded {len(events)} Windows Security events into '{INDEX}'")
    print(f"[+] Attack scenarios: Brute Force, Pass-the-Hash, Malicious Service, Log Tampering, Account Manipulation")

if __name__ == "__main__":
    main()
