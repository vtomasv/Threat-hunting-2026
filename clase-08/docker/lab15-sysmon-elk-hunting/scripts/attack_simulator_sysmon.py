#!/usr/bin/env python3
"""
attack_simulator_sysmon.py - Simulador de ataques en vivo para Lab 15
Inyecta eventos Sysmon en Elasticsearch que pueden ser consultados en Kibana.
Curso MAR404 - Clase 8 - Lab 15

Uso:
    simulate list              # Listar escenarios disponibles
    simulate <scenario>        # Ejecutar un escenario específico
    simulate all               # Ejecutar todos los escenarios
    simulate reset             # Limpiar eventos simulados
"""
import sys, json, time, random, hashlib
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200"
INDEX = "sysmon-hunting"

SCENARIOS = {
    "process_hollowing": {
        "name": "Process Hollowing (T1055.012)",
        "description": "Svchost.exe legítimo es vaciado y reemplazado con código malicioso",
        "mitre": "T1055.012",
        "tactic": "Defense Evasion"
    },
    "dll_sideloading": {
        "name": "DLL Side-Loading (T1574.002)",
        "description": "Aplicación legítima carga DLL maliciosa desde su directorio",
        "mitre": "T1574.002",
        "tactic": "Persistence"
    },
    "kerberoasting": {
        "name": "Kerberoasting (T1558.003)",
        "description": "Solicitud masiva de tickets TGS para crackeo offline",
        "mitre": "T1558.003",
        "tactic": "Credential Access"
    },
    "dcsync": {
        "name": "DCSync Attack (T1003.006)",
        "description": "Replicación de credenciales del Domain Controller",
        "mitre": "T1003.006",
        "tactic": "Credential Access"
    },
    "ransomware": {
        "name": "Ransomware Execution (T1486)",
        "description": "Cifrado masivo de archivos + eliminación de shadow copies",
        "mitre": "T1486",
        "tactic": "Impact"
    },
    "fileless_wmi": {
        "name": "Fileless WMI Persistence (T1546.003)",
        "description": "Suscripción WMI permanente para ejecución sin archivos",
        "mitre": "T1546.003",
        "tactic": "Persistence"
    },
    "cobalt_strike": {
        "name": "Cobalt Strike Beacon (T1071.001)",
        "description": "Beacon HTTPS con sleep jitter y named pipe",
        "mitre": "T1071.001",
        "tactic": "Command and Control"
    },
    "token_manipulation": {
        "name": "Token Manipulation (T1134.001)",
        "description": "Robo de token de SYSTEM para escalamiento de privilegios",
        "mitre": "T1134.001",
        "tactic": "Privilege Escalation"
    },
    "amsi_bypass": {
        "name": "AMSI Bypass (T1562.001)",
        "description": "Parcheo de AmsiScanBuffer para evadir detección",
        "mitre": "T1562.001",
        "tactic": "Defense Evasion"
    },
    "ntds_dump": {
        "name": "NTDS.dit Dump (T1003.003)",
        "description": "Extracción de la base de datos de Active Directory",
        "mitre": "T1003.003",
        "tactic": "Credential Access"
    },
}


def get_es():
    return Elasticsearch(ES_HOST)


def now_iso():
    return datetime.utcnow().isoformat()


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def inject_events(es, events):
    """Inyecta una lista de eventos en Elasticsearch."""
    for event in events:
        event["simulated"] = True
        event["simulated_at"] = now_iso()
        es.index(index=INDEX, document=event)
    es.indices.refresh(index=INDEX)
    return len(events)


def simulate_process_hollowing(es):
    """Simula Process Hollowing en svchost.exe"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "svchost.exe",
            "image": r"C:\Windows\System32\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 11200,
            "parent_image": r"C:\Windows\System32\services.exe",
            "parent_pid": 600, "parent_name": "services.exe",
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "integrity_level": "System",
            "category": "injection", "severity": "critical",
            "mitre_tactic": "Defense Evasion", "mitre_technique": "T1055.012",
            "attack_chain": "process_hollowing_sim",
            "hunt_note": "CREATE_SUSPENDED flag - proceso creado en estado suspendido"
        },
        {
            "event_id": 10, "event_description": "Process Access",
            "timestamp": (base_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
            "source_image": r"C:\Users\Public\Downloads\legit_app.exe",
            "source_pid": 11100, "source_name": "legit_app.exe",
            "target_image": r"C:\Windows\System32\svchost.exe",
            "target_pid": 11200, "target_name": "svchost.exe",
            "granted_access": "0x1FFFFF",
            "call_trace": r"C:\Windows\SYSTEM32\ntdll.dll+A1234|C:\Users\Public\Downloads\legit_app.exe+1B00",
            "user": "CORP\\admin",
            "category": "injection", "severity": "critical",
            "mitre_tactic": "Defense Evasion", "mitre_technique": "T1055.012",
            "attack_chain": "process_hollowing_sim",
            "hunt_note": "FULL_ACCESS a svchost.exe desde proceso no estándar - NtUnmapViewOfSection + NtWriteVirtualMemory"
        },
        {
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (base_time + timedelta(seconds=5)).isoformat(), "hostname": "WS-PC01",
            "process_name": "svchost.exe",
            "image": r"C:\Windows\System32\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 11200,
            "destination_ip": "45.77.65.211", "destination_port": 443,
            "destination_hostname": "update-service.cloud-cdn.net",
            "source_ip": "10.0.1.50", "source_port": 55100,
            "protocol": "tcp", "initiated": True,
            "category": "c2", "severity": "critical",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "attack_chain": "process_hollowing_sim",
            "hunt_note": "svchost.exe (-k netsvcs) haciendo conexión HTTPS a IP externa - ANOMALOUS"
        },
    ]
    return inject_events(es, events)


def simulate_dll_sideloading(es):
    """Simula DLL Side-Loading via aplicación legítima"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "OneDriveStandaloneUpdater.exe",
            "image": r"C:\Users\user01\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
            "user": "CORP\\user01", "pid": 11300,
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_pid": 2400, "parent_name": "explorer.exe",
            "command_line": r"C:\Users\user01\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
            "integrity_level": "Medium",
            "category": "persistence", "severity": "high",
            "mitre_tactic": "Persistence", "mitre_technique": "T1574.002",
            "attack_chain": "dll_sideloading_sim"
        },
        {
            "event_id": 7, "event_description": "Image Loaded",
            "timestamp": (base_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
            "process_name": "OneDriveStandaloneUpdater.exe",
            "image": r"C:\Users\user01\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
            "user": "CORP\\user01", "pid": 11300,
            "image_loaded": r"C:\Users\user01\AppData\Local\Microsoft\OneDrive\version.dll",
            "hashes": f"SHA256={sha256('malicious_version_dll')}",
            "signed": False, "signature": "N/A", "signature_status": "Unavailable",
            "category": "persistence", "severity": "critical",
            "mitre_tactic": "Persistence", "mitre_technique": "T1574.002",
            "attack_chain": "dll_sideloading_sim",
            "hunt_note": "version.dll NO FIRMADA cargada por OneDrive - posible DLL Side-Loading"
        },
        {
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (base_time + timedelta(seconds=3)).isoformat(), "hostname": "WS-PC01",
            "process_name": "OneDriveStandaloneUpdater.exe",
            "image": r"C:\Users\user01\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
            "user": "CORP\\user01", "pid": 11300,
            "destination_ip": "91.215.85.142", "destination_port": 8443,
            "destination_hostname": "api-gateway.cloud-services.io",
            "source_ip": "10.0.1.50", "source_port": 55200,
            "protocol": "tcp", "initiated": True,
            "category": "c2", "severity": "critical",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "attack_chain": "dll_sideloading_sim",
            "hunt_note": "OneDrive conectando a puerto no estándar 8443 en IP desconocida"
        },
    ]
    return inject_events(es, events)


def simulate_kerberoasting(es):
    """Simula Kerberoasting - solicitud masiva de TGS tickets"""
    base_time = datetime.utcnow()
    events = []
    # Múltiples solicitudes TGS en ráfaga
    spn_targets = ["MSSQLSvc/sql01.corp.local:1433", "HTTP/web01.corp.local",
                   "CIFS/fs01.corp.local", "MSSQLSvc/sql02.corp.local:1433",
                   "HTTP/intranet.corp.local", "FTP/ftp01.corp.local"]
    events.append({
        "event_id": 1, "event_description": "Process Create",
        "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
        "process_name": "powershell.exe",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "user": "CORP\\user01", "pid": 11400,
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "parent_pid": 8750, "parent_name": "cmd.exe",
        "command_line": r'powershell.exe -exec bypass -c "Import-Module .\Invoke-Kerberoast.ps1; Invoke-Kerberoast -OutputFormat Hashcat"',
        "integrity_level": "Medium",
        "category": "credential_access", "severity": "critical",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1558.003",
        "attack_chain": "kerberoasting_sim",
        "hunt_note": "Invoke-Kerberoast ejecutado - solicitud masiva de tickets TGS"
    })
    for i, spn in enumerate(spn_targets):
        events.append({
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (base_time + timedelta(seconds=i+1)).isoformat(), "hostname": "WS-PC01",
            "process_name": "powershell.exe",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "user": "CORP\\user01", "pid": 11400,
            "destination_ip": "10.0.1.1", "destination_port": 88,
            "destination_hostname": "dc01.corp.local",
            "source_ip": "10.0.1.50", "source_port": 55300 + i,
            "protocol": "tcp", "initiated": True,
            "category": "credential_access", "severity": "high",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1558.003",
            "attack_chain": "kerberoasting_sim",
            "hunt_note": f"TGS request for SPN: {spn}"
        })
    return inject_events(es, events)


def simulate_dcsync(es):
    """Simula DCSync - replicación de credenciales"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "lsass.exe",
            "image": r"C:\Windows\System32\lsass.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 680,
            "parent_image": r"C:\Windows\System32\wininit.exe",
            "parent_pid": 500, "parent_name": "wininit.exe",
            "command_line": r"C:\Windows\System32\lsass.exe",
            "integrity_level": "System",
            "category": "credential_access", "severity": "info",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1003.006",
            "attack_chain": "dcsync_sim"
        },
        {
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (base_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
            "process_name": "lsass.exe",
            "image": r"C:\Windows\System32\lsass.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 680,
            "destination_ip": "10.0.1.1", "destination_port": 389,
            "destination_hostname": "dc01.corp.local",
            "source_ip": "10.0.1.50", "source_port": 55400,
            "protocol": "tcp", "initiated": True,
            "category": "credential_access", "severity": "critical",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1003.006",
            "attack_chain": "dcsync_sim",
            "hunt_note": "lsass.exe desde workstation conectando al DC por LDAP - posible DCSync (DsGetNCChanges)"
        },
        {
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(), "hostname": "WS-PC01",
            "process_name": "lsass.exe",
            "image": r"C:\Windows\System32\lsass.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 680,
            "destination_ip": "10.0.1.1", "destination_port": 445,
            "destination_hostname": "dc01.corp.local",
            "source_ip": "10.0.1.50", "source_port": 55401,
            "protocol": "tcp", "initiated": True,
            "category": "credential_access", "severity": "critical",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1003.006",
            "attack_chain": "dcsync_sim",
            "hunt_note": "DRS replication request - DRSUAPI RPC call"
        },
    ]
    return inject_events(es, events)


def simulate_ransomware(es):
    """Simula ejecución de ransomware"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "vssadmin.exe",
            "image": r"C:\Windows\System32\vssadmin.exe",
            "user": "CORP\\admin", "pid": 11500,
            "parent_image": r"C:\Users\admin\Desktop\invoice.exe",
            "parent_pid": 11450, "parent_name": "invoice.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "integrity_level": "High",
            "category": "impact", "severity": "critical",
            "mitre_tactic": "Impact", "mitre_technique": "T1490",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Shadow copy deletion - precursor de ransomware"
        },
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(), "hostname": "WS-PC01",
            "process_name": "bcdedit.exe",
            "image": r"C:\Windows\System32\bcdedit.exe",
            "user": "CORP\\admin", "pid": 11510,
            "parent_image": r"C:\Users\admin\Desktop\invoice.exe",
            "parent_pid": 11450, "parent_name": "invoice.exe",
            "command_line": "bcdedit /set {default} recoveryenabled No",
            "integrity_level": "High",
            "category": "impact", "severity": "critical",
            "mitre_tactic": "Impact", "mitre_technique": "T1490",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Recovery disabled - ransomware preventing recovery"
        },
        {
            "event_id": 11, "event_description": "File Create",
            "timestamp": (base_time + timedelta(seconds=5)).isoformat(), "hostname": "WS-PC01",
            "process_name": "invoice.exe",
            "image": r"C:\Users\admin\Desktop\invoice.exe",
            "user": "CORP\\admin", "pid": 11450,
            "target_filename": r"C:\Users\admin\Documents\README_DECRYPT.txt",
            "category": "impact", "severity": "critical",
            "mitre_tactic": "Impact", "mitre_technique": "T1486",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Ransom note dropped"
        },
    ]
    # Simulate mass file rename (encryption)
    extensions = [".docx", ".xlsx", ".pdf", ".pptx", ".jpg"]
    for i, ext in enumerate(extensions):
        events.append({
            "event_id": 11, "event_description": "File Create",
            "timestamp": (base_time + timedelta(seconds=6+i)).isoformat(), "hostname": "WS-PC01",
            "process_name": "invoice.exe",
            "image": r"C:\Users\admin\Desktop\invoice.exe",
            "user": "CORP\\admin", "pid": 11450,
            "target_filename": f"C:\\Users\\admin\\Documents\\file_{i}{ext}.locked",
            "category": "impact", "severity": "critical",
            "mitre_tactic": "Impact", "mitre_technique": "T1486",
            "attack_chain": "ransomware_sim",
            "hunt_note": f"File encrypted: file_{i}{ext} -> file_{i}{ext}.locked"
        })
    return inject_events(es, events)


def simulate_fileless_wmi(es):
    """Simula persistencia fileless via WMI Event Subscription"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "powershell.exe",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "user": "CORP\\admin", "pid": 11600,
            "parent_image": r"C:\Windows\System32\cmd.exe",
            "parent_pid": 8750, "parent_name": "cmd.exe",
            "command_line": r'powershell.exe -nop -w hidden -c "$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name=\"EvilFilter\"; EventNameSpace=\"root\cimv2\"; QueryLanguage=\"WQL\"; Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'\"}"',
            "integrity_level": "High",
            "category": "persistence", "severity": "critical",
            "mitre_tactic": "Persistence", "mitre_technique": "T1546.003",
            "attack_chain": "fileless_wmi_sim",
            "hunt_note": "WMI Event Subscription creation - fileless persistence"
        },
        {
            "event_id": 19, "event_description": "WMI Event Filter",
            "timestamp": (base_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
            "process_name": "WmiPrvSE.exe",
            "image": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 1800,
            "event_type": "WmiFilterCreated",
            "wmi_namespace": r"root\subscription",
            "wmi_filter_name": "EvilFilter",
            "wmi_query": "SELECT * FROM __InstanceModificationEvent WITHIN 60",
            "category": "persistence", "severity": "critical",
            "mitre_tactic": "Persistence", "mitre_technique": "T1546.003",
            "attack_chain": "fileless_wmi_sim",
            "hunt_note": "WMI Event Filter created - triggers every 60 seconds"
        },
        {
            "event_id": 20, "event_description": "WMI Event Consumer",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(), "hostname": "WS-PC01",
            "process_name": "WmiPrvSE.exe",
            "image": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 1800,
            "event_type": "WmiConsumerCreated",
            "wmi_consumer_name": "EvilConsumer",
            "wmi_consumer_type": "CommandLineEventConsumer",
            "wmi_destination": r"powershell.exe -nop -w hidden -enc aQBlAHgA...",
            "category": "persistence", "severity": "critical",
            "mitre_tactic": "Persistence", "mitre_technique": "T1546.003",
            "attack_chain": "fileless_wmi_sim",
            "hunt_note": "WMI Consumer created - executes encoded PowerShell"
        },
    ]
    return inject_events(es, events)


def simulate_cobalt_strike(es):
    """Simula Cobalt Strike beacon con named pipe y sleep jitter"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "rundll32.exe",
            "image": r"C:\Windows\System32\rundll32.exe",
            "user": "CORP\\user01", "pid": 11700,
            "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_pid": 7720, "parent_name": "powershell.exe",
            "command_line": "rundll32.exe",
            "integrity_level": "Medium",
            "category": "c2", "severity": "critical",
            "mitre_tactic": "Defense Evasion", "mitre_technique": "T1218.011",
            "attack_chain": "cobalt_strike_sim",
            "hunt_note": "rundll32.exe sin argumentos - típico de Cobalt Strike beacon spawn"
        },
        {
            "event_id": 17, "event_description": "Pipe Created",
            "timestamp": (base_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
            "process_name": "rundll32.exe",
            "image": r"C:\Windows\System32\rundll32.exe",
            "user": "CORP\\user01", "pid": 11700,
            "pipe_name": r"\\.\pipe\MSSE-1234-server",
            "category": "c2", "severity": "critical",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "attack_chain": "cobalt_strike_sim",
            "hunt_note": "Named pipe MSSE-*-server - default Cobalt Strike pipe name"
        },
    ]
    # Beacon connections with jitter
    for i in range(8):
        jitter = random.randint(55, 65)  # ~60s sleep with jitter
        events.append({
            "event_id": 3, "event_description": "Network Connection",
            "timestamp": (base_time + timedelta(seconds=jitter*i+5)).isoformat(), "hostname": "WS-PC01",
            "process_name": "rundll32.exe",
            "image": r"C:\Windows\System32\rundll32.exe",
            "user": "CORP\\user01", "pid": 11700,
            "destination_ip": "185.220.101.42", "destination_port": 443,
            "destination_hostname": "cdn.jquery-uikit.com",
            "source_ip": "10.0.1.50", "source_port": 55700 + i,
            "protocol": "tcp", "initiated": True,
            "category": "c2", "severity": "critical",
            "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
            "attack_chain": "cobalt_strike_sim",
            "hunt_note": f"Beacon callback #{i+1} - ~60s interval with jitter"
        })
    return inject_events(es, events)


def simulate_token_manipulation(es):
    """Simula Token Manipulation para escalamiento de privilegios"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "cmd.exe",
            "image": r"C:\Windows\System32\cmd.exe",
            "user": "NT AUTHORITY\\SYSTEM", "pid": 11800,
            "parent_image": r"C:\Users\user01\AppData\Local\Temp\update.exe",
            "parent_pid": 8100, "parent_name": "update.exe",
            "command_line": "cmd.exe /c whoami",
            "integrity_level": "System",
            "category": "privilege_escalation", "severity": "critical",
            "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1134.001",
            "attack_chain": "token_manipulation_sim",
            "hunt_note": "cmd.exe ejecutado como SYSTEM desde proceso de usuario - token stolen"
        },
        {
            "event_id": 10, "event_description": "Process Access",
            "timestamp": (base_time - timedelta(seconds=5)).isoformat(), "hostname": "WS-PC01",
            "source_image": r"C:\Users\user01\AppData\Local\Temp\update.exe",
            "source_pid": 8100, "source_name": "update.exe",
            "target_image": r"C:\Windows\System32\winlogon.exe",
            "target_pid": 560, "target_name": "winlogon.exe",
            "granted_access": "0x0400",
            "user": "CORP\\user01",
            "category": "privilege_escalation", "severity": "critical",
            "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1134.001",
            "attack_chain": "token_manipulation_sim",
            "hunt_note": "TOKEN_QUERY (0x0400) access to winlogon.exe - token theft preparation"
        },
    ]
    return inject_events(es, events)


def simulate_amsi_bypass(es):
    """Simula AMSI Bypass"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "powershell.exe",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "user": "CORP\\user01", "pid": 11900,
            "parent_image": r"C:\Windows\System32\cmd.exe",
            "parent_pid": 8750, "parent_name": "cmd.exe",
            "command_line": r'powershell.exe -nop -c "[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiInitFailed\",\"NonPublic,Static\").SetValue($null,$true)"',
            "integrity_level": "Medium",
            "category": "defense_evasion", "severity": "critical",
            "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.001",
            "attack_chain": "amsi_bypass_sim",
            "hunt_note": "AMSI bypass via reflection - AmsiUtils.amsiInitFailed set to true"
        },
        {
            "event_id": 7, "event_description": "Image Loaded",
            "timestamp": (base_time + timedelta(seconds=1)).isoformat(), "hostname": "WS-PC01",
            "process_name": "powershell.exe",
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "user": "CORP\\user01", "pid": 11900,
            "image_loaded": r"C:\Windows\System32\amsi.dll",
            "hashes": f"SHA256={sha256('amsi.dll')}",
            "signed": True, "signature": "Microsoft Windows", "signature_status": "Valid",
            "category": "defense_evasion", "severity": "high",
            "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562.001",
            "attack_chain": "amsi_bypass_sim",
            "hunt_note": "amsi.dll loaded but will be patched in memory"
        },
    ]
    return inject_events(es, events)


def simulate_ntds_dump(es):
    """Simula NTDS.dit dump"""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 1, "event_description": "Process Create",
            "timestamp": base_time.isoformat(), "hostname": "WS-PC01",
            "process_name": "ntdsutil.exe",
            "image": r"C:\Windows\System32\ntdsutil.exe",
            "user": "CORP\\admin", "pid": 12000,
            "parent_image": r"C:\Windows\System32\cmd.exe",
            "parent_pid": 8750, "parent_name": "cmd.exe",
            "command_line": r'ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\ntds_dump" quit quit',
            "integrity_level": "High",
            "category": "credential_access", "severity": "critical",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1003.003",
            "attack_chain": "ntds_dump_sim",
            "hunt_note": "ntdsutil IFM creation - full AD database dump"
        },
        {
            "event_id": 11, "event_description": "File Create",
            "timestamp": (base_time + timedelta(seconds=10)).isoformat(), "hostname": "WS-PC01",
            "process_name": "ntdsutil.exe",
            "image": r"C:\Windows\System32\ntdsutil.exe",
            "user": "CORP\\admin", "pid": 12000,
            "target_filename": r"C:\Windows\Temp\ntds_dump\Active Directory\ntds.dit",
            "category": "credential_access", "severity": "critical",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1003.003",
            "attack_chain": "ntds_dump_sim",
            "hunt_note": "ntds.dit file created - contains all AD password hashes"
        },
        {
            "event_id": 11, "event_description": "File Create",
            "timestamp": (base_time + timedelta(seconds=11)).isoformat(), "hostname": "WS-PC01",
            "process_name": "ntdsutil.exe",
            "image": r"C:\Windows\System32\ntdsutil.exe",
            "user": "CORP\\admin", "pid": 12000,
            "target_filename": r"C:\Windows\Temp\ntds_dump\registry\SYSTEM",
            "category": "credential_access", "severity": "critical",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1003.003",
            "attack_chain": "ntds_dump_sim",
            "hunt_note": "SYSTEM hive extracted - needed to decrypt ntds.dit"
        },
    ]
    return inject_events(es, events)


def reset_simulated(es):
    """Elimina todos los eventos simulados."""
    body = {"query": {"term": {"simulated": True}}}
    result = es.delete_by_query(index=INDEX, query=body["query"])
    es.indices.refresh(index=INDEX)
    return result.get("deleted", 0)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    es = get_es()

    if command == "list":
        print("\n" + "="*70)
        print("  ESCENARIOS DE ATAQUE DISPONIBLES")
        print("="*70)
        for key, info in SCENARIOS.items():
            print(f"\n  {key}")
            print(f"    Nombre:      {info['name']}")
            print(f"    Descripción: {info['description']}")
            print(f"    MITRE:       {info['mitre']} ({info['tactic']})")
        print(f"\n{'='*70}")
        print(f"  Uso: simulate <scenario>  |  simulate all  |  simulate reset")
        print(f"{'='*70}\n")

    elif command == "all":
        print("\n[*] Ejecutando TODOS los escenarios de ataque...\n")
        total = 0
        for scenario in SCENARIOS:
            func = globals().get(f"simulate_{scenario}")
            if func:
                count = func(es)
                total += count
                print(f"  [+] {SCENARIOS[scenario]['name']}: {count} eventos inyectados")
        print(f"\n  [=] Total: {total} eventos inyectados en index '{INDEX}'")
        print(f"  [=] Consulta en Kibana: simulated:true")
        print(f"  [=] Kibana URL: http://localhost:5601/app/discover\n")

    elif command == "reset":
        deleted = reset_simulated(es)
        print(f"\n  [+] {deleted} eventos simulados eliminados del index '{INDEX}'\n")

    elif command in SCENARIOS:
        func = globals().get(f"simulate_{command}")
        if func:
            count = func(es)
            print(f"\n  [+] {SCENARIOS[command]['name']}")
            print(f"  [+] {count} eventos inyectados en index '{INDEX}'")
            print(f"\n  Queries sugeridas en Kibana (KQL):")
            print(f"  ─────────────────────────────────────────────────")
            print(f"  attack_chain:\"{command}_sim\"")
            print(f"  simulated:true AND severity:critical")
            print(f"  mitre_technique:\"{SCENARIOS[command]['mitre']}\"")
            print(f"\n  Kibana URL: http://localhost:5601/app/discover\n")
        else:
            print(f"[-] Función simulate_{command} no encontrada")
    else:
        print(f"[-] Escenario '{command}' no reconocido. Use 'simulate list' para ver opciones.")


if __name__ == "__main__":
    main()
