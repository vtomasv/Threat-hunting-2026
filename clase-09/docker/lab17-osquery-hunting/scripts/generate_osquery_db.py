#!/usr/bin/env python3
"""
generate_osquery_db.py - Genera base de datos SQLite simulando tablas de Osquery
con endpoint comprometido para hunting.
Curso MAR404 - Clase 9 - Lab 17
"""
import sqlite3, hashlib, random

DB_PATH = "/app/osquery.db"

def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # === TABLE: processes ===
    c.execute("""CREATE TABLE processes (
        pid INTEGER, name TEXT, path TEXT, cmdline TEXT,
        parent INTEGER, uid INTEGER, gid INTEGER,
        start_time INTEGER, resident_size INTEGER,
        is_elevated INTEGER DEFAULT 0
    )""")
    
    normal_procs = [
        (4, "System", "", "", 0, 0, 0, 1721462400, 1024, 0),
        (600, "csrss.exe", "C:\\Windows\\System32\\csrss.exe", "csrss.exe", 4, 0, 0, 1721462401, 4096, 1),
        (700, "wininit.exe", "C:\\Windows\\System32\\wininit.exe", "wininit.exe", 4, 0, 0, 1721462402, 2048, 1),
        (800, "services.exe", "C:\\Windows\\System32\\services.exe", "services.exe", 700, 0, 0, 1721462403, 8192, 1),
        (900, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", "lsass.exe", 700, 0, 0, 1721462404, 16384, 1),
        (1000, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", 800, 0, 0, 1721462405, 32768, 1),
        (1200, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k LocalService", 800, 0, 0, 1721462406, 16384, 1),
        (2400, "explorer.exe", "C:\\Windows\\explorer.exe", "explorer.exe", 1000, 1001, 1001, 1721462500, 65536, 0),
        (3000, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe", "chrome.exe --type=browser", 2400, 1001, 1001, 1721463000, 131072, 0),
        (3500, "outlook.exe", "C:\\Program Files\\Microsoft Office\\outlook.exe", "outlook.exe", 2400, 1001, 1001, 1721463100, 98304, 0),
    ]
    
    # Malicious processes
    malicious_procs = [
        (7788, "svchost.exe", "C:\\Users\\Public\\svchost.exe", "svchost.exe -k netsvcs", 2400, 1001, 1001, 1721480000, 45056, 0),
        (8100, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden -enc aQBlAHgA...", 7788, 0, 0, 1721480100, 78000, 1),
        (8500, "rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Windows\\Temp\\update.dll,DllMain", 8100, 0, 0, 1721480200, 32000, 1),
        (9000, "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all > C:\\Windows\\Temp\\info.txt", 8100, 0, 0, 1721480300, 4096, 1),
    ]
    
    for p in normal_procs + malicious_procs:
        c.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?)", p)
    
    # === TABLE: process_open_sockets ===
    c.execute("""CREATE TABLE process_open_sockets (
        pid INTEGER, fd INTEGER, socket INTEGER, family INTEGER,
        protocol INTEGER, local_address TEXT, local_port INTEGER,
        remote_address TEXT, remote_port INTEGER, state TEXT
    )""")
    
    normal_sockets = [
        (3000, 5, 100, 2, 6, "10.0.1.50", 49800, "142.250.80.46", 443, "ESTABLISHED"),
        (3500, 6, 101, 2, 6, "10.0.1.50", 49801, "52.96.166.130", 443, "ESTABLISHED"),
        (1000, 7, 102, 2, 6, "10.0.1.50", 49802, "10.0.1.1", 53, "ESTABLISHED"),
    ]
    
    malicious_sockets = [
        (7788, 10, 200, 2, 6, "10.0.1.50", 49900, "198.51.100.10", 443, "ESTABLISHED"),
        (8100, 11, 201, 2, 6, "10.0.1.50", 49901, "198.51.100.10", 8443, "ESTABLISHED"),
        (8500, 12, 202, 2, 6, "10.0.1.50", 49902, "203.0.113.50", 4444, "ESTABLISHED"),
    ]
    
    for s in normal_sockets + malicious_sockets:
        c.execute("INSERT INTO process_open_sockets VALUES (?,?,?,?,?,?,?,?,?,?)", s)
    
    # === TABLE: scheduled_tasks ===
    c.execute("""CREATE TABLE scheduled_tasks (
        name TEXT, action TEXT, path TEXT, enabled INTEGER,
        last_run_time INTEGER, next_run_time INTEGER, hidden INTEGER
    )""")
    
    tasks = [
        ("GoogleUpdateTaskMachine", "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe", "\\", 1, 1721462000, 1721548400, 0),
        ("MicrosoftEdgeUpdate", "C:\\Program Files\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", "\\", 1, 1721462000, 1721548400, 0),
        ("WindowsUpdateCheck", "C:\\Users\\Public\\svchost.exe -k netsvcs", "\\Microsoft\\Windows\\Update", 1, 1721480000, 1721483600, 1),
    ]
    
    for t in tasks:
        c.execute("INSERT INTO scheduled_tasks VALUES (?,?,?,?,?,?,?)", t)
    
    # === TABLE: startup_items ===
    c.execute("""CREATE TABLE startup_items (
        name TEXT, path TEXT, source TEXT, status TEXT, username TEXT
    )""")
    
    startups = [
        ("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe", "registry", "enabled", "SYSTEM"),
        ("OneDrive", "C:\\Users\\user01\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "registry", "enabled", "user01"),
        ("WindowsUpdate", "C:\\Users\\Public\\svchost.exe", "registry", "enabled", "SYSTEM"),
    ]
    
    for s in startups:
        c.execute("INSERT INTO startup_items VALUES (?,?,?,?,?)", s)
    
    # === TABLE: listening_ports ===
    c.execute("""CREATE TABLE listening_ports (
        pid INTEGER, port INTEGER, protocol INTEGER, address TEXT
    )""")
    
    ports = [
        (1000, 135, 6, "0.0.0.0"),
        (1200, 445, 6, "0.0.0.0"),
        (8500, 4444, 6, "0.0.0.0"),  # Malicious reverse shell listener
    ]
    
    for p in ports:
        c.execute("INSERT INTO listening_ports VALUES (?,?,?,?)", p)
    
    # === TABLE: hash ===
    c.execute("""CREATE TABLE hash (
        path TEXT, md5 TEXT, sha256 TEXT
    )""")
    
    hashes = [
        ("C:\\Windows\\System32\\svchost.exe", "a1b2c3d4e5f6", hashlib.sha256(b"legit_svchost").hexdigest()),
        ("C:\\Users\\Public\\svchost.exe", "f6e5d4c3b2a1", hashlib.sha256(b"malicious_svchost").hexdigest()),
        ("C:\\Windows\\Temp\\update.dll", "1a2b3c4d5e6f", hashlib.sha256(b"malicious_dll").hexdigest()),
    ]
    
    for h in hashes:
        c.execute("INSERT INTO hash VALUES (?,?,?)", h)
    
    conn.commit()
    conn.close()
    print(f"[+] Osquery database generated: {DB_PATH}")

if __name__ == "__main__":
    main()
