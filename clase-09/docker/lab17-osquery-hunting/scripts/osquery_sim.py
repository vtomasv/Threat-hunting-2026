#!/usr/bin/env python3
"""
osquery_sim.py - Simula la interfaz interactiva de osqueryi
Permite ejecutar SQL queries contra la base de datos simulada.
Soporta 12 tablas con datos realistas de un endpoint comprometido.
Curso MAR404 - Clase 9 - Lab 17
"""
import sqlite3
import sys
import os

try:
    import readline
except ImportError:
    pass

DB_PATH = "/app/osquery.db"
TABLES = [
    "processes", "process_open_sockets", "scheduled_tasks",
    "startup_items", "listening_ports", "hash", "file_events",
    "registry", "drivers", "logged_in_users", "process_events",
    "dns_cache"
]

BANNER = """
osquery - Threat Hunting Lab (MAR404)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Using a virtual database. Need help, type '.help'
"""

HELP_TEXT = """
=== COMANDOS DEL SISTEMA ===
  .tables                    - Lista todas las tablas disponibles
  .schema <table>           - Muestra el schema de una tabla
  .count <table>            - Cuenta registros en una tabla
  .help                     - Muestra esta ayuda
  .hunting                  - Muestra queries de hunting sugeridas
  .quit / exit              - Salir

=== TABLAS DISPONIBLES (12) ===
  processes              - Procesos activos (pid, name, path, cmdline, parent, ...)
  process_open_sockets   - Conexiones de red (pid, remote_address, remote_port, ...)
  scheduled_tasks        - Tareas programadas (name, action, hidden, ...)
  startup_items          - Items de inicio/persistencia (name, path, source, ...)
  listening_ports        - Puertos en escucha (pid, port, address, ...)
  hash                   - Hashes de archivos (path, md5, sha256, sha1)
  file_events            - Eventos de filesystem (target_path, action, time, ...)
  registry               - Claves de registro (path, name, type, data, mtime)
  drivers                - Drivers cargados (name, path, signed, manufacturer)
  logged_in_users        - Sesiones activas (type, user, host, time)
  process_events         - Log de ejecución de procesos (pid, path, cmdline, parent, time)
  dns_cache              - Cache DNS del endpoint (name, type, answer, ttl)

=== TIPS ===
  - Las queries son SQL estándar (SQLite)
  - Usa JOIN para correlacionar tablas
  - Usa LIKE '%patron%' para búsquedas parciales
  - Usa WHERE time > X para filtrar por tiempo
"""

HUNTING_QUERIES = """
=== QUERIES DE HUNTING SUGERIDAS ===

-- 1. PROCESOS EN PATHS INUSUALES (masquerading)
SELECT pid, name, path, parent FROM processes 
WHERE path NOT LIKE 'C:\\\\Windows\\\\System32%' 
  AND path NOT LIKE 'C:\\\\Windows\\\\SysWOW64%'
  AND path NOT LIKE 'C:\\\\Program Files%' 
  AND path NOT LIKE 'C:\\\\Windows\\\\explorer.exe'
  AND path != '' AND name IN ('svchost.exe','lsass.exe','csrss.exe','services.exe');

-- 2. PROCESOS CON PARENT SOSPECHOSO (parent-child anomaly)
SELECT p.pid, p.name, p.path, p.parent, pp.name as parent_name, pp.path as parent_path
FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid
WHERE p.name = 'svchost.exe' AND pp.name != 'services.exe';

-- 3. CONEXIONES A IPS EXTERNAS (C2 detection)
SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port 
FROM processes p JOIN process_open_sockets s ON p.pid = s.pid 
WHERE s.remote_address NOT LIKE '10.%' 
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.16.%'
  AND s.remote_address != '127.0.0.1';

-- 4. SCHEDULED TASKS OCULTAS O SOSPECHOSAS
SELECT name, action, hidden, username FROM scheduled_tasks 
WHERE hidden = 1 OR action LIKE '%Users%' OR action LIKE '%Temp%';

-- 5. PERSISTENCIA EN REGISTRO (Run keys)
SELECT path, name, data, mtime FROM registry 
WHERE path LIKE '%CurrentVersion\\Run%' 
  AND data LIKE '%Users%';

-- 6. DRIVERS SIN FIRMA (rootkit detection)
SELECT name, path, manufacturer FROM drivers WHERE signed = 0;

-- 7. PUERTOS EN ESCUCHA INUSUALES
SELECT l.pid, p.name, p.path, l.port, l.address 
FROM listening_ports l JOIN processes p ON l.pid = p.pid 
WHERE l.port NOT IN (135, 139, 445, 49664, 49665, 49666);

-- 8. ARCHIVOS CREADOS EN TEMP (staging/payload drops)
SELECT target_path, action, time, size, process_pid 
FROM file_events WHERE target_path LIKE '%Temp%' OR target_path LIKE '%Public%'
ORDER BY time DESC;

-- 9. POWERSHELL SOSPECHOSO (encoded, hidden, download)
SELECT pid, cmdline, parent, start_time FROM processes 
WHERE name = 'powershell.exe' 
  AND (cmdline LIKE '%-enc%' OR cmdline LIKE '%-w hidden%' OR cmdline LIKE '%DownloadString%' OR cmdline LIKE '%IEX%');

-- 10. CADENA DE EJECUCIÓN COMPLETA (process tree)
SELECT pe.eid, pe.pid, pe.path, pe.cmdline, pe.parent, pe.parent_path, pe.time
FROM process_events pe ORDER BY pe.time;

-- 11. DNS SOSPECHOSO (DGA, C2 domains)
SELECT name, answer, time_queried FROM dns_cache 
WHERE length(name) > 20 OR name LIKE '%.xyz' OR name LIKE '%.top'
ORDER BY time_queried DESC;

-- 12. LOLBINS EN USO (certutil, mshta, wmic, bitsadmin, rundll32)
SELECT pid, name, cmdline, parent, start_time FROM processes 
WHERE name IN ('certutil.exe','mshta.exe','WMIC.exe','bitsadmin.exe','rundll32.exe','regsvr32.exe');

-- 13. CREDENTIAL ACCESS (acceso a lsass o SAM)
SELECT pid, name, path, cmdline FROM processes 
WHERE cmdline LIKE '%lsass%' OR cmdline LIKE '%SAM%' OR cmdline LIKE '%sekurlsa%'
  OR name = 'procdump.exe' OR (name = 'lsass.exe' AND path NOT LIKE '%System32%');

-- 14. SESIONES REMOTAS SOSPECHOSAS
SELECT type, user, host, time FROM logged_in_users WHERE type = 'remote';

-- 15. DEFENDER DESHABILITADO
SELECT path, name, data, mtime FROM registry 
WHERE (name LIKE '%Disable%' AND data = '1') 
  AND path LIKE '%Defender%';
"""


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(HELP_TEXT)
        return

    # Non-interactive mode: execute query from argument
    if len(sys.argv) > 1 and sys.argv[1] != "--help":
        query = " ".join(sys.argv[1:])
        try:
            cursor = conn.execute(query.rstrip(";"))
            rows = cursor.fetchall()
            if rows:
                headers = [desc[0] for desc in cursor.description]
                widths = [len(h) for h in headers]
                str_rows = []
                for row in rows:
                    str_row = [str(v) if v is not None else "NULL" for v in row]
                    str_rows.append(str_row)
                    for i, v in enumerate(str_row):
                        widths[i] = max(widths[i], min(len(v), 60))
                header_line = " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
                print(header_line)
                print("-" * len(header_line))
                for str_row in str_rows:
                    line = " | ".join(f"{v[:60]:<{widths[i]}}" for i, v in enumerate(str_row))
                    print(line)
                print(f"\n({len(rows)} rows)")
            else:
                print("(0 rows)")
        except Exception as e:
            print(f"Error: {e}")
        conn.close()
        return

    print(BANNER)
    print(f"Tables: {len(TABLES)} | Records: ", end="")
    total = 0
    for t in TABLES:
        try:
            count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            total += count
        except:
            pass
    print(f"{total}")
    print("Type '.help' for commands, '.hunting' for queries, '.quit' to exit\n")

    while True:
        try:
            query = input("osquery> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not query:
            continue
        if query in (".quit", "exit", ".exit"):
            break
        if query == ".help":
            print(HELP_TEXT)
            continue
        if query == ".hunting":
            print(HUNTING_QUERIES)
            continue
        if query == ".tables":
            for t in TABLES:
                try:
                    count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    print(f"  => {t:30s} ({count} rows)")
                except:
                    print(f"  => {t:30s} (error)")
            continue
        if query.startswith(".schema"):
            parts = query.split()
            table = parts[1] if len(parts) > 1 else ""
            if table in TABLES:
                cursor = conn.execute(f"PRAGMA table_info({table})")
                print(f"\n  Schema for '{table}':")
                for row in cursor:
                    nullable = "" if row[3] == 0 else " NOT NULL"
                    default = f" DEFAULT {row[4]}" if row[4] else ""
                    pk = " [PK]" if row[5] else ""
                    print(f"    {row[1]:25s} {row[2]:10s}{nullable}{default}{pk}")
                print()
            else:
                print(f"  Table not found. Available: {', '.join(TABLES)}")
            continue
        if query.startswith(".count"):
            parts = query.split()
            table = parts[1] if len(parts) > 1 else ""
            if table in TABLES:
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                print(f"  {table}: {count} rows")
            else:
                for t in TABLES:
                    count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    print(f"  {t}: {count} rows")
            continue

        # Execute SQL query
        try:
            if not query.endswith(";"):
                query += ";"
            cursor = conn.execute(query.rstrip(";"))
            rows = cursor.fetchall()
            if rows:
                headers = [desc[0] for desc in cursor.description]
                # Calculate column widths
                widths = [len(h) for h in headers]
                str_rows = []
                for row in rows:
                    str_row = [str(v) if v is not None else "NULL" for v in row]
                    str_rows.append(str_row)
                    for i, v in enumerate(str_row):
                        widths[i] = max(widths[i], min(len(v), 60))

                # Print header
                header_line = " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
                print(header_line)
                print("-" * len(header_line))
                # Print rows
                for str_row in str_rows:
                    line = " | ".join(f"{v[:60]:<{widths[i]}}" for i, v in enumerate(str_row))
                    print(line)
                print(f"\n({len(rows)} rows)")
            else:
                print("(0 rows)")
        except Exception as e:
            print(f"Error: {e}")

    conn.close()


if __name__ == "__main__":
    main()
