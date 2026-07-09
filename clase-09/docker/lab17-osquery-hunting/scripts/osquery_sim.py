#!/usr/bin/env python3
"""
osquery_sim.py - Simula la interfaz interactiva de osqueryi
Permite ejecutar SQL queries contra la base de datos simulada.
Curso MAR404 - Clase 9 - Lab 17
"""
import sqlite3, sys, readline

DB_PATH = "/app/osquery.db"
TABLES = ["processes", "process_open_sockets", "scheduled_tasks", 
           "startup_items", "listening_ports", "hash"]

BANNER = """
Using a virtual database. Need help, type '.help'
osquery>"""

HELP_TEXT = """
Tablas disponibles (simuladas):
  .tables                    - Lista todas las tablas
  .schema <table>           - Muestra el schema de una tabla
  
Queries de hunting sugeridas:
  -- Procesos en paths inusuales
  SELECT pid, name, path FROM processes WHERE path NOT LIKE 'C:\\\\Windows%' AND path NOT LIKE 'C:\\\\Program Files%' AND path != '';
  
  -- Conexiones a IPs externas
  SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port 
  FROM processes p JOIN process_open_sockets s ON p.pid = s.pid 
  WHERE s.remote_address NOT LIKE '10.%' AND s.remote_address NOT LIKE '192.168.%';
  
  -- Scheduled tasks ocultas
  SELECT * FROM scheduled_tasks WHERE hidden = 1;
  
  -- Procesos elevados con path sospechoso
  SELECT pid, name, path, cmdline FROM processes WHERE is_elevated = 1 AND path LIKE '%Users%';
  
  -- Puertos en escucha inusuales
  SELECT l.pid, p.name, p.path, l.port FROM listening_ports l JOIN processes p ON l.pid = p.pid WHERE l.port > 1024;
  
  -- Hash de archivos sospechosos
  SELECT * FROM hash WHERE path LIKE '%Temp%' OR path LIKE '%Users%Public%';
"""

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(HELP_TEXT)
        return
    
    print("osquery - Threat Hunting Lab (MAR404)")
    print(f"Tables: {', '.join(TABLES)}")
    print("Type '.help' for hunting queries, '.quit' to exit")
    
    while True:
        try:
            query = input("\nosquery> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break
        
        if not query:
            continue
        if query == ".quit" or query == "exit":
            break
        if query == ".help":
            print(HELP_TEXT)
            continue
        if query == ".tables":
            for t in TABLES:
                print(f"  => {t}")
            continue
        if query.startswith(".schema"):
            table = query.split()[-1] if len(query.split()) > 1 else ""
            if table in TABLES:
                cursor = conn.execute(f"PRAGMA table_info({table})")
                for row in cursor:
                    print(f"  {row[1]:20s} {row[2]}")
            else:
                print(f"Table not found. Available: {', '.join(TABLES)}")
            continue
        
        try:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            if rows:
                headers = [desc[0] for desc in cursor.description]
                # Print header
                header_line = " | ".join(f"{h:>15s}" for h in headers)
                print(header_line)
                print("-" * len(header_line))
                for row in rows:
                    print(" | ".join(f"{str(v):>15s}" for v in row))
                print(f"\n({len(rows)} rows)")
            else:
                print("(0 rows)")
        except Exception as e:
            print(f"Error: {e}")
    
    conn.close()

if __name__ == "__main__":
    main()
