#!/usr/bin/env python3
"""
ioc_extractor.py - Extrae IOCs del caso integrador
Curso MAR404 - Clase 7 - Lab 14
"""
import json
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    with open(f"{DATA_DIR}/connections.json") as f:
        connections = json.load(f)
    with open(f"{DATA_DIR}/handles.json") as f:
        handles = json.load(f)
    
    print("=" * 70)
    print("  IOC EXTRACTOR — Indicadores de Compromiso")
    print("=" * 70)
    
    # IPs
    print("\n  [1] NETWORK IOCs:")
    mal_conns = [c for c in connections if c.get("malicious")]
    ips = set()
    for c in mal_conns:
        ip = c["remote"].split(":")[0]
        ips.add(ip)
        print(f"      {c['remote']:<25} [{c['state']}] — {c.get('notes','')}")
    
    # Files
    print("\n  [2] FILE IOCs:")
    files = set()
    for h in handles:
        if h["handle_type"] == "File":
            files.add(h["name"])
            print(f"      {h['name']}")
            print(f"        → {h['notes']}")
    
    # Processes/Commands
    print("\n  [3] PROCESS IOCs:")
    for p in processes:
        if p.get("is_malicious") and p.get("cmdline"):
            cmd = p["cmdline"][:100]
            print(f"      PID {p['pid']}: {cmd}")
    
    # Summary for blocking
    print(f"\n\n  {'='*60}")
    print("  IOCs PARA BLOQUEO INMEDIATO:")
    print(f"  {'='*60}")
    print("\n  # IPs de C2 (bloquear en firewall)")
    for ip in ips:
        print(f"  {ip}")
    print("\n  # Archivos maliciosos (buscar y eliminar)")
    print("  C:\\Users\\jrodriguez\\Downloads\\Factura_Julio_2025.docm")
    print("  C:\\Windows\\Temp\\tmp8A3F.dll")
    print("  C:\\Windows\\Temp\\lsass.dmp")
    print("  C:\\Windows\\Temp\\PsExec.exe")
    print("  C:\\Windows\\Temp\\7z.exe")
    print("  C:\\Windows\\Temp\\backup.7z")
    print("  C:\\Windows\\Temp\\staging\\*")
    print("\n  # Hashes (para EDR/AV rules)")
    print("  SHA256: [extraer de disco — no disponible en memory-only analysis]")
    print("\n  # Cuentas comprometidas")
    print("  FILESVR\\jrodriguez — credenciales probablemente exfiltradas")
    print("\n  # Servicios maliciosos")
    print("  PSEXESVC — PsExec service (lateral movement)")

if __name__ == "__main__":
    main()
