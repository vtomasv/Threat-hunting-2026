#!/usr/bin/env python3
"""
memory_hunter.py - Análisis integral de memoria para hunting
Curso MAR404 - Clase 7 - Lab 14
"""
import json, sys
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    with open(f"{DATA_DIR}/malfind.json") as f:
        malfind = json.load(f)
    with open(f"{DATA_DIR}/connections.json") as f:
        connections = json.load(f)
    
    mode = sys.argv[1] if len(sys.argv) > 1 else "--summary"
    
    if mode == "--summary":
        print("=" * 70)
        print("  MEMORY HUNTER — Resumen de Análisis")
        print("=" * 70)
        
        mal_procs = [p for p in processes if p.get("is_malicious")]
        mal_conns = [c for c in connections if c.get("malicious")]
        
        print(f"\n  Total procesos: {len(processes)}")
        print(f"  Procesos sospechosos: {len(mal_procs)}")
        print(f"  Regiones malfind: {len(malfind)}")
        print(f"  Conexiones maliciosas: {len(mal_conns)}")
        
        print(f"\n  {'─'*60}")
        print(f"  PROCESOS SOSPECHOSOS:")
        for p in mal_procs:
            print(f"    PID {p['pid']:>5} | {p['name']:<20} | {p.get('technique','')}")
    
    elif mode == "--processes":
        print("=" * 70)
        print("  ANÁLISIS DE PROCESOS")
        print("=" * 70)
        for p in processes:
            if p.get("is_malicious"):
                print(f"\n  [!] PID {p['pid']} — {p['name']}")
                print(f"      PPID: {p['ppid']} | User: {p.get('user','')}")
                print(f"      Path: {p.get('path','')}")
                print(f"      CMD: {p.get('cmdline','')}")
                print(f"      Phase: {p.get('phase','')}")
                print(f"      Technique: {p.get('technique','')}")
                print(f"      Note: {p.get('note','')}")
    
    elif mode == "--malfind":
        print("=" * 70)
        print("  MALFIND — Regiones Sospechosas")
        print("=" * 70)
        for m in malfind:
            print(f"\n  [{m['severity']}] {m['process']} (PID {m['pid']})")
            print(f"  VAD: {m['vad_start']} - {m['vad_end']}")
            print(f"  Protection: {m['protection']} | Type: {m['vad_type']}")
            print(f"  Hex: {m['hex_dump'][:50]}...")
            print(f"  → {m['notes']}")
    
    elif mode == "--network":
        print("=" * 70)
        print("  CONEXIONES DE RED")
        print("=" * 70)
        for c in connections:
            flag = "[!]" if c.get("malicious") else "[OK]"
            proc = next((p for p in processes if p["pid"] == c["pid"]), None)
            print(f"\n  {flag} PID {c['pid']} ({proc['name'] if proc else '?'})")
            print(f"      {c['local']} → {c['remote']} [{c['state']}]")
            if c.get("notes"):
                print(f"      {c['notes']}")
    
    else:
        print("Uso: memory_hunter [--summary|--processes|--malfind|--network]")

if __name__ == "__main__":
    main()
