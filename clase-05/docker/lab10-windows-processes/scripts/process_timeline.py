#!/usr/bin/env python3
"""
process_timeline.py - Genera timeline de creación de procesos
Curso MAR404 - Clase 5
"""
import json
from datetime import datetime

DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  TIMELINE DE CREACIÓN DE PROCESOS")
    print("=" * 70)
    print(f"\n{'Timestamp':<28}{'PID':<8}{'PPID':<8}{'Process':<20}{'User'}")
    print("-" * 90)
    
    sorted_procs = sorted(processes, key=lambda p: p["create_time"])
    
    boot_time = datetime.fromisoformat(sorted_procs[0]["create_time"])
    
    for p in sorted_procs:
        proc_time = datetime.fromisoformat(p["create_time"])
        delta = (proc_time - boot_time).total_seconds() / 60
        
        marker = ""
        if delta > 20:
            marker = " ← POST-BOOT"
        if delta > 60:
            marker = " ← SOSPECHOSO (>1h post-boot)"
        
        print(f"{p['create_time']:<28}{p['pid']:<8}{p['ppid']:<8}{p['name']:<20}{p['user'][:25]}{marker}")
    
    print(f"\n{'='*70}")
    print("  Tip: Procesos core (svchost, lsass, services) deben crearse al boot")
    print("  Procesos creados mucho después pueden indicar compromiso")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
