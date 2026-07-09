#!/usr/bin/env python3
"""
thread_checker.py - Verifica threads con start address anómalo
Curso MAR404 - Clase 6
"""
import json
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/threads.json") as f:
        threads = json.load(f)
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  THREAD CHECKER — Detección de Threads Anómalos")
    print("=" * 70)
    print(f"\n  {'PID':<8}{'TID':<8}{'StartAddr':<18}{'Module':<25}{'State':<12}{'Status'}")
    print(f"  {'-'*85}")
    
    suspicious_count = 0
    for pid_str, thread_list in threads.items():
        pid = int(pid_str)
        proc = next((p for p in processes if p["pid"] == pid), None)
        proc_name = proc["name"] if proc else "Unknown"
        
        for t in thread_list:
            status = "[!] SUSPICIOUS" if t["suspicious"] else "[OK]"
            if t["suspicious"]:
                suspicious_count += 1
            print(f"  {pid:<8}{t['tid']:<8}{t['start_address']:<18}{t['module']:<25}{t['state']:<12}{status}")
            if t["suspicious"]:
                print(f"  {'':8}{'':8}→ {t['notes']}")
                print()
    
    print(f"\n{'='*70}")
    print(f"  Threads sospechosos: {suspicious_count}")
    print(f"{'='*70}")
    print("\n  Indicadores de thread inyectado:")
    print("  • Start address en región sin backing file (UNKNOWN module)")
    print("  • Start address fuera de cualquier módulo cargado")
    print("  • Thread en proceso que no debería tener actividad de red")
    print("  • Múltiples threads nuevos en proceso simple (notepad, calc)")

if __name__ == "__main__":
    main()
