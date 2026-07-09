#!/usr/bin/env python3
"""
network_correlator.py - Correlaciona conexiones de red con procesos
Curso MAR404 - Clase 5
"""
import json

DATA_DIR = "/data"

# Procesos que normalmente NO tienen conexiones de red
NO_NETWORK_PROCS = ["notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe", "snippingtool.exe"]

# Rangos de IP conocidos como sospechosos (ejemplo)
SUSPICIOUS_RANGES = ["185.220.", "91.215.", "203.0.113."]

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    with open(f"{DATA_DIR}/connections.json") as f:
        connections = json.load(f)
    
    print("=" * 70)
    print("  CORRELACIÓN RED ↔ PROCESOS")
    print("=" * 70)
    
    print(f"\n{'PID':<8}{'Process':<20}{'Remote':<25}{'State':<15}{'Anomalía'}")
    print("-" * 80)
    
    for conn in connections:
        proc = next((p for p in processes if p["pid"] == conn["pid"]), None)
        proc_name = proc["name"] if proc else "Unknown"
        
        anomaly = ""
        
        # Check 1: Proceso que no debería tener red
        if proc_name.lower() in NO_NETWORK_PROCS:
            anomaly = "PROCESO SIN RED ESPERADA"
        
        # Check 2: IP sospechosa
        for suspicious in SUSPICIOUS_RANGES:
            if suspicious in conn["remote"]:
                anomaly = anomaly + " | IP SOSPECHOSA" if anomaly else "IP SOSPECHOSA"
        
        # Check 3: Puerto C2 común
        remote_port = conn["remote"].split(":")[-1]
        if remote_port in ["4443", "4444", "8443", "9090", "1337"]:
            anomaly = anomaly + " | PUERTO C2" if anomaly else "PUERTO C2"
        
        status = f"[!] {anomaly}" if anomaly else "[OK]"
        print(f"{conn['pid']:<8}{proc_name:<20}{conn['remote']:<25}{conn['state']:<15}{status}")
    
    print(f"\n{'='*70}")
    print("  Tip: Investigue procesos con conexiones inesperadas")
    print("  Tip: Correlacione con malfind para confirmar inyección")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
