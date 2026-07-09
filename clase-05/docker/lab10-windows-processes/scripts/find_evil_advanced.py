#!/usr/bin/env python3
"""
find_evil_advanced.py
=====================
Análisis avanzado de Find Evil con detección de:
- Process Hollowing (VAD RWX + MZ header)
- DLL Side-Loading (DLLs no firmadas en paths inusuales)
- Parent PID Spoofing (timestamps inconsistentes)
- Token Manipulation (privilege escalation)

Uso: find_evil_advanced [--full]

Curso MAR404 - Clase 5
"""

import json
import sys
import os
from datetime import datetime

DATA_DIR = "/data"


def load_data():
    """Carga los datasets."""
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    with open(f"{DATA_DIR}/connections.json") as f:
        connections = json.load(f)
    return processes, connections


def check_hollowing(processes):
    """Detecta posible Process Hollowing."""
    findings = []
    
    # Procesos que normalmente NO tienen conexiones de red
    no_network_procs = ["notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe"]
    
    for p in processes:
        if p["name"].lower() in no_network_procs and p.get("vad_suspicious"):
            findings.append({
                "pid": p["pid"],
                "name": p["name"],
                "severity": "CRITICAL",
                "technique": "T1055.012 - Process Hollowing",
                "evidence": [
                    f"Proceso {p['name']} tiene VAD con PAGE_EXECUTE_READWRITE",
                    f"Threads: {p['threads']} (esperado: 3-4 para {p['name']})",
                    f"Handles: {p['handles']} (esperado: ~80 para {p['name']})",
                    "Posible PE inyectado en espacio de memoria del proceso"
                ]
            })
    
    return findings


def check_dll_sideloading(processes):
    """Detecta posible DLL Side-Loading."""
    findings = []
    
    for p in processes:
        if p.get("dlls"):
            for dll in p["dlls"]:
                if dll.get("suspicious"):
                    findings.append({
                        "pid": p["pid"],
                        "name": p["name"],
                        "severity": "HIGH",
                        "technique": "T1574.002 - DLL Side-Loading",
                        "evidence": [
                            f"DLL sospechosa: {dll['name']} en {dll['path']}",
                            f"Firmada: {'Sí' if dll.get('signed') else 'NO'}",
                            f"Notas: {dll.get('notes', 'N/A')}"
                        ]
                    })
    
    return findings


def check_ppid_spoofing(processes):
    """Detecta Parent PID Spoofing via análisis de timestamps."""
    findings = []
    
    boot_procs = ["svchost.exe", "services.exe", "lsass.exe", "csrss.exe"]
    
    # Obtener boot time (del proceso System)
    system_proc = next((p for p in processes if p["name"] == "System"), None)
    if not system_proc:
        return findings
    
    boot_time = datetime.fromisoformat(system_proc["create_time"])
    
    for p in processes:
        if p["name"].lower() in boot_procs:
            proc_time = datetime.fromisoformat(p["create_time"])
            delta_minutes = (proc_time - boot_time).total_seconds() / 60
            
            if delta_minutes > 10:  # Más de 10 min después del boot
                # Verificar si tiene pocos threads/handles comparado con hermanos
                siblings = [s for s in processes if s["name"] == p["name"] and s["pid"] != p["pid"]]
                if siblings:
                    avg_threads = sum(s["threads"] for s in siblings) / len(siblings)
                    if p["threads"] < avg_threads * 0.3:
                        findings.append({
                            "pid": p["pid"],
                            "name": p["name"],
                            "severity": "HIGH",
                            "technique": "T1134.004 - Parent PID Spoofing",
                            "evidence": [
                                f"Creado {delta_minutes:.0f} min después del boot (esperado: al boot)",
                                f"Threads: {p['threads']} (promedio hermanos: {avg_threads:.0f})",
                                f"Handles: {p['handles']}",
                                "Timestamp inconsistente sugiere creación posterior con PPID falsificado"
                            ]
                        })
    
    return findings


def check_token_manipulation(processes):
    """Detecta Token Manipulation / Privilege Escalation."""
    findings = []
    
    for p in processes:
        if p["user"] == "NT AUTHORITY\\SYSTEM":
            # Verificar si el parent es un proceso de usuario
            parent = next((pp for pp in processes if pp["pid"] == p["ppid"]), None)
            if parent and parent["user"] != "NT AUTHORITY\\SYSTEM" and parent["user"] != "NT AUTHORITY\\LOCAL SERVICE":
                findings.append({
                    "pid": p["pid"],
                    "name": p["name"],
                    "severity": "CRITICAL",
                    "technique": "T1134.001 - Token Impersonation/Theft",
                    "evidence": [
                        f"Proceso SYSTEM con parent de usuario: {parent['name']} (PID {parent['pid']})",
                        f"Parent user: {parent['user']}",
                        f"Cmdline: {p['cmdline']}",
                        "Indica privilege escalation via token manipulation"
                    ]
                })
            # Verificar si parent tiene VAD sospechoso (hollowed)
            if parent and parent.get("vad_suspicious"):
                findings[-1]["evidence"].append(f"Parent {parent['name']} tiene VAD RWX (posible hollowing)")
    
    return findings


def check_network_anomalies(processes, connections):
    """Correlaciona conexiones de red con procesos."""
    findings = []
    
    no_network = ["notepad.exe", "calc.exe", "mspaint.exe"]
    
    for conn in connections:
        proc = next((p for p in processes if p["pid"] == conn["pid"]), None)
        if not proc:
            continue
        
        # Proceso que no debería tener red
        if proc["name"].lower() in no_network:
            findings.append({
                "pid": proc["pid"],
                "name": proc["name"],
                "severity": "CRITICAL",
                "technique": "T1071 - Application Layer Protocol",
                "evidence": [
                    f"{proc['name']} tiene conexión a {conn['remote']}",
                    f"Estado: {conn['state']}",
                    f"{proc['name']} NO debería tener conexiones de red",
                    "Indica proceso hollowed o inyectado actuando como beacon C2"
                ]
            })
    
    return findings


def main():
    full_mode = "--full" in sys.argv
    
    processes, connections = load_data()
    
    print("=" * 70)
    print("  FIND EVIL ADVANCED — Análisis de Técnicas Avanzadas")
    print("  Curso MAR404 - Cacería de Amenazas")
    print("=" * 70)
    
    all_findings = []
    
    # Ejecutar todos los checks
    print("\n[*] Verificando Process Hollowing...")
    all_findings.extend(check_hollowing(processes))
    
    print("[*] Verificando DLL Side-Loading...")
    all_findings.extend(check_dll_sideloading(processes))
    
    print("[*] Verificando Parent PID Spoofing...")
    all_findings.extend(check_ppid_spoofing(processes))
    
    print("[*] Verificando Token Manipulation...")
    all_findings.extend(check_token_manipulation(processes))
    
    print("[*] Verificando anomalías de red...")
    all_findings.extend(check_network_anomalies(processes, connections))
    
    # Reportar
    if all_findings:
        print(f"\n{'!'*70}")
        print(f"  HALLAZGOS: {len(all_findings)} anomalías detectadas")
        print(f"{'!'*70}\n")
        
        for i, f in enumerate(all_findings, 1):
            print(f"  [{i}] [{f['severity']}] PID {f['pid']} ({f['name']})")
            print(f"      Técnica: {f['technique']}")
            for ev in f["evidence"]:
                print(f"      • {ev}")
            print()
    
    # Resumen
    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    
    print(f"\n{'='*70}")
    print(f"  RESUMEN: {critical} CRITICAL | {high} HIGH")
    print(f"  Total hallazgos: {len(all_findings)}")
    print(f"{'='*70}")
    
    if full_mode:
        print("\n\n[SOLUCIÓN COMPLETA]")
        for p in processes:
            if p.get("is_malicious"):
                print(f"\n  PID {p['pid']} - {p['name']}")
                print(f"  Técnica: {p.get('technique', 'N/A')}")
                if p.get("indicators"):
                    for ind in p["indicators"]:
                        print(f"    → {ind}")


if __name__ == "__main__":
    main()
