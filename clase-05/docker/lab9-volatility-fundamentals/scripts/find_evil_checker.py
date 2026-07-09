#!/usr/bin/env python3
"""
find_evil_checker.py
====================
Aplica la metodología SANS "Find Evil" al dataset de procesos.
Verifica automáticamente cada proceso contra las reglas esperadas.

Uso: find_evil_checker [--verbose] [--pid PID]

Curso MAR404 - Clase 5
"""

import json
import sys
import os

DATA_DIR = "/data"


# Reglas de procesos legítimos de Windows
PROCESS_RULES = {
    "System": {
        "expected_pid": 4,
        "expected_ppid": 0,
        "expected_path": "N/A",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": 1,
        "expected_parent": "Idle (PID 0)",
    },
    "smss.exe": {
        "expected_pid": None,
        "expected_ppid": 4,
        "expected_path": "C:\\Windows\\System32\\smss.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": 1,
        "expected_parent": "System (PID 4)",
    },
    "csrss.exe": {
        "expected_pid": None,
        "expected_ppid": None,  # smss.exe (pero termina, queda huérfano)
        "expected_path": "C:\\Windows\\System32\\csrss.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": None,  # 1 por sesión
        "expected_parent": "smss.exe (puede aparecer huérfano)",
    },
    "wininit.exe": {
        "expected_pid": None,
        "expected_ppid": None,
        "expected_path": "C:\\Windows\\System32\\wininit.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": 1,
        "expected_parent": "smss.exe (puede aparecer huérfano)",
    },
    "services.exe": {
        "expected_pid": None,
        "expected_ppid": None,  # wininit.exe
        "expected_path": "C:\\Windows\\System32\\services.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": 1,
        "expected_parent": "wininit.exe",
    },
    "lsass.exe": {
        "expected_pid": None,
        "expected_ppid": None,  # wininit.exe
        "expected_path": "C:\\Windows\\System32\\lsass.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": 1,
        "expected_parent": "wininit.exe",
        "critical_note": "SOLO 1 instancia. Múltiples = compromiso probable (mimikatz, credential dump)"
    },
    "svchost.exe": {
        "expected_pid": None,
        "expected_ppid": None,  # services.exe
        "expected_path": "C:\\Windows\\System32\\svchost.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE"],
        "max_instances": None,  # Múltiples
        "expected_parent": "services.exe",
        "cmdline_must_contain": "-k",
        "critical_note": "SIEMPRE debe tener flag -k. Path SIEMPRE System32."
    },
    "winlogon.exe": {
        "expected_pid": None,
        "expected_ppid": None,
        "expected_path": "C:\\Windows\\System32\\winlogon.exe",
        "expected_user": ["NT AUTHORITY\\SYSTEM"],
        "max_instances": None,
        "expected_parent": "smss.exe (puede aparecer huérfano)",
    },
    "explorer.exe": {
        "expected_pid": None,
        "expected_ppid": None,
        "expected_path": "C:\\Windows\\explorer.exe",
        "expected_user": None,  # Cualquier usuario interactivo
        "max_instances": None,
        "expected_parent": "userinit.exe (puede aparecer huérfano)",
    },
}


def check_process(process, all_processes, verbose=False):
    """Verifica un proceso contra las reglas Find Evil."""
    findings = []
    name = process["name"]
    
    rules = PROCESS_RULES.get(name)
    if not rules:
        # Proceso no en la lista de core processes
        # Verificar si el nombre es similar a uno conocido
        for known_name in PROCESS_RULES.keys():
            if name != known_name and (
                name.lower().replace("0", "o").replace("1", "l") == known_name.lower() or
                len(set(name.lower()) ^ set(known_name.lower())) <= 2 and abs(len(name) - len(known_name)) <= 1
            ):
                findings.append(f"[CRITICAL] Nombre '{name}' es SIMILAR a '{known_name}' - posible MASQUERADING (T1036)")
        return findings
    
    # Check 1: Path
    if rules.get("expected_path") and rules["expected_path"] != "N/A":
        if process["path"].lower() != rules["expected_path"].lower():
            findings.append(f"[CRITICAL] Path INCORRECTO: '{process['path']}' (esperado: '{rules['expected_path']}')")
    
    # Check 2: Instancias
    if rules.get("max_instances"):
        instances = [p for p in all_processes if p["name"] == name]
        if len(instances) > rules["max_instances"]:
            findings.append(f"[HIGH] Múltiples instancias ({len(instances)}) de {name} (máximo esperado: {rules['max_instances']})")
    
    # Check 3: Usuario
    if rules.get("expected_user"):
        if process["user"] not in rules["expected_user"]:
            findings.append(f"[HIGH] Usuario INCORRECTO: '{process['user']}' (esperado: {rules['expected_user']})")
    
    # Check 4: Cmdline (para svchost)
    if rules.get("cmdline_must_contain"):
        if rules["cmdline_must_contain"] not in process.get("cmdline", ""):
            findings.append(f"[HIGH] Cmdline NO contiene '{rules['cmdline_must_contain']}': '{process['cmdline']}'")
    
    # Check 5: Timestamp (procesos core deben crearse al boot)
    if name in ["lsass.exe", "services.exe", "csrss.exe", "wininit.exe"]:
        # Verificar si se creó mucho después del System process
        system_proc = next((p for p in all_processes if p["name"] == "System"), None)
        if system_proc:
            from datetime import datetime
            try:
                sys_time = datetime.fromisoformat(system_proc["create_time"])
                proc_time = datetime.fromisoformat(process["create_time"])
                delta = (proc_time - sys_time).total_seconds()
                if delta > 300:  # Más de 5 minutos después del boot
                    findings.append(f"[MEDIUM] Creado {delta/60:.0f} min después del boot (procesos core se crean al inicio)")
            except:
                pass
    
    return findings


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    target_pid = None
    if "--pid" in sys.argv:
        idx = sys.argv.index("--pid")
        if idx + 1 < len(sys.argv):
            target_pid = int(sys.argv[idx + 1])
    
    # Cargar datos
    pslist_file = f"{DATA_DIR}/pslist_output.json"
    if not os.path.exists(pslist_file):
        print(f"[ERROR] No se encontró {pslist_file}")
        print("Ejecute primero el generador de datos.")
        sys.exit(1)
    
    with open(pslist_file) as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  FIND EVIL CHECKER — Metodología SANS")
    print("  Análisis automático de procesos Windows")
    print("=" * 70)
    print(f"\n  Total procesos: {len(processes)}")
    print(f"  Procesos core verificados: {len(PROCESS_RULES)} reglas")
    print()
    
    all_findings = {}
    
    for proc in processes:
        if target_pid and proc["pid"] != target_pid:
            continue
        
        findings = check_process(proc, processes, verbose)
        
        if findings:
            all_findings[proc["pid"]] = {
                "process": proc,
                "findings": findings
            }
    
    if all_findings:
        print(f"\n{'!'*70}")
        print(f"  PROCESOS CON ANOMALÍAS DETECTADAS: {len(all_findings)}")
        print(f"{'!'*70}\n")
        
        for pid, data in all_findings.items():
            proc = data["process"]
            print(f"  PID: {pid} | Nombre: {proc['name']} | Path: {proc['path']}")
            print(f"  Parent: {proc['ppid']} | User: {proc['user']}")
            print(f"  Cmdline: {proc['cmdline'][:80]}")
            print(f"  Created: {proc['create_time']}")
            print()
            for finding in data["findings"]:
                print(f"    {finding}")
            print()
            print("  " + "-" * 60)
            print()
    else:
        print("\n  [+] No se detectaron anomalías en los procesos analizados.")
    
    # Resumen
    critical = sum(1 for d in all_findings.values() for f in d["findings"] if "[CRITICAL]" in f)
    high = sum(1 for d in all_findings.values() for f in d["findings"] if "[HIGH]" in f)
    medium = sum(1 for d in all_findings.values() for f in d["findings"] if "[MEDIUM]" in f)
    
    print(f"\n{'='*70}")
    print(f"  RESUMEN: {critical} CRITICAL | {high} HIGH | {medium} MEDIUM")
    print(f"{'='*70}")
    
    if not target_pid:
        print("\n  Tip: Use --pid <PID> para analizar un proceso específico")
        print("  Tip: Use --verbose para más detalles")


if __name__ == "__main__":
    main()
