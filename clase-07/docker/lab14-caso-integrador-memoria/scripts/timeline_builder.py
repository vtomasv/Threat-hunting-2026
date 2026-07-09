#!/usr/bin/env python3
"""
timeline_builder.py - Construye timeline del incidente
Curso MAR404 - Clase 7 - Lab 14
"""
import json
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  TIMELINE BUILDER — Reconstrucción del Incidente")
    print("=" * 70)
    
    mal_procs = sorted(
        [p for p in processes if p.get("is_malicious")],
        key=lambda x: x["create_time"]
    )
    
    print(f"\n  Eventos maliciosos: {len(mal_procs)}")
    print(f"  Primer evento: {mal_procs[0]['create_time']}")
    print(f"  Último evento: {mal_procs[-1]['create_time']}")
    
    current_phase = ""
    for i, p in enumerate(mal_procs, 1):
        phase = p.get("phase", "Unknown")
        if phase != current_phase:
            current_phase = phase
            print(f"\n  {'═'*60}")
            print(f"  FASE: {phase.upper()}")
            print(f"  {'═'*60}")
        
        print(f"\n  [{i:02d}] {p['create_time']}")
        print(f"      Proceso: {p['name']} (PID {p['pid']}, PPID {p['ppid']})")
        print(f"      User: {p.get('user', 'N/A')}")
        if p.get("cmdline"):
            cmd = p["cmdline"][:80] + "..." if len(p.get("cmdline","")) > 80 else p.get("cmdline","")
            print(f"      CMD: {cmd}")
        print(f"      Técnica: {p.get('technique', 'N/A')}")
        print(f"      Nota: {p.get('note', '')}")
    
    print(f"\n\n  {'='*60}")
    print("  RESUMEN DE FASES:")
    print(f"  {'='*60}")
    phases = {}
    for p in mal_procs:
        phase = p.get("phase", "Unknown")
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(p)
    
    for phase, procs in phases.items():
        print(f"\n  {phase}:")
        for p in procs:
            print(f"    → {p['name']} (PID {p['pid']}) — {p.get('technique','')}")

if __name__ == "__main__":
    main()
