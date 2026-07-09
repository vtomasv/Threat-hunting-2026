#!/usr/bin/env python3
"""
attack_mapper.py - Mapea el ataque a MITRE ATT&CK
Curso MAR404 - Clase 7 - Lab 14
"""
import json
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  ATTACK MAPPER — Mapeo MITRE ATT&CK")
    print("=" * 70)
    
    mal_procs = [p for p in processes if p.get("is_malicious")]
    
    # Agrupar por táctica
    tactics = {
        "Initial Access": [],
        "Execution": [],
        "Credential Access": [],
        "Discovery": [],
        "Lateral Movement": [],
        "Collection": [],
    }
    
    for p in mal_procs:
        phase = p.get("phase", "Unknown")
        if phase in tactics:
            tactics[phase].append(p)
    
    for tactic, procs in tactics.items():
        if procs:
            print(f"\n  {'━'*60}")
            print(f"  {tactic.upper()}")
            print(f"  {'━'*60}")
            for p in procs:
                print(f"    {p.get('technique', 'N/A')}")
                print(f"      Proceso: {p['name']} (PID {p['pid']})")
                print(f"      Evidencia: {p.get('note', '')}")
                print()
    
    # ATT&CK Navigator JSON
    print(f"\n  {'='*60}")
    print("  TÉCNICAS PARA ATT&CK NAVIGATOR:")
    print(f"  {'='*60}")
    techniques = set()
    for p in mal_procs:
        tech = p.get("technique", "")
        if tech:
            tid = tech.split(" - ")[0]
            techniques.add(tid)
    
    for t in sorted(techniques):
        proc = next((p for p in mal_procs if p.get("technique","").startswith(t)), None)
        name = proc.get("technique","").split(" - ")[1] if proc else ""
        print(f"    {t:<15} {name}")
    
    print(f"\n  Total técnicas únicas: {len(techniques)}")
    print(f"  Tácticas cubiertas: {sum(1 for v in tactics.values() if v)}/{len(tactics)}")

if __name__ == "__main__":
    main()
