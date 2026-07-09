#!/usr/bin/env python3
"""
trojan_profiler.py - Perfila las capacidades del troyano
Curso MAR404 - Clase 7
"""
import json
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/trojan_profile.json") as f:
        data = json.load(f)
    
    profile = data["trojan_profile"]
    
    print("=" * 70)
    print("  TROJAN PROFILER — Análisis de Capacidades")
    print("=" * 70)
    
    print(f"\n  Nombre:    {profile['name']}")
    print(f"  Familia:   {profile['family']}")
    print(f"  Delivery:  {profile['delivery']}")
    print(f"  Capacidades: {len(profile['capabilities'])}")
    
    print(f"\n  {'─'*60}")
    print(f"  CAPACIDADES IDENTIFICADAS:")
    print(f"  {'─'*60}")
    
    for i, cap in enumerate(profile["capabilities"], 1):
        print(f"\n  [{i}] {cap['name']}")
        print(f"      Técnica:  {cap['technique']}")
        print(f"      MITRE:    {cap['mitre']}")
        if cap.get("output_file"):
            print(f"      Output:   {cap['output_file']}")
        if cap.get("c2_url"):
            print(f"      C2 URL:   {cap['c2_url']}")
            print(f"      Interval: {cap['interval']}")
            print(f"      Encoding: {cap['encoding']}")
        if cap.get("task_name"):
            print(f"      Task:     {cap['task_name']}")
        print(f"      Evidencia: {cap['evidence']}")
    
    # Conexiones
    print(f"\n\n  {'─'*60}")
    print(f"  CONEXIONES DE RED:")
    print(f"  {'─'*60}")
    for conn in data["network_connections"]:
        print(f"  PID {conn['pid']} → {conn['remote']} [{conn['state']}]")
        print(f"    {conn['notes']}")
    
    # Persistencia
    print(f"\n  {'─'*60}")
    print(f"  PERSISTENCIA:")
    print(f"  {'─'*60}")
    for p in data["persistence"]:
        print(f"  [{p['type']}] {p['name']}")
        print(f"    Action: {p['action']}")
        print(f"    Trigger: {p['trigger']}")
    
    # Resumen MITRE
    print(f"\n\n  {'='*60}")
    print(f"  MAPEO MITRE ATT&CK:")
    print(f"  {'='*60}")
    for cap in profile["capabilities"]:
        print(f"  {cap['mitre']:<40} → {cap['name']}")

if __name__ == "__main__":
    main()
