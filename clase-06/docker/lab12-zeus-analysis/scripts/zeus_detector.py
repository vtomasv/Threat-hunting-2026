#!/usr/bin/env python3
"""
zeus_detector.py - Detecta indicadores de Zeus Botnet en memoria
Curso MAR404 - Clase 6
"""
import json, sys
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    with open(f"{DATA_DIR}/hooks.json") as f:
        hooks = json.load(f)
    with open(f"{DATA_DIR}/zeus_config.json") as f:
        config = json.load(f)
    with open(f"{DATA_DIR}/connections.json") as f:
        connections = json.load(f)
    with open(f"{DATA_DIR}/registry.json") as f:
        registry = json.load(f)
    
    print("=" * 70)
    print("  ZEUS BOTNET DETECTOR")
    print("  Análisis de indicadores de Zeus/Zbot en memoria")
    print("=" * 70)
    
    findings = []
    
    # 1. Detectar procesos inyectados
    print("\n[1] Analizando procesos inyectados...")
    hooked_pids = hooks.get("hooked_processes", [])
    for pid in hooked_pids:
        proc = next((p for p in processes if p["pid"] == pid), None)
        if proc:
            findings.append(f"[CRITICAL] PID {pid} ({proc['name']}) — Proceso con API hooks (inyectado por Zeus)")
    
    # 2. Detectar API hooks
    print("[2] Analizando API hooks...")
    for hook in hooks["hooks"]:
        findings.append(
            f"[CRITICAL] Hook en {hook['process']} (PID {hook['pid']}): "
            f"{hook['module']}!{hook['function']} → {hook['destination']}\n"
            f"           Propósito: {hook['purpose']}"
        )
    
    # 3. Detectar conexiones C2
    print("[3] Analizando conexiones C2...")
    for conn in connections:
        if conn.get("is_malicious"):
            findings.append(f"[HIGH] Conexión C2: {conn['local']} → {conn['remote']} ({conn['notes']})")
    
    # 4. Detectar persistencia
    print("[4] Analizando persistencia en registry...")
    for reg in registry:
        if reg["suspicious"]:
            findings.append(
                f"[HIGH] Persistencia: {reg['key']}\\{reg['value']} = {reg['data']}\n"
                f"           {reg['notes']}"
            )
    
    # 5. Mutex
    print("[5] Verificando mutex...")
    findings.append(f"[MEDIUM] Mutex detectado: {config['persistence']['mutex']}")
    
    # Reportar
    print(f"\n{'!'*70}")
    print(f"  HALLAZGOS: {len(findings)}")
    print(f"{'!'*70}\n")
    for i, f_item in enumerate(findings, 1):
        print(f"  [{i:02d}] {f_item}\n")
    
    # IOC Summary
    print(f"\n{'='*70}")
    print("  RESUMEN DE IOCs")
    print(f"{'='*70}")
    print(f"\n  Botnet ID: {config['botnet_id']}")
    print(f"  Versión: {config['version']}")
    print(f"\n  C2 URLs:")
    for c2 in config["c2_urls"]:
        print(f"    [{c2['status']}] {c2['url']}")
    print(f"\n  Banking Targets:")
    for t in config["targets"]:
        print(f"    {t['url_pattern']} → {t['action']}")
    print(f"\n  Persistencia:")
    print(f"    Registry: {config['persistence']['registry_key']}\\{config['persistence']['registry_value']}")
    print(f"    Path: {config['persistence']['install_path']}")
    print(f"    Mutex: {config['persistence']['mutex']}")
    
    if "--full" in sys.argv:
        print(f"\n\n  DGA Domains (sample): {', '.join(config['dga_domains_sample'])}")
        print(f"  RC4 Key: {config['rc4_key_hex']}")
        print(f"  Exfil interval: {config['exfil']['interval_seconds']}s")
        print(f"  Data types: {', '.join(config['exfil']['data_types'])}")

if __name__ == "__main__":
    main()
