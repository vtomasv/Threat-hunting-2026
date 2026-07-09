#!/usr/bin/env python3
"""
injection_analyzer.py - Detecta técnicas de Process Injection
Curso MAR404 - Clase 6
"""
import json, sys, os
DATA_DIR = "/data"

def analyze():
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    with open(f"{DATA_DIR}/vad_data.json") as f:
        vad_data = json.load(f)
    with open(f"{DATA_DIR}/threads.json") as f:
        threads = json.load(f)
    with open(f"{DATA_DIR}/connections.json") as f:
        connections = json.load(f)
    
    full = "--full" in sys.argv
    
    print("=" * 70)
    print("  INJECTION ANALYZER — Detección de Process Injection")
    print("  Curso MAR404 - Cacería de Amenazas")
    print("=" * 70)
    
    findings = []
    
    # Análisis de VAD
    print("\n[*] Analizando Virtual Address Descriptors (VAD)...")
    for pid_str, data in vad_data.items():
        pid = int(pid_str)
        proc = next((p for p in processes if p["pid"] == pid), None)
        if not proc:
            continue
        
        for vad in data["vads"]:
            if vad["suspicious"]:
                finding = {
                    "pid": pid,
                    "process": proc["name"],
                    "type": "VAD_ANOMALY",
                    "severity": "CRITICAL",
                    "detail": vad["notes"],
                    "vad_range": f"{vad['start']} - {vad['end']}",
                    "protection": vad["protection"],
                }
                
                # Clasificar tipo de inyección
                if vad.get("hex_dump") and "4d 5a" in vad.get("hex_dump", ""):
                    finding["injection_type"] = "PE Injection / Process Hollowing"
                    finding["evidence"] = "MZ header detectado en región RWX"
                elif vad.get("hex_dump") and "fc 48" in vad.get("hex_dump", ""):
                    finding["injection_type"] = "Shellcode Injection (APC/Thread)"
                    finding["evidence"] = "Shellcode x64 pattern (fc 48 83 e4 f0)"
                elif vad.get("file") and "Temp" in str(vad.get("file", "")):
                    finding["injection_type"] = "Classic DLL Injection"
                    finding["evidence"] = f"DLL cargada desde path temporal: {vad['file']}"
                
                findings.append(finding)
    
    # Análisis de threads
    print("[*] Analizando threads con start address anómalo...")
    for pid_str, thread_list in threads.items():
        pid = int(pid_str)
        proc = next((p for p in processes if p["pid"] == pid), None)
        for t in thread_list:
            if t["suspicious"]:
                findings.append({
                    "pid": pid,
                    "process": proc["name"] if proc else "Unknown",
                    "type": "THREAD_ANOMALY",
                    "severity": "HIGH",
                    "detail": t["notes"],
                    "tid": t["tid"],
                    "start_address": t["start_address"],
                })
    
    # Análisis de handles cross-process
    print("[*] Analizando handles cross-process...")
    for pid_str, data in vad_data.items():
        pid = int(pid_str)
        if "handles_cross_process" in data:
            proc = next((p for p in processes if p["pid"] == pid), None)
            for h in data["handles_cross_process"]:
                findings.append({
                    "pid": pid,
                    "process": proc["name"] if proc else "Unknown",
                    "type": "CROSS_PROCESS_HANDLE",
                    "severity": "HIGH",
                    "detail": f"Handle {h['access']} a PID {h['target_pid']} — {h['notes']}",
                })
    
    # Análisis de conexiones
    print("[*] Correlacionando con conexiones de red...")
    for conn in connections:
        if conn.get("is_malicious"):
            proc = next((p for p in processes if p["pid"] == conn["pid"]), None)
            findings.append({
                "pid": conn["pid"],
                "process": proc["name"] if proc else "Unknown",
                "type": "MALICIOUS_CONNECTION",
                "severity": "CRITICAL",
                "detail": f"{conn['local']} → {conn['remote']} | {conn.get('notes', '')}",
            })
    
    # Reportar
    print(f"\n{'!'*70}")
    print(f"  HALLAZGOS TOTALES: {len(findings)}")
    print(f"{'!'*70}\n")
    
    for i, f in enumerate(findings, 1):
        sev_color = "CRITICAL" if f["severity"] == "CRITICAL" else "HIGH"
        print(f"  [{i:02d}] [{f['severity']}] PID {f['pid']} ({f['process']}) — {f['type']}")
        print(f"       {f['detail']}")
        if f.get("injection_type"):
            print(f"       → Tipo: {f['injection_type']}")
        if f.get("evidence"):
            print(f"       → Evidencia: {f['evidence']}")
        print()
    
    # Resumen por técnica
    print(f"\n{'='*70}")
    print("  RESUMEN POR TÉCNICA DE INYECCIÓN:")
    print(f"{'='*70}")
    
    techniques_found = set()
    for f in findings:
        if f.get("injection_type"):
            techniques_found.add(f["injection_type"])
    
    for tech in techniques_found:
        related = [f for f in findings if f.get("injection_type") == tech]
        pids = set(f["pid"] for f in related)
        print(f"\n  {tech}:")
        for pid in pids:
            proc = next((p for p in processes if p["pid"] == pid), None)
            print(f"    → PID {pid} ({proc['name'] if proc else 'Unknown'})")
    
    if full:
        print(f"\n\n{'='*70}")
        print("  [SOLUCIÓN COMPLETA]")
        print(f"{'='*70}")
        for p in processes:
            if p.get("is_malicious"):
                print(f"\n  PID {p['pid']} - {p['name']}: {p.get('technique', 'N/A')}")
                print(f"  Nota: {p.get('note', 'N/A')}")


if __name__ == "__main__":
    analyze()
