#!/usr/bin/env python3
"""
vad_inspector.py - Inspecciona VADs de un proceso específico
Uso: vad_inspector --pid <PID>
Curso MAR404 - Clase 6
"""
import json, sys
DATA_DIR = "/data"

def main():
    if "--pid" not in sys.argv:
        print("Uso: vad_inspector --pid <PID>")
        print("\nProcesos disponibles:")
        with open(f"{DATA_DIR}/processes.json") as f:
            for p in json.load(f):
                print(f"  PID {p['pid']:>6} | {p['name']:<20} | {p.get('user', 'N/A')}")
        return
    
    pid = int(sys.argv[sys.argv.index("--pid") + 1])
    
    with open(f"{DATA_DIR}/vad_data.json") as f:
        vad_data = json.load(f)
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    proc = next((p for p in processes if p["pid"] == pid), None)
    pid_str = str(pid)
    
    if pid_str not in vad_data:
        print(f"[!] No hay datos VAD para PID {pid}")
        return
    
    data = vad_data[pid_str]
    
    print(f"\n{'='*70}")
    print(f"  VAD INSPECTOR — PID {pid} ({proc['name'] if proc else 'Unknown'})")
    print(f"{'='*70}\n")
    
    print(f"  {'Start':<14}{'End':<14}{'Protection':<28}{'Type':<10}{'File/Status'}")
    print(f"  {'-'*80}")
    
    for vad in data["vads"]:
        status = vad.get("file", "Private (no file)")
        if vad["suspicious"]:
            status = f"[SUSPICIOUS] {status}"
        print(f"  {vad['start']:<14}{vad['end']:<14}{vad['protection']:<28}{vad['type']:<10}{status}")
    
    # Detalles de regiones sospechosas
    suspicious_vads = [v for v in data["vads"] if v["suspicious"]]
    if suspicious_vads:
        print(f"\n\n  {'!'*60}")
        print(f"  REGIONES SOSPECHOSAS: {len(suspicious_vads)}")
        print(f"  {'!'*60}")
        
        for vad in suspicious_vads:
            print(f"\n  Rango: {vad['start']} - {vad['end']}")
            print(f"  Protección: {vad['protection']}")
            print(f"  Análisis: {vad['notes']}")
            if vad.get("hex_dump"):
                print(f"\n  Hex Dump:")
                for line in vad["hex_dump"].strip().split("\n"):
                    print(f"    {line}")
    
    # Info adicional
    if "injected_dll" in data:
        dll = data["injected_dll"]
        print(f"\n\n  {'='*60}")
        print(f"  DLL INYECTADA DETECTADA:")
        print(f"  {'='*60}")
        print(f"  Nombre: {dll['name']}")
        print(f"  Path: {dll['path']}")
        print(f"  Firmada: {'Sí' if dll['signed'] else 'NO'}")
        print(f"  Exports: {', '.join(dll['exports'])}")
        print(f"  Imports sospechosos: {', '.join(dll['imports'][:5])}")
        print(f"\n  Strings sospechosos:")
        for s in dll["strings_suspicious"]:
            print(f"    → {s}")
    
    if "hollowing_evidence" in data:
        h = data["hollowing_evidence"]
        print(f"\n\n  {'='*60}")
        print(f"  EVIDENCIA DE PROCESS HOLLOWING:")
        print(f"  {'='*60}")
        print(f"  Imagen original: {h['original_image']}")
        print(f"  PEB ImageBase: {h['peb_image_base']}")
        print(f"  Contenido actual: {h['actual_content']}")
        print(f"  Entry point diferente: {h['entry_point_diff']}")
        print(f"  Secciones: {', '.join(h['section_names'])}")
        print(f"  Notas: {h['notes']}")
    
    if "apc_evidence" in data:
        a = data["apc_evidence"]
        print(f"\n\n  {'='*60}")
        print(f"  EVIDENCIA DE APC INJECTION:")
        print(f"  {'='*60}")
        print(f"  Thread con APC: TID {a['thread_with_apc']}")
        print(f"  Dirección target: {a['apc_target_address']}")
        print(f"  Tipo shellcode: {a['shellcode_type']}")
        print(f"  Callback: {a['callback_ip']}")
        print(f"  Notas: {a['notes']}")
    
    if "handles_cross_process" in data:
        print(f"\n\n  {'='*60}")
        print(f"  HANDLES CROSS-PROCESS (INJECTOR):")
        print(f"  {'='*60}")
        for h in data["handles_cross_process"]:
            print(f"  → Target PID {h['target_pid']} | Access: {h['access']}")
            print(f"    {h['notes']}")


if __name__ == "__main__":
    main()
