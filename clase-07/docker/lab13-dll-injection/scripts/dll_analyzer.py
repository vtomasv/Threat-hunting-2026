#!/usr/bin/env python3
"""
dll_analyzer.py - Analiza DLLs cargadas y detecta Side-Loading
Curso MAR404 - Clase 7
"""
import json, sys
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/dll_data.json") as f:
        dll_data = json.load(f)
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  DLL ANALYZER — Detección de DLL Side-Loading")
    print("=" * 70)
    
    for pid_str, data in dll_data.items():
        pid = int(pid_str)
        proc = next((p for p in processes if p["pid"] == pid), None)
        print(f"\n  Proceso: {proc['name'] if proc else 'Unknown'} (PID {pid})")
        print(f"  Path: {proc.get('path', 'N/A')}")
        print(f"  {'─'*60}")
        
        for dll in data["loaded_dlls"]:
            status = "[!] SUSPICIOUS" if dll["suspicious"] else "[OK]"
            signed = "Signed" if dll["signed"] else "UNSIGNED"
            print(f"\n  {status} {dll['name']}")
            print(f"    Path: {dll['path']}")
            print(f"    Base: {dll['base']} | Size: {dll['size']}")
            print(f"    Firma: {signed} ({dll.get('signer', 'N/A')})")
            
            if dll["suspicious"]:
                print(f"\n    {'!'*50}")
                print(f"    ALERTA: DLL SIDE-LOADING DETECTADO")
                print(f"    {'!'*50}")
                print(f"    Path legítimo: {dll.get('legitimate_path', 'N/A')}")
                print(f"    Path actual:   {dll['path']}")
                print(f"    Notas: {dll.get('notes', '')}")
                
                if dll.get("exports"):
                    print(f"\n    Exports:")
                    for exp in dll["exports"]:
                        flag = " ← SOSPECHOSO" if exp in dll.get("suspicious_exports", []) else ""
                        print(f"      {exp}{flag}")
                
                if dll.get("imports_suspicious"):
                    print(f"\n    Imports sospechosos:")
                    for imp in dll["imports_suspicious"]:
                        print(f"      {imp}")
                
                if dll.get("strings"):
                    print(f"\n    Strings relevantes:")
                    for s in dll["strings"]:
                        print(f"      \"{s}\"")
        
        # VAD analysis
        if "vad_suspicious" in data:
            print(f"\n\n  {'='*60}")
            print(f"  VAD SOSPECHOSOS (PID {pid}):")
            for vad in data["vad_suspicious"]:
                print(f"\n    {vad['start']} - {vad['end']}")
                print(f"    Protection: {vad['protection']}")
                print(f"    Type: {vad['type']} | File: {vad.get('file', 'Private')}")
                print(f"    → {vad['notes']}")

if __name__ == "__main__":
    main()
