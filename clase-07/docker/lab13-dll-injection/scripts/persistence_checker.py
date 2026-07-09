#!/usr/bin/env python3
"""
persistence_checker.py - Verifica mecanismos de persistencia
Curso MAR404 - Clase 7
"""
import json
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/trojan_profile.json") as f:
        data = json.load(f)
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    print("=" * 70)
    print("  PERSISTENCE CHECKER — Mecanismos de Persistencia")
    print("=" * 70)
    
    # Check scheduled tasks
    print("\n  [1] SCHEDULED TASKS:")
    schtasks = [p for p in processes if p["name"] == "schtasks.exe"]
    for p in schtasks:
        print(f"      PID {p['pid']} | PPID {p['ppid']}")
        print(f"      CMD: {p.get('cmdline', 'N/A')}")
        print(f"      Time: {p['create_time']}")
        if p.get("is_malicious"):
            print(f"      [!] MALICIOSO: {p.get('note', '')}")
    
    # Check persistence from trojan profile
    print("\n  [2] PERSISTENCIA CONFIGURADA:")
    for p in data.get("persistence", []):
        status = "[!] SUSPICIOUS" if p.get("suspicious") else "[OK]"
        print(f"      {status} {p['type']}: {p['name']}")
        print(f"      Action: {p['action']}")
        print(f"      Trigger: {p['trigger']}")
    
    # DLL Side-Loading persistence
    print("\n  [3] DLL SIDE-LOADING (PERSISTENCIA IMPLÍCITA):")
    print("      La DLL maliciosa (version.dll) se carga automáticamente")
    print("      cada vez que OneDriveUpdater.exe se ejecuta.")
    print("      Combinado con Scheduled Task → persistencia completa.")
    
    print(f"\n\n  {'='*60}")
    print("  CADENA DE PERSISTENCIA:")
    print(f"  {'='*60}")
    print("""
      Scheduled Task (hourly)
          ↓
      OneDriveUpdater.exe (legítimo, firmado)
          ↓
      version.dll (maliciosa, side-loaded)
          ↓
      Troyano activo (keylogger + exfil)
    
    Ventajas para el atacante:
    • El ejecutable es legítimo y firmado por Microsoft
    • La tarea programada parece una actualización normal
    • Solo la DLL es maliciosa (más difícil de detectar)
    • Sobrevive reinicios automáticamente
    """)

if __name__ == "__main__":
    main()
