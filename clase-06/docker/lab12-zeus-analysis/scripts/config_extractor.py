#!/usr/bin/env python3
"""
config_extractor.py - Extrae y descifra configuración de Zeus
Curso MAR404 - Clase 6
"""
import json, base64
DATA_DIR = "/data"

def main():
    print("=" * 70)
    print("  CONFIG EXTRACTOR — Descifrado de Configuración Zeus")
    print("=" * 70)
    
    # Leer blob cifrado
    print("\n[1] Leyendo blob cifrado...")
    with open(f"{DATA_DIR}/zeus_encrypted_config.bin") as f:
        lines = f.readlines()
    
    key_line = [l for l in lines if "Key" in l][0]
    b64_data = [l for l in lines if not l.startswith("#") and l.strip()][0]
    
    print(f"    Archivo: zeus_encrypted_config.bin")
    print(f"    {key_line.strip()}")
    print(f"    Base64 length: {len(b64_data.strip())} chars")
    
    # Descifrar (simulado - en realidad es base64 directo para el lab)
    print("\n[2] Descifrando con RC4...")
    decoded = base64.b64decode(b64_data.strip())
    config_data = json.loads(decoded)
    
    print(f"    Descifrado exitoso: {len(config_data)} entradas")
    
    # Mostrar configuración completa
    with open(f"{DATA_DIR}/zeus_config.json") as f:
        full_config = json.load(f)
    
    print(f"\n[3] Configuración completa del bot:")
    print(f"\n    {'─'*50}")
    print(f"    IDENTIFICACIÓN")
    print(f"    {'─'*50}")
    print(f"    Botnet ID:    {full_config['botnet_id']}")
    print(f"    Versión:      {full_config['version']}")
    print(f"    Cifrado:      {full_config['encryption']}")
    print(f"    DGA Seed:     {full_config['dga_seed']}")
    
    print(f"\n    {'─'*50}")
    print(f"    COMMAND & CONTROL")
    print(f"    {'─'*50}")
    for c2 in full_config["c2_urls"]:
        status = "✓" if c2["status"] == "active" else "✗"
        print(f"    [{status}] {c2['url']} ({c2['type']})")
    
    print(f"\n    DGA Domains (muestra):")
    for d in full_config["dga_domains_sample"]:
        print(f"      → {d}")
    
    print(f"\n    {'─'*50}")
    print(f"    TARGETS BANCARIOS")
    print(f"    {'─'*50}")
    for t in full_config["targets"]:
        print(f"    URL: {t['url_pattern']}")
        print(f"    Acción: {t['action']}")
        if t["fields"]:
            print(f"    Campos: {', '.join(t['fields'])}")
        print()
    
    print(f"    {'─'*50}")
    print(f"    PERSISTENCIA")
    print(f"    {'─'*50}")
    p = full_config["persistence"]
    print(f"    Registry: {p['registry_key']}\\{p['registry_value']}")
    print(f"    Data:     {p['registry_data']}")
    print(f"    Mutex:    {p['mutex']}")
    print(f"    Install:  {p['install_path']}")
    
    print(f"\n    {'─'*50}")
    print(f"    EXFILTRACIÓN")
    print(f"    {'─'*50}")
    e = full_config["exfil"]
    print(f"    Método:   {e['method']}")
    print(f"    Encoding: {e['encoding']}")
    print(f"    Intervalo: {e['interval_seconds']}s")
    print(f"    Datos:    {', '.join(e['data_types'])}")
    
    # Generar IOC file
    print(f"\n\n{'='*70}")
    print("  IOCs EXTRAÍDOS (formato para SIEM/Firewall)")
    print(f"{'='*70}")
    print("\n  # IPs de C2")
    for c2 in full_config["c2_urls"]:
        ip = c2["url"].split("//")[1].split("/")[0]
        print(f"  {ip}")
    print("\n  # Dominios DGA")
    for d in full_config["dga_domains_sample"]:
        print(f"  {d}")
    print(f"\n  # Mutex")
    print(f"  {p['mutex']}")
    print(f"\n  # File paths")
    print(f"  {p['install_path']}")
    print(f"\n  # Registry")
    print(f"  {p['registry_key']}\\{p['registry_value']}")

if __name__ == "__main__":
    main()
