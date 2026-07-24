#!/usr/bin/env python3
"""
ioc_extractor.py - Extractor de Indicadores de Compromiso
MAR404 - Lab 20
"""
import re, os, sys, json, hashlib
from collections import Counter
from rich.console import Console
from rich.panel import Panel
console = Console()

WEBROOT = "/evidence/server-image/var/www/html"
LOG_FILE = "/evidence/server-image/var/log/apache2/access.log"

def extract_iocs():
    console.print(Panel.fit("[bold red]EXTRACCIÓN DE IOCs[/bold red]", border_style="red"))
    
    iocs = {
        "ips": set(),
        "domains": set(),
        "file_hashes": [],
        "suspicious_files": [],
        "user_agents": set(),
        "urls": set()
    }
    
    # Extraer IPs externas de logs
    console.print("\n[bold]1. IPs externas del log de acceso:[/bold]")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            for line in f:
                ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if not ip.startswith(('10.', '192.168.', '172.16.')):
                        iocs['ips'].add(ip)
    
    for ip in sorted(iocs['ips']):
        console.print(f"  [red]{ip}[/red]")
    
    # Calcular hashes de archivos sospechosos
    console.print("\n[bold]2. Hashes de archivos sospechosos:[/bold]")
    for root, _, files in os.walk(WEBROOT):
        for fname in files:
            if '.php' in fname.lower():
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        content = f.read()
                    
                    # Buscar funciones peligrosas
                    text = content.decode('utf-8', errors='ignore')
                    if any(func in text for func in ['eval(', 'system(', 'shell_exec(', 'exec(']):
                        md5 = hashlib.md5(content).hexdigest()
                        sha256 = hashlib.sha256(content).hexdigest()
                        rel_path = fpath.replace(WEBROOT, '')
                        iocs['file_hashes'].append({
                            'file': rel_path,
                            'md5': md5,
                            'sha256': sha256,
                            'size': len(content)
                        })
                        console.print(f"  [yellow]{rel_path}[/yellow]")
                        console.print(f"    MD5:    {md5}")
                        console.print(f"    SHA256: {sha256}")
                except:
                    pass
    
    # Extraer User-Agents sospechosos
    console.print("\n[bold]3. User-Agents sospechosos:[/bold]")
    if os.path.exists(LOG_FILE):
        ua_pattern = re.compile(r'"([^"]*)"$')
        with open(LOG_FILE) as f:
            for line in f:
                parts = line.split('"')
                if len(parts) >= 6:
                    ua = parts[5]
                    if any(s in ua.lower() for s in ['python', 'curl', 'wget', 'msie 6', 'msie 5']):
                        iocs['user_agents'].add(ua)
    
    for ua in sorted(iocs['user_agents']):
        console.print(f"  [yellow]{ua}[/yellow]")
    
    # Guardar IOCs en archivo JSON
    output = {
        "ips": sorted(list(iocs['ips'])),
        "file_hashes": iocs['file_hashes'],
        "user_agents": sorted(list(iocs['user_agents']))
    }
    
    output_path = "/investigation/findings/extracted_iocs.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    console.print(f"\n[green]IOCs guardados en: {output_path}[/green]")

if __name__ == "__main__":
    extract_iocs()
