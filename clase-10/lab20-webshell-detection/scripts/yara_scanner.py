#!/usr/bin/env python3
"""
yara_scanner.py - Scanner YARA para detección de web shells
MAR404 - Lab 20
"""
import os, sys
from rich.console import Console
from rich.panel import Panel
console = Console()

WEBROOT = "/evidence/server-image/var/www/html"
YARA_DIR = "/investigation/yara-rules"

def scan():
    try:
        import yara
    except ImportError:
        console.print("[red]YARA no disponible. Instalar con: pip3 install yara-python[/red]")
        return
    
    console.print(Panel.fit("[bold green]YARA WEB SHELL SCANNER[/bold green]", border_style="green"))
    
    # Compilar todas las reglas
    rule_files = [f for f in os.listdir(YARA_DIR) if f.endswith('.yar')]
    
    if not rule_files:
        console.print("[yellow]No se encontraron reglas YARA en /investigation/yara-rules/[/yellow]")
        console.print("Crea tus propias reglas y vuelve a ejecutar este scanner.")
        return
    
    console.print(f"[+] Cargando {len(rule_files)} archivos de reglas...")
    
    for rule_file in rule_files:
        rule_path = os.path.join(YARA_DIR, rule_file)
        try:
            rules = yara.compile(filepath=rule_path)
            console.print(f"  [green]✓[/green] {rule_file}")
        except yara.SyntaxError as e:
            console.print(f"  [red]✗[/red] {rule_file}: {e}")
            continue
        
        # Escanear webroot
        matches_found = 0
        for root, _, files in os.walk(WEBROOT):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    matches = rules.match(fpath)
                    if matches:
                        matches_found += 1
                        rel_path = fpath.replace(WEBROOT, '')
                        console.print(f"\n  [red]⚠ MATCH en {rel_path}[/red]")
                        for m in matches:
                            console.print(f"    Regla: {m.rule}")
                            for s in m.strings:
                                console.print(f"    String: offset={s[0]}, id={s[1]}, data={s[2][:50]}")
                except:
                    pass
        
        if matches_found == 0:
            console.print(f"    Sin coincidencias para {rule_file}")
    
    console.print(f"\n[bold]Escaneo completado.[/bold]")

if __name__ == "__main__":
    scan()
