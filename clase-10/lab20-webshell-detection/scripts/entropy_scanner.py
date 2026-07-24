#!/usr/bin/env python3
"""
entropy_scanner.py - Scanner de entropía para detección de ofuscación
MAR404 - Lab 20
"""
import os, sys, math
from collections import Counter
from rich.console import Console
from rich.table import Table
console = Console()

WEBROOT = "/evidence/server-image/var/www/html"

def entropy(data):
    if not data: return 0
    c = Counter(data)
    l = len(data)
    return -sum((n/l)*math.log2(n/l) for n in c.values())

def scan():
    console.print("[bold]Escaneando entropía de archivos...[/bold]\n")
    results = []
    for root, _, files in os.walk(WEBROOT):
        for f in files:
            path = os.path.join(root, f)
            try:
                with open(path, 'r', errors='ignore') as fh:
                    content = fh.read()
                e = entropy(content)
                results.append((path.replace(WEBROOT,''), e, len(content)))
            except: pass
    
    results.sort(key=lambda x: x[1], reverse=True)
    
    table = Table(title="Entropía de Archivos (Top 20)")
    table.add_column("Archivo", width=50)
    table.add_column("Entropía", width=10)
    table.add_column("Tamaño", width=10)
    table.add_column("Alerta", width=10)
    
    for path, e, size in results[:20]:
        alert = "[red]⚠ ALTA[/red]" if e > 5.5 else "[yellow]MEDIA[/yellow]" if e > 5.0 else "[green]OK[/green]"
        table.add_row(path, f"{e:.3f}", str(size), alert)
    
    console.print(table)
    console.print(f"\n[dim]Umbral de alerta: > 5.5 (código normal PHP: 4.0-5.0)[/dim]")

if __name__ == "__main__":
    scan()
