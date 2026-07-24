#!/usr/bin/env python3
"""
=============================================================================
userassist_decoder.py - Decodificador de UserAssist (ROT13)
=============================================================================
Decodifica y analiza las entradas UserAssist del registro de Windows.

UserAssist almacena información sobre programas ejecutados por el usuario
a través del shell de Windows (Explorer.exe). Los nombres están codificados
en ROT13 como "protección" básica.

Uso:
    python3 userassist_decoder.py              # Análisis completo
    python3 userassist_decoder.py --raw        # Muestra datos RAW (codificados)
    python3 userassist_decoder.py --decode     # Decodifica paso a paso
    python3 userassist_decoder.py --focus      # Análisis de focus time
    python3 userassist_decoder.py --background # Detecta ejecuciones en background

Autor: MAR404 - Cacería de Amenazas
=============================================================================
"""

import json
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
EVIDENCE_DIR = "/cases/SRV-FIN-01/userassist"


def rot13_decode(text):
    """Decodifica ROT13."""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def load_data(raw=False):
    """Carga datos de UserAssist."""
    if raw:
        path = f"{EVIDENCE_DIR}/raw/userassist_raw.json"
    else:
        path = f"{EVIDENCE_DIR}/userassist_parsed.json"
    
    if not os.path.exists(path):
        console.print(f"[red]ERROR: No se encontró {path}[/red]")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def analyze_all():
    """Análisis completo de UserAssist."""
    entries = load_data()
    
    console.print(Panel.fit(
        "[bold cyan]USERASSIST ANALYSIS — SRV-FIN-01[/bold cyan]\n"
        f"Total de entradas: {len(entries)}\n"
        f"Maliciosas: {len([e for e in entries if e['category']=='malicious'])}\n"
        f"Sospechosas: {len([e for e in entries if e['category']=='suspicious'])}",
        title="Resumen UserAssist", border_style="cyan"
    ))
    
    table = Table(title="Entradas UserAssist Decodificadas", box=box.DOUBLE_EDGE)
    table.add_column("Estado", width=6)
    table.add_column("Programa", style="cyan", width=25)
    table.add_column("Runs", justify="center", width=5)
    table.add_column("Focus", justify="center", width=5)
    table.add_column("Focus Time", width=12)
    table.add_column("Última Ejecución", width=20)
    
    for entry in entries:
        if entry['category'] == 'malicious':
            status = "[red]◉ MAL[/red]"
        elif entry['category'] == 'suspicious':
            status = "[yellow]◉ SUS[/yellow]"
        else:
            status = "[green]◉ OK[/green]"
        
        table.add_row(
            status,
            entry['program'],
            str(entry['run_count']),
            str(entry['focus_count']),
            entry['focus_time_human'],
            entry['last_execution'][:19]
        )
    
    console.print(table)
    
    # Explicación
    console.print("\n[dim]Focus Count: Veces que la ventana tuvo el foco (interacción del usuario)")
    console.print("Focus Time: Tiempo total que la ventana estuvo en primer plano")
    console.print("Focus = 0: El programa se ejecutó en BACKGROUND (sin ventana visible)[/dim]")


def show_raw():
    """Muestra datos RAW codificados en ROT13."""
    raw_entries = load_data(raw=True)
    
    console.print(Panel.fit(
        "[bold yellow]USERASSIST RAW DATA (ROT13 ENCODED)[/bold yellow]\n"
        "Los nombres de programa están codificados en ROT13\n"
        "Usa --decode para ver el proceso de decodificación",
        border_style="yellow"
    ))
    
    for entry in raw_entries:
        console.print(f"\n[yellow]Value Name (ROT13):[/yellow]")
        console.print(f"  {entry['value_name']}")
        console.print(f"  Run Count: {entry['run_count']}")
        console.print(f"  Focus Count: {entry['focus_count']}")
        console.print(f"  Focus Time (ms): {entry['focus_time_ms']}")
        console.print(f"  Last Execution (FILETIME): {entry['last_execution_filetime']}")


def decode_step_by_step():
    """Decodifica ROT13 paso a paso (educativo)."""
    raw_entries = load_data(raw=True)
    
    console.print(Panel.fit(
        "[bold green]DECODIFICACIÓN ROT13 PASO A PASO[/bold green]\n"
        "ROT13 rota cada letra 13 posiciones en el alfabeto\n"
        "A→N, B→O, C→P, ... N→A, O→B, P→C, ...\n"
        "Los números y caracteres especiales NO se modifican",
        border_style="green"
    ))
    
    for entry in raw_entries:
        encoded = entry['value_name']
        decoded = rot13_decode(encoded)
        
        console.print(f"\n{'─' * 70}")
        console.print(f"[yellow]Codificado:[/yellow]  {encoded[:60]}...")
        console.print(f"[green]Decodificado:[/green] {decoded[:60]}...")
        
        # Extraer nombre del programa
        parts = decoded.split('\\')
        program = parts[-1] if parts else decoded
        console.print(f"[cyan]Programa:[/cyan]     {program}")
        console.print(f"  Ejecuciones: {entry['run_count']} | Focus: {entry['focus_count']}")


def analyze_focus():
    """Análisis de focus time para detectar ejecuciones interactivas vs background."""
    entries = load_data()
    
    console.print(Panel.fit(
        "[bold magenta]ANÁLISIS DE FOCUS TIME[/bold magenta]\n"
        "Focus Time alto = usuario interactuó con el programa\n"
        "Focus Time = 0 = ejecución en background (sospechoso para herramientas)",
        border_style="magenta"
    ))
    
    # Separar por tipo de ejecución
    interactive = [e for e in entries if e['focus_count'] > 0]
    background = [e for e in entries if e['focus_count'] == 0]
    
    console.print(f"\n[green]═══ EJECUCIONES INTERACTIVAS ({len(interactive)}) ═══[/green]")
    for entry in interactive:
        console.print(f"  {entry['program']}: {entry['focus_time_human']} de uso activo ({entry['run_count']} ejecuciones)")
    
    console.print(f"\n[red]═══ EJECUCIONES EN BACKGROUND ({len(background)}) ═══[/red]")
    for entry in background:
        cat_color = "red" if entry['category'] == 'malicious' else "yellow"
        console.print(f"  [{cat_color}]{entry['program']}: {entry['run_count']} ejecuciones SIN interacción de usuario[/{cat_color}]")
        if entry.get('notes'):
            console.print(f"    [italic]→ {entry['notes']}[/italic]")


def main():
    if len(sys.argv) < 2:
        analyze_all()
    elif sys.argv[1] == '--raw':
        show_raw()
    elif sys.argv[1] == '--decode':
        decode_step_by_step()
    elif sys.argv[1] == '--focus':
        analyze_focus()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 userassist_decoder.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)     Análisis completo decodificado
  --raw          Muestra datos RAW (codificados en ROT13)
  --decode       Decodificación paso a paso (educativo)
  --focus        Análisis de focus time (interactivo vs background)
  --help         Muestra esta ayuda

[bold]Concepto:[/bold]
  UserAssist registra programas ejecutados via Explorer shell.
  Los nombres se codifican en ROT13 (cifrado de sustitución simple).
  Focus Count = 0 indica ejecución sin ventana visible (background/C2).
        """)
    else:
        analyze_all()


if __name__ == "__main__":
    main()
