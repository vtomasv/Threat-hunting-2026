#!/usr/bin/env python3
"""
=============================================================================
mft_analyzer.py - Analizador de MFT con detección de Timestomping
=============================================================================
Analiza la Master File Table para detectar manipulación de timestamps.

Concepto clave:
  - $STANDARD_INFORMATION (SI): Timestamps modificables por APIs de usuario
  - $FILE_NAME (FN): Timestamps que SOLO el kernel puede modificar

  Si SI.Created ≠ FN.Created → TIMESTOMPING DETECTADO (T1070.006)

Uso:
    python3 mft_analyzer.py                    # Análisis completo
    python3 mft_analyzer.py --timestomp        # Solo detección de timestomping
    python3 mft_analyzer.py --deleted          # Archivos eliminados (unallocated)
    python3 mft_analyzer.py --timeline         # Timeline basada en FN (real)
    python3 mft_analyzer.py --suspicious-paths # Archivos en paths sospechosos

Autor: MAR404 - Cacería de Amenazas
=============================================================================
"""

import json
import sys
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
EVIDENCE_DIR = "/cases/SRV-FIN-01/mft"


def load_mft_data():
    """Carga los datos parseados de MFT."""
    json_path = f"{EVIDENCE_DIR}/mft_parsed.json"
    if not os.path.exists(json_path):
        console.print("[red]ERROR: No se encontró mft_parsed.json[/red]")
        sys.exit(1)
    with open(json_path) as f:
        return json.load(f)


def analyze_all():
    """Análisis completo de la MFT."""
    entries = load_mft_data()
    
    timestomped = [e for e in entries if e['timestomp_detected']]
    deleted = [e for e in entries if not e['is_allocated']]
    
    console.print(Panel.fit(
        "[bold cyan]MFT ANALYSIS — SRV-FIN-01[/bold cyan]\n"
        f"Total de entradas analizadas: {len(entries)}\n"
        f"[red]Timestomping detectado: {len(timestomped)} archivos[/red]\n"
        f"[yellow]Archivos eliminados (recuperables): {len(deleted)}[/yellow]\n"
        f"Maliciosos: {len([e for e in entries if e['category']=='malicious'])}",
        title="Resumen MFT", border_style="cyan"
    ))
    
    table = Table(title="Entradas MFT Analizadas", box=box.DOUBLE_EDGE)
    table.add_column("MFT#", width=7)
    table.add_column("Archivo", style="cyan", width=25)
    table.add_column("SI Created", width=22)
    table.add_column("FN Created", width=22)
    table.add_column("Stomp?", width=7)
    table.add_column("Alloc", width=5)
    
    for entry in entries:
        stomp = "[red]YES![/red]" if entry['timestomp_detected'] else "[green]No[/green]"
        alloc = "[green]✓[/green]" if entry['is_allocated'] else "[red]DEL[/red]"
        
        si_c = entry['si_created'][:19]
        fn_c = entry['fn_created'][:19]
        
        # Resaltar si los timestamps son diferentes
        si_style = "red" if entry['timestomp_detected'] else ""
        fn_style = "green" if entry['timestomp_detected'] else ""
        
        table.add_row(
            str(entry['mft_entry']),
            entry['filename'],
            f"[{si_style}]{si_c}[/{si_style}]" if si_style else si_c,
            f"[{fn_style}]{fn_c}[/{fn_style}]" if fn_style else fn_c,
            stomp,
            alloc
        )
    
    console.print(table)
    
    console.print("\n[dim]Leyenda: SI = $STANDARD_INFORMATION (modificable por usuario)")
    console.print("         FN = $FILE_NAME (solo modificable por kernel)[/dim]")
    console.print("[dim]         Si SI ≠ FN → El atacante modificó los timestamps[/dim]")


def detect_timestomping():
    """Detección específica de timestomping."""
    entries = load_mft_data()
    timestomped = [e for e in entries if e['timestomp_detected']]
    
    console.print(Panel.fit(
        "[bold red]DETECCIÓN DE TIMESTOMPING (T1070.006)[/bold red]\n"
        "═══════════════════════════════════════════════════════\n"
        "El timestomping modifica $STANDARD_INFORMATION para hacer\n"
        "que un archivo parezca más antiguo de lo que realmente es.\n"
        "$FILE_NAME NO puede ser modificado por el atacante.\n"
        "═══════════════════════════════════════════════════════",
        border_style="red"
    ))
    
    if not timestomped:
        console.print("[green]No se detectó timestomping.[/green]")
        return
    
    console.print(f"\n[red bold]⚠ {len(timestomped)} ARCHIVOS CON TIMESTOMPING DETECTADO ⚠[/red bold]\n")
    
    for entry in timestomped:
        console.print(f"[red]{'═' * 70}[/red]")
        console.print(f"[red bold]▶ {entry['filename']}[/red bold]")
        console.print(f"  Path: {entry['full_path']}")
        console.print(f"  MFT Entry: {entry['mft_entry']} | Size: {entry['size']:,} bytes")
        console.print(f"  Flags: {entry['flags']}")
        console.print()
        console.print(f"  [red]$STANDARD_INFORMATION (FALSO - modificado por atacante):[/red]")
        console.print(f"    Created:       {entry['si_created']}")
        console.print(f"    Modified:      {entry['si_modified']}")
        console.print(f"    Accessed:      {entry['si_accessed']}")
        console.print(f"    Entry Modified:{entry['si_entry_modified']}")
        console.print()
        console.print(f"  [green]$FILE_NAME (REAL - solo kernel puede modificar):[/green]")
        console.print(f"    Created:       {entry['fn_created']}")
        console.print(f"    Modified:      {entry['fn_modified']}")
        console.print(f"    Accessed:      {entry['fn_accessed']}")
        console.print(f"    Entry Modified:{entry['fn_entry_modified']}")
        console.print()
        
        # Calcular diferencia
        try:
            si_date = datetime.fromisoformat(entry['si_created'].replace('Z', ''))
            fn_date = datetime.fromisoformat(entry['fn_created'].replace('Z', ''))
            diff = fn_date - si_date
            console.print(f"  [yellow]⏱ Diferencia: {diff.days} días ({diff.days/365:.1f} años)[/yellow]")
            console.print(f"  [yellow]  El atacante retrocedió el timestamp {diff.days} días al pasado[/yellow]")
        except:
            pass
        
        console.print(f"\n  [bold yellow]📋 Análisis: {entry['notes']}[/bold yellow]")
        console.print()


def show_deleted():
    """Muestra archivos eliminados pero recuperables de la MFT."""
    entries = load_mft_data()
    deleted = [e for e in entries if not e['is_allocated']]
    
    console.print(Panel.fit(
        f"[bold yellow]ARCHIVOS ELIMINADOS (RECUPERABLES): {len(deleted)}[/bold yellow]\n"
        "Estos archivos fueron borrados pero sus entradas MFT persisten",
        border_style="yellow"
    ))
    
    for entry in deleted:
        console.print(f"\n[yellow]▶ {entry['filename']}[/yellow] (DELETED)")
        console.print(f"  Path original: {entry['full_path']}")
        console.print(f"  Tamaño: {entry['size']:,} bytes")
        console.print(f"  Creado (FN): {entry['fn_created']}")
        console.print(f"  Modificado (FN): {entry['fn_modified']}")
        if entry.get('notes'):
            console.print(f"  [italic]{entry['notes']}[/italic]")


def generate_real_timeline():
    """Genera timeline basada en $FILE_NAME (timestamps reales)."""
    entries = load_mft_data()
    
    console.print(Panel.fit(
        "[bold blue]TIMELINE REAL (basada en $FILE_NAME)[/bold blue]\n"
        "Usa timestamps de FN que no pueden ser manipulados",
        border_style="blue"
    ))
    
    # Ordenar por FN.Created
    sorted_entries = sorted(entries, key=lambda x: x['fn_created'])
    
    table = Table(title="Timeline Real del Ataque (FN timestamps)", box=box.SIMPLE)
    table.add_column("FN Created", width=22)
    table.add_column("Archivo", width=30)
    table.add_column("Path", width=35)
    table.add_column("Size", justify="right", width=12)
    table.add_column("Stomped?", width=8)
    
    for entry in sorted_entries:
        stomp = "[red]SI[/red]" if entry['timestomp_detected'] else ""
        cat_color = "red" if entry['category'] == 'malicious' else "yellow" if entry['category'] == 'suspicious' else "green"
        
        table.add_row(
            entry['fn_created'][:19],
            f"[{cat_color}]{entry['filename']}[/{cat_color}]",
            entry['full_path'][:35],
            f"{entry['size']:,}",
            stomp
        )
    
    console.print(table)


def main():
    if len(sys.argv) < 2:
        analyze_all()
    elif sys.argv[1] == '--timestomp':
        detect_timestomping()
    elif sys.argv[1] == '--deleted':
        show_deleted()
    elif sys.argv[1] == '--timeline':
        generate_real_timeline()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 mft_analyzer.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)          Análisis completo de MFT
  --timestomp         Detección de timestomping (T1070.006)
  --deleted           Archivos eliminados (recuperables)
  --timeline          Timeline real basada en $FILE_NAME
  --suspicious-paths  Archivos en paths sospechosos
  --help              Muestra esta ayuda

[bold]Concepto clave:[/bold]
  $STANDARD_INFORMATION → Modificable por el atacante (SetFileTime API)
  $FILE_NAME → Solo modificable por el kernel de Windows
  Si SI ≠ FN → TIMESTOMPING CONFIRMADO
        """)
    else:
        analyze_all()


if __name__ == "__main__":
    main()
