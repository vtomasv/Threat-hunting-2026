#!/usr/bin/env python3
"""
=============================================================================
prefetch_parser.py - Parser de archivos Prefetch de Windows
=============================================================================
Simula el análisis de archivos Prefetch (.pf) como lo haría PECmd.exe
(Eric Zimmerman) o el módulo prefetch de python-registry.

Uso:
    python3 prefetch_parser.py                    # Analiza todos los .pf
    python3 prefetch_parser.py --file <nombre>    # Analiza un .pf específico
    python3 prefetch_parser.py --suspicious       # Solo muestra sospechosos
    python3 prefetch_parser.py --timeline         # Genera timeline de ejecuciones
    python3 prefetch_parser.py --lolbins          # Detecta LOLBins sospechosos

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
EVIDENCE_DIR = "/cases/SRV-FIN-01/prefetch"

# LOLBins conocidos que pueden ser abusados
LOLBINS = [
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wscript.exe", "cscript.exe", "powershell.exe",
    "cmd.exe", "wmic.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msconfig.exe", "cmstp.exe",
    "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
    "forfiles.exe", "hh.exe", "ie4uinit.exe", "infdefaultinstall.exe",
    "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe",
    "mmc.exe", "msdt.exe", "msiexec.exe", "netsh.exe", "odbcconf.exe",
    "pcalua.exe", "pcwrun.exe", "presentationhost.exe", "replace.exe",
    "rpcping.exe", "runscripthelper.exe", "sdbinst.exe", "syncappvpublishingserver.exe",
    "verclsid.exe", "wab.exe", "xwizard.exe"
]

# Herramientas de ataque conocidas
ATTACK_TOOLS = [
    "mimikatz", "psexec", "procdump", "rubeus", "sharphound",
    "bloodhound", "covenant", "cobalt", "beacon", "meterpreter",
    "nc.exe", "ncat", "netcat", "lazagne", "safetykatz",
    "printspoofer", "juicypotato", "godpotato", "sweetpotato",
    "rclone", "megacmd", "wevtutil", "nltest"
]


def load_prefetch_data():
    """Carga los datos parseados de Prefetch."""
    json_path = f"{EVIDENCE_DIR}/prefetch_parsed.json"
    if not os.path.exists(json_path):
        console.print("[red]ERROR: No se encontró prefetch_parsed.json[/red]")
        console.print("Ejecute primero: python3 /opt/lab19/scripts/generate_attack_simulation.py")
        sys.exit(1)
    
    with open(json_path) as f:
        return json.load(f)


def analyze_all():
    """Análisis completo de todos los archivos Prefetch."""
    entries = load_prefetch_data()
    
    console.print(Panel.fit(
        "[bold cyan]PREFETCH ANALYSIS — SRV-FIN-01[/bold cyan]\n"
        f"Total de archivos: {len(entries)}\n"
        f"Maliciosos: {len([e for e in entries if e['category']=='malicious'])}\n"
        f"Sospechosos: {len([e for e in entries if e['category']=='suspicious'])}\n"
        f"Legítimos: {len([e for e in entries if e['category']=='legitimate'])}",
        title="Resumen", border_style="cyan"
    ))
    
    table = Table(title="Archivos Prefetch Analizados", box=box.DOUBLE_EDGE)
    table.add_column("Estado", style="bold", width=6)
    table.add_column("Ejecutable", style="cyan", width=22)
    table.add_column("Path", width=45)
    table.add_column("Runs", justify="center", width=5)
    table.add_column("Última Ejecución", width=20)
    
    for entry in entries:
        if entry['category'] == 'malicious':
            status = "[red]◉ MAL[/red]"
        elif entry['category'] == 'suspicious':
            status = "[yellow]◉ SUS[/yellow]"
        else:
            status = "[green]◉ OK[/green]"
        
        last_run = entry['last_run_times'][0][:19] if entry['last_run_times'] else "N/A"
        path = entry['full_path'][:45]
        
        table.add_row(status, entry['executable'], path, str(entry['run_count']), last_run)
    
    console.print(table)
    
    # Detalles de entradas maliciosas
    console.print("\n[bold red]═══ HALLAZGOS CRÍTICOS ═══[/bold red]\n")
    for entry in entries:
        if entry['category'] == 'malicious':
            console.print(f"[red]▶ {entry['executable']}[/red]")
            console.print(f"  Archivo PF: {entry['filename']}")
            console.print(f"  Path: {entry['full_path']}")
            console.print(f"  Ejecuciones: {entry['run_count']}")
            console.print(f"  Última ejecución: {entry['last_run_times'][0]}")
            console.print(f"  Directorios accedidos:")
            for d in entry.get('directories_accessed', []):
                console.print(f"    → {d}")
            console.print(f"  [bold yellow]Nota: {entry['notes']}[/bold yellow]")
            console.print()


def analyze_suspicious():
    """Muestra solo entradas sospechosas y maliciosas."""
    entries = load_prefetch_data()
    suspicious = [e for e in entries if e['category'] in ('malicious', 'suspicious')]
    
    console.print(Panel.fit(
        f"[bold red]ENTRADAS SOSPECHOSAS/MALICIOSAS: {len(suspicious)}[/bold red]",
        border_style="red"
    ))
    
    for entry in suspicious:
        severity = "[red][MALICIOUS][/red]" if entry['category'] == 'malicious' else "[yellow][SUSPICIOUS][/yellow]"
        console.print(f"\n{severity} {entry['executable']}")
        console.print(f"  Hash: {entry['hash']} | Runs: {entry['run_count']}")
        console.print(f"  Path: {entry['full_path']}")
        console.print(f"  Last Run: {entry['last_run_times'][0]}")
        if entry.get('notes'):
            console.print(f"  [italic]{entry['notes']}[/italic]")


def detect_lolbins():
    """Detecta uso de LOLBins (Living Off the Land Binaries)."""
    entries = load_prefetch_data()
    
    console.print(Panel.fit(
        "[bold magenta]DETECCIÓN DE LOLBINS[/bold magenta]\n"
        "Living Off the Land Binaries usados de forma sospechosa",
        title="LOLBin Analysis", border_style="magenta"
    ))
    
    found_lolbins = []
    for entry in entries:
        exe_lower = entry['executable'].lower()
        if exe_lower in LOLBINS:
            # Evaluar si el uso es sospechoso
            suspicious_indicators = []
            if entry['run_count'] > 3 and exe_lower in ('certutil.exe', 'bitsadmin.exe'):
                suspicious_indicators.append("Alta frecuencia de ejecución")
            if 'downloads' in entry['full_path'].lower() or 'temp' in entry['full_path'].lower():
                suspicious_indicators.append("Accede a directorios de descarga/temp")
            if any('temp' in d.lower() or 'public' in d.lower() for d in entry.get('directories_accessed', [])):
                suspicious_indicators.append("Directorios accedidos sospechosos")
            
            if suspicious_indicators:
                found_lolbins.append((entry, suspicious_indicators))
    
    if found_lolbins:
        for entry, indicators in found_lolbins:
            console.print(f"\n[magenta]▶ {entry['executable']}[/magenta]")
            console.print(f"  Ejecuciones: {entry['run_count']}")
            console.print(f"  Indicadores sospechosos:")
            for ind in indicators:
                console.print(f"    [yellow]⚠ {ind}[/yellow]")
            console.print(f"  MITRE: Posible abuso como herramienta de descarga/ejecución")
    else:
        console.print("[green]No se detectaron LOLBins con uso sospechoso.[/green]")


def generate_timeline():
    """Genera una línea de tiempo ordenada de ejecuciones."""
    entries = load_prefetch_data()
    
    console.print(Panel.fit(
        "[bold blue]TIMELINE DE EJECUCIONES[/bold blue]",
        border_style="blue"
    ))
    
    # Crear timeline de todas las ejecuciones
    timeline = []
    for entry in entries:
        for run_time in entry['last_run_times']:
            timeline.append({
                'time': run_time,
                'executable': entry['executable'],
                'category': entry['category'],
                'path': entry['full_path']
            })
    
    # Ordenar por tiempo
    timeline.sort(key=lambda x: x['time'])
    
    table = Table(title="Timeline de Ejecuciones (Ordenada)", box=box.SIMPLE)
    table.add_column("Timestamp", style="dim", width=20)
    table.add_column("Ejecutable", width=25)
    table.add_column("Categoría", width=12)
    table.add_column("Path", width=50)
    
    for event in timeline:
        cat_style = "red" if event['category'] == 'malicious' else "yellow" if event['category'] == 'suspicious' else "green"
        table.add_row(
            event['time'][:19],
            event['executable'],
            f"[{cat_style}]{event['category']}[/{cat_style}]",
            event['path'][:50]
        )
    
    console.print(table)


def analyze_single(filename):
    """Analiza un archivo Prefetch específico."""
    entries = load_prefetch_data()
    
    found = None
    for entry in entries:
        if filename.lower() in entry['filename'].lower() or filename.lower() in entry['executable'].lower():
            found = entry
            break
    
    if not found:
        console.print(f"[red]No se encontró: {filename}[/red]")
        console.print("Archivos disponibles:")
        for e in entries:
            console.print(f"  • {e['filename']}")
        return
    
    console.print(Panel.fit(
        f"[bold]Análisis detallado: {found['filename']}[/bold]",
        border_style="cyan"
    ))
    
    console.print(f"  Ejecutable:     {found['executable']}")
    console.print(f"  Hash del Path:  {found['hash']}")
    console.print(f"  Path Completo:  {found['full_path']}")
    console.print(f"  Tamaño:         {found['size']:,} bytes")
    console.print(f"  Run Count:      {found['run_count']}")
    console.print(f"  Creado:         {found['created']}")
    console.print(f"  Modificado:     {found['modified']}")
    console.print(f"  Volumen:        {found['volume_path']}")
    console.print(f"  Serial:         {found['volume_serial']}")
    console.print(f"\n  Últimas ejecuciones:")
    for i, rt in enumerate(found['last_run_times'], 1):
        console.print(f"    [{i}] {rt}")
    console.print(f"\n  Directorios accedidos:")
    for d in found.get('directories_accessed', []):
        console.print(f"    → {d}")
    if found.get('notes'):
        console.print(f"\n  [bold yellow]⚠ NOTAS: {found['notes']}[/bold yellow]")


def main():
    if len(sys.argv) < 2:
        analyze_all()
    elif sys.argv[1] == '--suspicious':
        analyze_suspicious()
    elif sys.argv[1] == '--timeline':
        generate_timeline()
    elif sys.argv[1] == '--lolbins':
        detect_lolbins()
    elif sys.argv[1] == '--file' and len(sys.argv) > 2:
        analyze_single(sys.argv[2])
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 prefetch_parser.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)      Análisis completo de todos los Prefetch
  --suspicious    Solo muestra entradas sospechosas/maliciosas
  --timeline      Genera timeline ordenada de ejecuciones
  --lolbins       Detecta LOLBins usados de forma sospechosa
  --file <name>   Analiza un archivo específico
  --help          Muestra esta ayuda
        """)
    else:
        analyze_all()


if __name__ == "__main__":
    main()
