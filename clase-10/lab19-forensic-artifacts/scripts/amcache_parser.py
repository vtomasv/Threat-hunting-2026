#!/usr/bin/env python3
"""
=============================================================================
amcache_parser.py - Parser de Amcache.hve de Windows
=============================================================================
Simula el análisis de Amcache como lo haría AmcacheParser.exe (Eric Zimmerman)
o RegRipper.

Uso:
    python3 amcache_parser.py                  # Análisis completo
    python3 amcache_parser.py --unsigned       # Solo binarios sin firma
    python3 amcache_parser.py --hashes         # Exporta hashes para VT/MISP
    python3 amcache_parser.py --anomalies      # Detecta anomalías
    python3 amcache_parser.py --compare-paths  # Compara paths legítimos vs anómalos

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
EVIDENCE_DIR = "/cases/SRV-FIN-01/amcache"

# Paths legítimos conocidos para binarios de Windows
LEGITIMATE_PATHS = {
    "svchost.exe": ["C:\\Windows\\System32\\"],
    "explorer.exe": ["C:\\Windows\\"],
    "cmd.exe": ["C:\\Windows\\System32\\"],
    "powershell.exe": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"],
    "notepad.exe": ["C:\\Windows\\System32\\", "C:\\Windows\\"],
}

# Publishers legítimos conocidos
TRUSTED_PUBLISHERS = [
    "Microsoft Windows",
    "Microsoft Corporation",
    "Microsoft Windows Publisher",
]


def load_amcache_data():
    """Carga los datos parseados de Amcache."""
    json_path = f"{EVIDENCE_DIR}/amcache_parsed.json"
    if not os.path.exists(json_path):
        console.print("[red]ERROR: No se encontró amcache_parsed.json[/red]")
        sys.exit(1)
    with open(json_path) as f:
        return json.load(f)


def analyze_all():
    """Análisis completo de Amcache."""
    entries = load_amcache_data()
    
    console.print(Panel.fit(
        "[bold cyan]AMCACHE ANALYSIS — SRV-FIN-01[/bold cyan]\n"
        f"Total de entradas: {len(entries)}\n"
        f"Firmados: {len([e for e in entries if e['is_signed']])}\n"
        f"Sin firma: {len([e for e in entries if not e['is_signed']])}\n"
        f"Maliciosos: {len([e for e in entries if e['category']=='malicious'])}",
        title="Resumen Amcache", border_style="cyan"
    ))
    
    table = Table(title="Entradas de Amcache", box=box.DOUBLE_EDGE)
    table.add_column("Estado", width=6)
    table.add_column("Nombre", style="cyan", width=20)
    table.add_column("Path", width=40)
    table.add_column("SHA1", width=12)
    table.add_column("Firmado", width=8)
    table.add_column("Publisher", width=20)
    table.add_column("First Run", width=20)
    
    for entry in entries:
        if entry['category'] == 'malicious':
            status = "[red]◉ MAL[/red]"
        elif entry['category'] == 'suspicious':
            status = "[yellow]◉ SUS[/yellow]"
        else:
            status = "[green]◉ OK[/green]"
        
        signed = "[green]✓[/green]" if entry['is_signed'] else "[red]✗[/red]"
        sha1_short = entry['sha1'][:12] + "..."
        
        table.add_row(
            status, entry['name'], entry['full_path'][:40],
            sha1_short, signed, entry.get('publisher', '')[:20],
            entry['first_run'][:19]
        )
    
    console.print(table)


def analyze_unsigned():
    """Muestra solo binarios sin firma digital."""
    entries = load_amcache_data()
    unsigned = [e for e in entries if not e['is_signed']]
    
    console.print(Panel.fit(
        f"[bold red]BINARIOS SIN FIRMA DIGITAL: {len(unsigned)}[/bold red]\n"
        "Los binarios sin firma son sospechosos en un entorno corporativo",
        border_style="red"
    ))
    
    for entry in unsigned:
        console.print(f"\n[red]▶ {entry['name']}[/red]")
        console.print(f"  Path:       {entry['full_path']}")
        console.print(f"  SHA1:       {entry['sha1']}")
        console.print(f"  Tamaño:     {entry['size']:,} bytes")
        console.print(f"  Link Date:  {entry['link_date']}")
        console.print(f"  First Run:  {entry['first_run']}")
        console.print(f"  PE Type:    {entry['binary_type']}")
        console.print(f"  Checksum:   {entry['pe_header_checksum']}")
        if entry.get('notes'):
            console.print(f"  [yellow]⚠ {entry['notes']}[/yellow]")


def export_hashes():
    """Exporta hashes para búsqueda en VirusTotal/MISP."""
    entries = load_amcache_data()
    
    console.print(Panel.fit(
        "[bold green]EXPORTACIÓN DE HASHES PARA THREAT INTELLIGENCE[/bold green]",
        border_style="green"
    ))
    
    output_file = "/cases/SRV-FIN-01/iocs/amcache_hashes_for_vt.txt"
    
    with open(output_file, 'w') as f:
        f.write("# Hashes extraídos de Amcache - Para búsqueda en VT/MISP/OTX\n")
        f.write("# Formato: SHA1 hash\n\n")
        for entry in entries:
            if entry['category'] in ('malicious', 'suspicious'):
                f.write(f"# {entry['name']} ({entry['full_path']})\n")
                f.write(f"{entry['sha1']}\n\n")
    
    console.print(f"[green]Hashes exportados a: {output_file}[/green]")
    console.print("\nHashes sospechosos/maliciosos:")
    for entry in entries:
        if entry['category'] in ('malicious', 'suspicious'):
            console.print(f"  {entry['sha1']}  {entry['name']}")


def detect_anomalies():
    """Detecta anomalías en las entradas de Amcache."""
    entries = load_amcache_data()
    
    console.print(Panel.fit(
        "[bold yellow]DETECCIÓN DE ANOMALÍAS EN AMCACHE[/bold yellow]",
        border_style="yellow"
    ))
    
    anomalies = []
    
    for entry in entries:
        entry_anomalies = []
        
        # 1. Binario sin firma en path de sistema
        if not entry['is_signed'] and 'windows' in entry['full_path'].lower():
            entry_anomalies.append("Binario sin firma en directorio de Windows")
        
        # 2. Path anómalo para ejecutable conocido
        name_lower = entry['name'].lower()
        if name_lower in LEGITIMATE_PATHS:
            legit_paths = LEGITIMATE_PATHS[name_lower]
            if not any(entry['full_path'].startswith(lp) for lp in legit_paths):
                entry_anomalies.append(f"Path anómalo para {entry['name']} (esperado: {legit_paths})")
        
        # 3. Checksum PE = 0 (no calculado)
        if entry['pe_header_checksum'] == "0x00000000":
            entry_anomalies.append("PE Checksum = 0 (no calculado, típico de herramientas custom/compiladas ad-hoc)")
        
        # 4. Sin publisher ni versión
        if not entry.get('publisher') and not entry.get('version'):
            entry_anomalies.append("Sin publisher ni versión (metadata vacía)")
        
        # 5. Link date muy reciente (compilado recientemente)
        if '2026-07' in entry.get('link_date', '') or '2026-06' in entry.get('link_date', ''):
            entry_anomalies.append("Compilado recientemente (link date en últimos 30 días)")
        
        if entry_anomalies:
            anomalies.append((entry, entry_anomalies))
    
    for entry, anoms in anomalies:
        severity = "[red]ALTA[/red]" if len(anoms) >= 2 else "[yellow]MEDIA[/yellow]"
        console.print(f"\n{severity} — {entry['name']} ({entry['full_path']})")
        for a in anoms:
            console.print(f"  [yellow]⚠ {a}[/yellow]")
    
    console.print(f"\n[bold]Total de anomalías detectadas: {len(anomalies)} entradas[/bold]")


def compare_paths():
    """Compara paths de ejecutables con nombres conocidos."""
    entries = load_amcache_data()
    
    console.print(Panel.fit(
        "[bold magenta]COMPARACIÓN DE PATHS — MASQUERADING DETECTION[/bold magenta]\n"
        "Detecta ejecutables con nombres legítimos en paths incorrectos (T1036.005)",
        border_style="magenta"
    ))
    
    # Buscar duplicados por nombre
    names = {}
    for entry in entries:
        name = entry['name'].lower()
        if name not in names:
            names[name] = []
        names[name].append(entry)
    
    for name, entries_list in names.items():
        if len(entries_list) > 1:
            console.print(f"\n[magenta]▶ {name} — {len(entries_list)} instancias encontradas:[/magenta]")
            for e in entries_list:
                signed_icon = "✓" if e['is_signed'] else "✗"
                cat_color = "red" if e['category'] == 'malicious' else "yellow" if e['category'] == 'suspicious' else "green"
                console.print(f"  [{cat_color}][{signed_icon}] {e['full_path']}[/{cat_color}]")
                console.print(f"      SHA1: {e['sha1']}")
                console.print(f"      Size: {e['size']:,} | Publisher: {e.get('publisher', 'N/A')}")


def main():
    if len(sys.argv) < 2:
        analyze_all()
    elif sys.argv[1] == '--unsigned':
        analyze_unsigned()
    elif sys.argv[1] == '--hashes':
        export_hashes()
    elif sys.argv[1] == '--anomalies':
        detect_anomalies()
    elif sys.argv[1] == '--compare-paths':
        compare_paths()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 amcache_parser.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)       Análisis completo de Amcache
  --unsigned       Solo binarios sin firma digital
  --hashes         Exporta hashes para VT/MISP
  --anomalies      Detecta anomalías (paths, firmas, checksums)
  --compare-paths  Detecta masquerading (T1036.005)
  --help           Muestra esta ayuda
        """)
    else:
        analyze_all()


if __name__ == "__main__":
    main()
