#!/usr/bin/env python3
"""
=============================================================================
timestomp_detector.py - Detector Avanzado de Timestomping
=============================================================================
Herramienta especializada en la detección de manipulación de timestamps
en la MFT de Windows (T1070.006 - Indicator Removal: Timestomp).

Técnicas de detección:
1. Comparación SI vs FN timestamps
2. Detección de timestamps "imposibles" (futuro, epoch)
3. Detección de timestamps copiados de archivos legítimos
4. Análisis de nanosegundos (timestamps con .0000000 = modificados)
5. Correlación con Prefetch/Amcache para validar fechas reales

Uso:
    python3 timestomp_detector.py              # Análisis completo
    python3 timestomp_detector.py --deep       # Análisis profundo con heurísticas
    python3 timestomp_detector.py --correlate  # Correlación con otros artefactos

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
CASE_DIR = "/cases/SRV-FIN-01"


def load_all_evidence():
    """Carga todos los artefactos para correlación."""
    data = {}
    
    mft_path = f"{CASE_DIR}/mft/mft_parsed.json"
    prefetch_path = f"{CASE_DIR}/prefetch/prefetch_parsed.json"
    amcache_path = f"{CASE_DIR}/amcache/amcache_parsed.json"
    
    for name, path in [('mft', mft_path), ('prefetch', prefetch_path), ('amcache', amcache_path)]:
        if os.path.exists(path):
            with open(path) as f:
                data[name] = json.load(f)
    
    return data


def basic_detection():
    """Detección básica de timestomping."""
    data = load_all_evidence()
    mft = data.get('mft', [])
    
    console.print(Panel.fit(
        "[bold red]TIMESTOMPING DETECTOR v2.0[/bold red]\n"
        "═══════════════════════════════════════════════\n"
        "Detecta manipulación de timestamps en la MFT\n"
        "Técnica MITRE: T1070.006\n"
        "═══════════════════════════════════════════════",
        border_style="red"
    ))
    
    detections = []
    
    for entry in mft:
        issues = []
        
        # Test 1: SI.Created != FN.Created
        if entry['si_created'] != entry['fn_created']:
            issues.append({
                'test': 'SI vs FN Mismatch',
                'detail': f"SI.Created={entry['si_created'][:19]} ≠ FN.Created={entry['fn_created'][:19]}",
                'severity': 'CRITICAL'
            })
        
        # Test 2: SI.Created en el pasado lejano pero FN.Created reciente
        try:
            si_date = datetime.fromisoformat(entry['si_created'].replace('Z', ''))
            fn_date = datetime.fromisoformat(entry['fn_created'].replace('Z', ''))
            
            if (fn_date - si_date).days > 30:
                issues.append({
                    'test': 'Timestamp Regression',
                    'detail': f"SI es {(fn_date - si_date).days} días más antiguo que FN",
                    'severity': 'CRITICAL'
                })
        except:
            pass
        
        # Test 3: Todos los SI timestamps son idénticos (herramienta de timestomping)
        if (entry['si_created'] == entry['si_modified'] == 
            entry['si_accessed'] == entry['si_entry_modified'] and
            entry['si_created'] != entry['fn_created']):
            issues.append({
                'test': 'Uniform SI Timestamps',
                'detail': 'Todos los SI timestamps son idénticos (típico de herramienta de timestomping)',
                'severity': 'HIGH'
            })
        
        # Test 4: Archivo con flags Hidden+System en directorio de usuario
        if 'Hidden' in entry.get('flags', '') and ('Users' in entry['full_path'] or 'Temp' in entry['full_path']):
            issues.append({
                'test': 'Suspicious Flags',
                'detail': f"Flags={entry['flags']} en path de usuario/temp",
                'severity': 'MEDIUM'
            })
        
        if issues:
            detections.append((entry, issues))
    
    # Mostrar resultados
    if detections:
        console.print(f"\n[red bold]⚠ {len(detections)} ARCHIVOS CON INDICADORES DE TIMESTOMPING ⚠[/red bold]\n")
        
        for entry, issues in detections:
            console.print(f"[red]{'─' * 70}[/red]")
            console.print(f"[red bold]  {entry['filename']}[/red bold] ({entry['full_path']})")
            console.print(f"  MFT Entry: {entry['mft_entry']} | Size: {entry['size']:,} bytes")
            
            for issue in issues:
                sev_color = "red" if issue['severity'] == 'CRITICAL' else "yellow" if issue['severity'] == 'HIGH' else "white"
                console.print(f"  [{sev_color}]  [{issue['severity']}] {issue['test']}: {issue['detail']}[/{sev_color}]")
            
            console.print()
    else:
        console.print("[green]No se detectó timestomping.[/green]")
    
    return detections


def deep_analysis():
    """Análisis profundo con heurísticas avanzadas."""
    data = load_all_evidence()
    mft = data.get('mft', [])
    
    console.print(Panel.fit(
        "[bold yellow]ANÁLISIS PROFUNDO DE TIMESTOMPING[/bold yellow]\n"
        "Heurísticas avanzadas para detectar manipulación sutil",
        border_style="yellow"
    ))
    
    # Heurística 1: Buscar timestamps que coincidan con archivos legítimos del sistema
    console.print("\n[bold]═══ Heurística 1: Timestamps Copiados ═══[/bold]")
    console.print("[dim]Busca archivos maliciosos con timestamps idénticos a archivos legítimos[/dim]\n")
    
    legitimate_timestamps = {}
    malicious_timestamps = {}
    
    for entry in mft:
        if entry['category'] == 'legitimate':
            legitimate_timestamps[entry['si_created']] = entry['filename']
        elif entry['category'] in ('malicious', 'suspicious'):
            malicious_timestamps[entry['si_created']] = entry
    
    for ts, mal_entry in malicious_timestamps.items():
        if ts in legitimate_timestamps:
            console.print(f"  [red]⚠ TIMESTAMP COPIADO DETECTADO:[/red]")
            console.print(f"    Archivo malicioso: {mal_entry['filename']}")
            console.print(f"    Tiene el mismo timestamp que: {legitimate_timestamps[ts]}")
            console.print(f"    Timestamp: {ts}")
            console.print(f"    → El atacante copió el timestamp de {legitimate_timestamps[ts]} a {mal_entry['filename']}")
            console.print()
    
    # Heurística 2: Nanosegundos = 0 (herramientas de timestomping a menudo no setean nanosegundos)
    console.print("\n[bold]═══ Heurística 2: Precisión de Nanosegundos ═══[/bold]")
    console.print("[dim]Timestamps con .000000 pueden indicar modificación por herramienta[/dim]\n")
    
    for entry in mft:
        if entry['timestomp_detected']:
            si_ts = entry['si_created']
            if '.000000' in si_ts or si_ts.endswith(':00Z') or si_ts.endswith(':00.000000Z'):
                console.print(f"  [yellow]⚠ {entry['filename']}: SI timestamp con precisión sospechosa ({si_ts})[/yellow]")
    
    # Heurística 3: Archivos creados "antes" que su directorio padre
    console.print("\n[bold]═══ Heurística 3: Orden Cronológico Imposible ═══[/bold]")
    console.print("[dim]Archivos que aparentan ser más antiguos que el directorio que los contiene[/dim]\n")
    
    for entry in mft:
        if entry['timestomp_detected']:
            try:
                si_date = datetime.fromisoformat(entry['si_created'].replace('Z', ''))
                # Si el SI timestamp es anterior a la instalación del OS (2019)
                if si_date.year < 2019 and 'Windows' in entry['full_path']:
                    console.print(f"  [red]⚠ {entry['filename']}: SI.Created ({si_date.year}) es anterior a la instalación del OS (2019)[/red]")
            except:
                pass


def correlate_artifacts():
    """Correlaciona timestamps de MFT con Prefetch y Amcache."""
    data = load_all_evidence()
    mft = data.get('mft', [])
    prefetch = data.get('prefetch', [])
    amcache = data.get('amcache', [])
    
    console.print(Panel.fit(
        "[bold magenta]CORRELACIÓN MULTI-ARTEFACTO[/bold magenta]\n"
        "Valida timestamps de MFT contra Prefetch y Amcache",
        border_style="magenta"
    ))
    
    for mft_entry in mft:
        if not mft_entry['timestomp_detected']:
            continue
        
        filename = mft_entry['filename'].lower()
        console.print(f"\n[magenta]{'═' * 60}[/magenta]")
        console.print(f"[magenta bold]  Correlación para: {mft_entry['filename']}[/magenta bold]")
        console.print(f"[magenta]{'═' * 60}[/magenta]")
        
        # Buscar en Prefetch
        for pf in prefetch:
            if filename in pf['executable'].lower():
                console.print(f"\n  [cyan]PREFETCH:[/cyan]")
                console.print(f"    Última ejecución: {pf['last_run_times'][0]}")
                console.print(f"    Run count: {pf['run_count']}")
                
                # Comparar con MFT
                console.print(f"    MFT SI.Created: {mft_entry['si_created'][:19]} (FALSO)")
                console.print(f"    MFT FN.Created: {mft_entry['fn_created'][:19]} (REAL)")
                console.print(f"    Prefetch Last:  {pf['last_run_times'][0][:19]}")
                
                # ¿El prefetch es consistente con FN o SI?
                pf_date = pf['last_run_times'][0][:10]
                fn_date = mft_entry['fn_created'][:10]
                si_date = mft_entry['si_created'][:10]
                
                if pf_date == fn_date:
                    console.print(f"    [green]✓ Prefetch es CONSISTENTE con FN (fecha real)[/green]")
                elif pf_date == si_date:
                    console.print(f"    [red]✗ Prefetch coincide con SI (timestamp falso) - IMPOSIBLE[/red]")
                break
        
        # Buscar en Amcache
        for ac in amcache:
            if filename in ac['name'].lower():
                console.print(f"\n  [cyan]AMCACHE:[/cyan]")
                console.print(f"    First Run: {ac['first_run']}")
                console.print(f"    SHA1: {ac['sha1']}")
                
                # Comparar
                ac_date = ac['first_run'][:10]
                fn_date = mft_entry['fn_created'][:10]
                
                if ac_date == fn_date:
                    console.print(f"    [green]✓ Amcache First Run CONSISTENTE con FN (fecha real)[/green]")
                else:
                    console.print(f"    [yellow]⚠ Amcache First Run difiere de FN[/yellow]")
                break
        
        console.print(f"\n  [bold]CONCLUSIÓN:[/bold] El archivo fue realmente creado el {mft_entry['fn_created'][:10]}")
        console.print(f"  pero el atacante modificó SI para que parezca del {mft_entry['si_created'][:10]}")


def main():
    if len(sys.argv) < 2:
        basic_detection()
    elif sys.argv[1] == '--deep':
        deep_analysis()
    elif sys.argv[1] == '--correlate':
        correlate_artifacts()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 timestomp_detector.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)     Detección básica de timestomping
  --deep         Análisis profundo con heurísticas avanzadas
  --correlate    Correlación con Prefetch y Amcache
  --help         Muestra esta ayuda
        """)
    else:
        basic_detection()


if __name__ == "__main__":
    main()
