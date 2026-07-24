#!/usr/bin/env python3
"""
=============================================================================
timeline_builder.py - Constructor de Timeline Forense Consolidada
=============================================================================
Correlaciona TODOS los artefactos (Prefetch, Amcache, UserAssist, MFT)
para construir una línea de tiempo unificada del ataque.

Uso:
    python3 timeline_builder.py                # Timeline completa
    python3 timeline_builder.py --phases       # Agrupada por fases del ataque
    python3 timeline_builder.py --mitre        # Mapeo MITRE ATT&CK
    python3 timeline_builder.py --report       # Genera reporte ejecutivo

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
CASE_DIR = "/cases/SRV-FIN-01"


def load_timeline():
    """Carga la timeline del ataque."""
    path = f"{CASE_DIR}/timeline/attack_timeline.json"
    if not os.path.exists(path):
        console.print("[red]ERROR: Timeline no encontrada[/red]")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def show_full_timeline():
    """Muestra la timeline completa del ataque."""
    timeline = load_timeline()
    
    console.print(Panel.fit(
        "[bold cyan]TIMELINE CONSOLIDADA DEL ATAQUE[/bold cyan]\n"
        f"Caso: IR-2026-0715-001 | Host: SRV-FIN-01\n"
        f"Total de eventos: {len(timeline)}\n"
        f"Duración del ataque: ~5.5 horas",
        title="Attack Timeline", border_style="cyan"
    ))
    
    table = Table(box=box.SIMPLE)
    table.add_column("Hora", width=8)
    table.add_column("Fase", width=22)
    table.add_column("MITRE", width=10)
    table.add_column("Descripción", width=50)
    table.add_column("Sev.", width=5)
    
    for event in timeline:
        time_short = event['time'][11:19]
        sev_color = "red" if event['severity'] == 'CRITICAL' else "yellow" if event['severity'] == 'HIGH' else "white"
        
        table.add_row(
            time_short,
            event['phase'],
            event['technique'],
            event['description'][:50],
            f"[{sev_color}]{event['severity'][:4]}[/{sev_color}]"
        )
    
    console.print(table)


def show_by_phases():
    """Agrupa eventos por fases del Cyber Kill Chain."""
    timeline = load_timeline()
    
    phases = {}
    for event in timeline:
        phase = event['phase']
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(event)
    
    console.print(Panel.fit(
        "[bold blue]TIMELINE POR FASES DEL ATAQUE[/bold blue]",
        border_style="blue"
    ))
    
    phase_order = [
        "Initial Access", "Execution", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration"
    ]
    
    for phase in phase_order:
        if phase in phases:
            events = phases[phase]
            console.print(f"\n[bold blue]{'═' * 60}[/bold blue]")
            console.print(f"[bold blue]  FASE: {phase} ({len(events)} eventos)[/bold blue]")
            console.print(f"[bold blue]{'═' * 60}[/bold blue]")
            
            for event in events:
                sev_color = "red" if event['severity'] == 'CRITICAL' else "yellow"
                console.print(f"  [{sev_color}]{event['time'][11:19]}[/{sev_color}] [{event['technique']}] {event['description']}")
                console.print(f"  [dim]    Evidencia: {event['evidence']}[/dim]")


def show_mitre_mapping():
    """Muestra mapeo completo MITRE ATT&CK."""
    timeline = load_timeline()
    
    console.print(Panel.fit(
        "[bold red]MAPEO MITRE ATT&CK[/bold red]",
        border_style="red"
    ))
    
    # Agrupar por técnica
    techniques = {}
    for event in timeline:
        tech = event['technique']
        if tech not in techniques:
            techniques[tech] = {
                'phase': event['phase'],
                'events': []
            }
        techniques[tech]['events'].append(event)
    
    table = Table(title="Técnicas MITRE ATT&CK Identificadas", box=box.DOUBLE_EDGE)
    table.add_column("Técnica", width=12)
    table.add_column("Táctica", width=22)
    table.add_column("Descripción", width=40)
    table.add_column("Ocurrencias", justify="center", width=5)
    
    for tech_id, data in sorted(techniques.items()):
        desc = data['events'][0]['description'][:40]
        table.add_row(tech_id, data['phase'], desc, str(len(data['events'])))
    
    console.print(table)
    
    console.print(f"\n[bold]Total de técnicas únicas: {len(techniques)}[/bold]")
    console.print("[dim]Referencia: https://attack.mitre.org/techniques/[/dim]")


def generate_report():
    """Genera reporte ejecutivo del incidente."""
    timeline = load_timeline()
    
    report = f"""
{'=' * 70}
  REPORTE EJECUTIVO DE INCIDENTE
  Caso: IR-2026-0715-001
  Host: SRV-FIN-01 (Windows Server 2019)
  Analista: [TU NOMBRE]
  Fecha: {timeline[0]['time'][:10]}
{'=' * 70}

RESUMEN EJECUTIVO:
  El servidor SRV-FIN-01 fue comprometido mediante un ataque de
  spearphishing que resultó en la ejecución de un beacon Cobalt Strike.
  El atacante escaló privilegios, robó credenciales, se movió lateralmente
  a 3 hosts adicionales y exfiltró ~150MB de datos financieros.

DURACIÓN DEL ATAQUE: ~5.5 horas (09:23 - 14:57 UTC)

FASES IDENTIFICADAS:
  1. Acceso Inicial: Documento Word con macro maliciosa
  2. Ejecución: PowerShell + certutil para staging
  3. Persistencia: Beacon disfrazado como svchost.exe
  4. Escalación: PrintSpoofer (impersonation exploit)
  5. Credenciales: Mimikatz + ProcDump (LSASS dump)
  6. Movimiento Lateral: PsExec a 3 hosts internos
  7. Exfiltración: Rclone a cloud storage externo
  8. Evasión: Timestomping + limpieza de logs

IMPACTO:
  - 4 hosts comprometidos (SRV-FIN-01, .102, .103, .104)
  - Credenciales de dominio robadas (NTLM hashes)
  - ~150MB de datos financieros Q2 2026 exfiltrados
  - Event logs parcialmente eliminados

IOCs CRÍTICOS:
  - IP Atacante: 185.220.101.34
  - C2: update-service.cloudfront-cdn.com (104.21.45.67)
  - SHA1 Beacon: a1b2c3d4e5f6789012345678901234567890abcd

RECOMENDACIONES INMEDIATAS:
  1. Aislar los 4 hosts comprometidos
  2. Resetear todas las credenciales del dominio
  3. Bloquear IOCs en firewall/proxy
  4. Revisar accesos a datos financieros
  5. Notificar al equipo legal (posible breach de datos)

{'=' * 70}
"""
    
    report_path = f"{CASE_DIR}/reports/executive_report.txt"
    with open(report_path, 'w') as f:
        f.write(report)
    
    console.print(report)
    console.print(f"\n[green]Reporte guardado en: {report_path}[/green]")


def main():
    if len(sys.argv) < 2:
        show_full_timeline()
    elif sys.argv[1] == '--phases':
        show_by_phases()
    elif sys.argv[1] == '--mitre':
        show_mitre_mapping()
    elif sys.argv[1] == '--report':
        generate_report()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 timeline_builder.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)    Timeline completa cronológica
  --phases      Agrupada por fases del ataque
  --mitre       Mapeo MITRE ATT&CK
  --report      Genera reporte ejecutivo
  --help        Muestra esta ayuda
        """)
    else:
        show_full_timeline()


if __name__ == "__main__":
    main()
