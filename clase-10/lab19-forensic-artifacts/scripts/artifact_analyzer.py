#!/usr/bin/env python3
"""
=============================================================================
artifact_analyzer.py - Analizador Principal de Artefactos Forenses
=============================================================================
Script wrapper que ejecuta todos los análisis disponibles.

Uso:
    python3 artifact_analyzer.py               # Menú interactivo
    python3 artifact_analyzer.py --all         # Ejecuta todos los análisis
    python3 artifact_analyzer.py --prefetch    # Solo Prefetch
    python3 artifact_analyzer.py --amcache     # Solo Amcache
    python3 artifact_analyzer.py --userassist  # Solo UserAssist
    python3 artifact_analyzer.py --mft         # Solo MFT
    python3 artifact_analyzer.py --timestomp   # Solo Timestomping
    python3 artifact_analyzer.py --timeline    # Timeline consolidada

Autor: MAR404 - Cacería de Amenazas
=============================================================================
"""

import sys
import os

# Agregar directorio de herramientas al path
sys.path.insert(0, '/tools/parsers')
sys.path.insert(0, '/opt/lab19/scripts')

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()


def show_menu():
    """Muestra menú interactivo."""
    console.print(Panel.fit(
        "[bold cyan]FORENSIC ARTIFACT ANALYZER[/bold cyan]\n"
        "Caso: IR-2026-0715-001 | Host: SRV-FIN-01\n"
        "═══════════════════════════════════════════",
        border_style="cyan"
    ))
    
    console.print("""
[bold]Selecciona un análisis:[/bold]

  [cyan]1[/cyan] - Análisis de Prefetch (ejecuciones de programas)
  [cyan]2[/cyan] - Análisis de Amcache (inventario de aplicaciones)
  [cyan]3[/cyan] - Análisis de UserAssist (programas ejecutados via shell)
  [cyan]4[/cyan] - Análisis de MFT (timestamps del sistema de archivos)
  [cyan]5[/cyan] - Detección de Timestomping (T1070.006)
  [cyan]6[/cyan] - Timeline consolidada del ataque
  [cyan]7[/cyan] - Quick Wins (búsqueda rápida de IOCs)
  [cyan]8[/cyan] - Ejecutar TODOS los análisis
  [cyan]0[/cyan] - Salir

    """)
    
    choice = Prompt.ask("Opción", choices=["0","1","2","3","4","5","6","7","8"], default="8")
    return choice


def run_analysis(module):
    """Ejecuta un módulo de análisis."""
    os.system(f"python3 /tools/parsers/{module}")


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == '--all':
            modules = [
                ('prefetch_parser.py', 'PREFETCH'),
                ('amcache_parser.py', 'AMCACHE'),
                ('userassist_decoder.py', 'USERASSIST'),
                ('mft_analyzer.py', 'MFT'),
                ('timestomp_detector.py', 'TIMESTOMPING'),
                ('timeline_builder.py', 'TIMELINE'),
            ]
            for mod, name in modules:
                console.print(f"\n[bold cyan]{'═' * 70}[/bold cyan]")
                console.print(f"[bold cyan]  {name} ANALYSIS[/bold cyan]")
                console.print(f"[bold cyan]{'═' * 70}[/bold cyan]\n")
                run_analysis(mod)
        elif arg == '--prefetch':
            run_analysis('prefetch_parser.py')
        elif arg == '--amcache':
            run_analysis('amcache_parser.py')
        elif arg == '--userassist':
            run_analysis('userassist_decoder.py')
        elif arg == '--mft':
            run_analysis('mft_analyzer.py')
        elif arg == '--timestomp':
            run_analysis('timestomp_detector.py')
        elif arg == '--timeline':
            run_analysis('timeline_builder.py')
        elif arg == '--help':
            console.print("""
[bold]Uso:[/bold] python3 artifact_analyzer.py [OPCIÓN]

[bold]Opciones:[/bold]
  (sin args)      Menú interactivo
  --all           Ejecuta todos los análisis
  --prefetch      Solo análisis de Prefetch
  --amcache       Solo análisis de Amcache
  --userassist    Solo análisis de UserAssist
  --mft           Solo análisis de MFT
  --timestomp     Solo detección de timestomping
  --timeline      Timeline consolidada
  --help          Muestra esta ayuda
            """)
    else:
        # Modo interactivo
        while True:
            choice = show_menu()
            if choice == '0':
                break
            elif choice == '1':
                run_analysis('prefetch_parser.py')
            elif choice == '2':
                run_analysis('amcache_parser.py')
            elif choice == '3':
                run_analysis('userassist_decoder.py')
            elif choice == '4':
                run_analysis('mft_analyzer.py')
            elif choice == '5':
                run_analysis('timestomp_detector.py')
            elif choice == '6':
                run_analysis('timeline_builder.py')
            elif choice == '7':
                os.system('bash /tools/scripts/hunt_helper.sh quick-wins')
            elif choice == '8':
                os.system(f"python3 {sys.argv[0]} --all")
            
            input("\nPresiona Enter para continuar...")


if __name__ == "__main__":
    main()
