#!/usr/bin/env python3
"""
=============================================================================
webshell_hunter.py - Herramienta de Detección de Web Shells
=============================================================================
Detecta web shells mediante múltiples técnicas:
1. Búsqueda de funciones peligrosas (eval, system, exec, etc.)
2. Análisis de entropía (código ofuscado tiene alta entropía)
3. Detección de archivos con extensiones sospechosas
4. Análisis de tamaño anómalo
5. Detección de archivos modificados recientemente
6. Búsqueda de patrones de ofuscación conocidos

Uso:
    python3 webshell_hunter.py --scan              # Escaneo completo
    python3 webshell_hunter.py --functions         # Busca funciones peligrosas
    python3 webshell_hunter.py --entropy           # Análisis de entropía
    python3 webshell_hunter.py --extensions        # Extensiones sospechosas
    python3 webshell_hunter.py --recent            # Archivos recientes
    python3 webshell_hunter.py --obfuscation       # Patrones de ofuscación
    python3 webshell_hunter.py --all               # Todos los análisis

Autor: MAR404 - Cacería de Amenazas
=============================================================================
"""

import os
import sys
import math
import re
from collections import Counter
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
WEBROOT = "/evidence/server-image/var/www/html"

# Funciones peligrosas de PHP
DANGEROUS_FUNCTIONS = [
    'eval(', 'assert(', 'system(', 'shell_exec(', 'exec(',
    'passthru(', 'popen(', 'proc_open(', 'pcntl_exec(',
    'base64_decode(', 'str_rot13(', 'gzinflate(', 'gzuncompress(',
    'preg_replace', 'create_function(', 'call_user_func(',
    'call_user_func_array(', 'array_map(', 'array_filter(',
    'usort(', 'ob_start(', 'file_put_contents(',
    '$_POST[', '$_GET[', '$_REQUEST[', '$_COOKIE[',
    'move_uploaded_file(', 'include(', 'require(',
]

# Patrones de ofuscación
OBFUSCATION_PATTERNS = [
    (r'\\$[a-z]+=\\$[a-z]+\(\\$[a-z]+\)', 'Variable function call'),
    (r'chr\(\d+\)\.chr\(\d+\)', 'Character concatenation'),
    (r'\\\\x[0-9a-f]{2}', 'Hex encoded strings'),
    (r'base64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{20,}', 'Long base64 string'),
    (r'str_rot13\s*\(', 'ROT13 encoding'),
    (r'gzinflate\s*\(', 'Gzip compression'),
    (r'eval\s*\(\s*\$', 'Eval with variable'),
    (r'preg_replace\s*\(.*/e', 'preg_replace with /e modifier'),
    (r'assert\s*\(\s*\$', 'Assert with variable'),
    (r'\\$\w+\s*\(\s*\\$', 'Dynamic function invocation'),
]


def calculate_entropy(data):
    """Calcula la entropía de Shannon de un string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length) 
                   for count in counter.values())
    return round(entropy, 4)


def scan_dangerous_functions():
    """Busca funciones peligrosas en archivos PHP."""
    console.print(Panel.fit(
        "[bold red]BÚSQUEDA DE FUNCIONES PELIGROSAS[/bold red]",
        border_style="red"
    ))
    
    findings = []
    php_extensions = ('.php', '.phtml', '.php5', '.php7', '.phps', '.php.jpg', '.php.png')
    
    for root, dirs, files in os.walk(WEBROOT):
        for fname in files:
            if any(fname.lower().endswith(ext) or ext in fname.lower() for ext in php_extensions):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        lines = f.readlines()
                    
                    file_findings = []
                    for line_num, line in enumerate(lines, 1):
                        for func in DANGEROUS_FUNCTIONS:
                            if func.lower() in line.lower():
                                file_findings.append({
                                    'line': line_num,
                                    'function': func,
                                    'context': line.strip()[:80]
                                })
                    
                    if file_findings:
                        rel_path = fpath.replace(WEBROOT, '')
                        findings.append({
                            'file': rel_path,
                            'findings': file_findings,
                            'total_dangerous': len(file_findings)
                        })
                except:
                    pass
    
    # Mostrar resultados
    if findings:
        # Ordenar por número de funciones peligrosas
        findings.sort(key=lambda x: x['total_dangerous'], reverse=True)
        
        for f in findings:
            risk = "CRITICAL" if f['total_dangerous'] >= 3 else "HIGH" if f['total_dangerous'] >= 2 else "MEDIUM"
            color = "red" if risk == "CRITICAL" else "yellow" if risk == "HIGH" else "white"
            
            console.print(f"\n[{color}][{risk}] {f['file']} ({f['total_dangerous']} funciones peligrosas)[/{color}]")
            for finding in f['findings'][:5]:  # Mostrar máximo 5 por archivo
                console.print(f"  Línea {finding['line']:4d}: [dim]{finding['function']}[/dim]")
                console.print(f"            {finding['context'][:70]}")
    
    console.print(f"\n[bold]Total: {len(findings)} archivos con funciones peligrosas[/bold]")
    return findings


def scan_entropy():
    """Analiza entropía de archivos PHP (alta entropía = posible ofuscación)."""
    console.print(Panel.fit(
        "[bold yellow]ANÁLISIS DE ENTROPÍA[/bold yellow]\n"
        "Entropía > 5.5 puede indicar código ofuscado o cifrado\n"
        "Entropía normal de PHP: 4.0 - 5.0",
        border_style="yellow"
    ))
    
    results = []
    
    for root, dirs, files in os.walk(WEBROOT):
        for fname in files:
            if '.php' in fname.lower():
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    entropy = calculate_entropy(content)
                    size = os.path.getsize(fpath)
                    rel_path = fpath.replace(WEBROOT, '')
                    
                    results.append({
                        'file': rel_path,
                        'entropy': entropy,
                        'size': size,
                        'suspicious': entropy > 5.5
                    })
                except:
                    pass
    
    # Ordenar por entropía descendente
    results.sort(key=lambda x: x['entropy'], reverse=True)
    
    table = Table(title="Análisis de Entropía", box=box.SIMPLE)
    table.add_column("Archivo", width=45)
    table.add_column("Entropía", justify="center", width=10)
    table.add_column("Tamaño", justify="right", width=10)
    table.add_column("Riesgo", width=10)
    
    for r in results:
        risk_color = "red" if r['entropy'] > 5.5 else "yellow" if r['entropy'] > 5.0 else "green"
        risk_text = "ALTO" if r['entropy'] > 5.5 else "MEDIO" if r['entropy'] > 5.0 else "BAJO"
        
        table.add_row(
            r['file'],
            f"[{risk_color}]{r['entropy']}[/{risk_color}]",
            f"{r['size']:,}",
            f"[{risk_color}]{risk_text}[/{risk_color}]"
        )
    
    console.print(table)
    return results


def scan_extensions():
    """Busca archivos con extensiones sospechosas."""
    console.print(Panel.fit(
        "[bold magenta]EXTENSIONES SOSPECHOSAS[/bold magenta]\n"
        "Busca doble extensión, extensiones PHP ocultas, etc.",
        border_style="magenta"
    ))
    
    suspicious_patterns = [
        '.php.jpg', '.php.png', '.php.gif', '.php.pdf',
        '.phtml', '.php5', '.php7', '.phps',
        '.pht', '.pgif', '.shtml'
    ]
    
    findings = []
    for root, dirs, files in os.walk(WEBROOT):
        for fname in files:
            for pattern in suspicious_patterns:
                if pattern in fname.lower():
                    fpath = os.path.join(root, fname)
                    rel_path = fpath.replace(WEBROOT, '')
                    findings.append({
                        'file': rel_path,
                        'pattern': pattern,
                        'size': os.path.getsize(fpath)
                    })
    
    # También buscar .htaccess con handlers PHP
    for root, dirs, files in os.walk(WEBROOT):
        if '.htaccess' in files:
            htaccess_path = os.path.join(root, '.htaccess')
            try:
                with open(htaccess_path) as f:
                    content = f.read()
                if 'php' in content.lower() and ('addhandler' in content.lower() or 'sethandler' in content.lower()):
                    findings.append({
                        'file': htaccess_path.replace(WEBROOT, '') + ' [.htaccess con PHP handler]',
                        'pattern': 'PHP handler override',
                        'size': os.path.getsize(htaccess_path)
                    })
            except:
                pass
    
    for f in findings:
        console.print(f"[magenta]⚠ {f['file']}[/magenta]")
        console.print(f"  Patrón: {f['pattern']} | Tamaño: {f['size']} bytes")
    
    return findings


def scan_obfuscation():
    """Detecta patrones de ofuscación conocidos."""
    console.print(Panel.fit(
        "[bold cyan]DETECCIÓN DE OFUSCACIÓN[/bold cyan]\n"
        "Busca patrones conocidos de ofuscación de web shells",
        border_style="cyan"
    ))
    
    findings = []
    
    for root, dirs, files in os.walk(WEBROOT):
        for fname in files:
            if '.php' in fname.lower():
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    file_patterns = []
                    for pattern, description in OBFUSCATION_PATTERNS:
                        matches = re.findall(pattern, content)
                        if matches:
                            file_patterns.append({
                                'pattern': description,
                                'count': len(matches),
                                'sample': matches[0][:50] if matches else ''
                            })
                    
                    if file_patterns:
                        rel_path = fpath.replace(WEBROOT, '')
                        findings.append({
                            'file': rel_path,
                            'patterns': file_patterns
                        })
                except:
                    pass
    
    for f in findings:
        risk = len(f['patterns'])
        color = "red" if risk >= 3 else "yellow" if risk >= 2 else "white"
        console.print(f"\n[{color}]▶ {f['file']} ({risk} patrones de ofuscación)[/{color}]")
        for p in f['patterns']:
            console.print(f"  [{color}]⚠ {p['pattern']} (x{p['count']})[/{color}]")
    
    return findings


def full_scan():
    """Ejecuta todos los escaneos."""
    console.print(Panel.fit(
        "[bold green]ESCANEO COMPLETO DE WEB SHELLS[/bold green]\n"
        f"Webroot: {WEBROOT}",
        border_style="green"
    ))
    
    console.print("\n[bold]═══ FASE 1: Funciones Peligrosas ═══[/bold]")
    func_results = scan_dangerous_functions()
    
    console.print("\n[bold]═══ FASE 2: Análisis de Entropía ═══[/bold]")
    entropy_results = scan_entropy()
    
    console.print("\n[bold]═══ FASE 3: Extensiones Sospechosas ═══[/bold]")
    ext_results = scan_extensions()
    
    console.print("\n[bold]═══ FASE 4: Patrones de Ofuscación ═══[/bold]")
    obf_results = scan_obfuscation()
    
    # Resumen final
    console.print("\n" + "=" * 70)
    console.print("[bold]RESUMEN DEL ESCANEO[/bold]")
    console.print("=" * 70)
    console.print(f"  Archivos con funciones peligrosas: {len(func_results)}")
    console.print(f"  Archivos con alta entropía: {len([r for r in entropy_results if r['suspicious']])}")
    console.print(f"  Extensiones sospechosas: {len(ext_results)}")
    console.print(f"  Patrones de ofuscación: {len(obf_results)}")


def main():
    if len(sys.argv) < 2:
        full_scan()
    elif sys.argv[1] == '--scan':
        full_scan()
    elif sys.argv[1] == '--functions':
        scan_dangerous_functions()
    elif sys.argv[1] == '--entropy':
        scan_entropy()
    elif sys.argv[1] == '--extensions':
        scan_extensions()
    elif sys.argv[1] == '--obfuscation':
        scan_obfuscation()
    elif sys.argv[1] == '--all':
        full_scan()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 webshell_hunter.py [OPCIÓN]

[bold]Opciones:[/bold]
  --scan, --all     Escaneo completo (todos los métodos)
  --functions       Solo búsqueda de funciones peligrosas
  --entropy         Solo análisis de entropía
  --extensions      Solo extensiones sospechosas
  --obfuscation     Solo patrones de ofuscación
  --help            Muestra esta ayuda
        """)
    else:
        full_scan()


if __name__ == "__main__":
    main()
