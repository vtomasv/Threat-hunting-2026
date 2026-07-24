#!/usr/bin/env python3
"""
=============================================================================
log_analyzer.py - Analizador de Logs de Apache para Web Shell Hunting
=============================================================================
Analiza los logs de acceso de Apache para identificar:
1. IPs con comportamiento anómalo (muchos POST, escaneo de directorios)
2. User-Agents sospechosos (herramientas automatizadas)
3. Accesos a archivos sospechosos
4. Patrones temporales anómalos (accesos en horarios inusuales)
5. Parámetros de URL sospechosos

Uso:
    python3 log_analyzer.py --overview         # Vista general del tráfico
    python3 log_analyzer.py --suspicious-ips   # IPs sospechosas
    python3 log_analyzer.py --user-agents      # User-Agents anómalos
    python3 log_analyzer.py --post-requests    # Requests POST sospechosos
    python3 log_analyzer.py --timeline         # Timeline de actividad
    python3 log_analyzer.py --attacker-profile # Perfil del atacante

Autor: MAR404 - Cacería de Amenazas
=============================================================================
"""

import re
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
LOG_FILE = "/evidence/server-image/var/log/apache2/access.log"

# Regex para parsear Apache Combined Log Format
LOG_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
)

# IPs internas conocidas
INTERNAL_RANGES = ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.']

# User-Agents sospechosos
SUSPICIOUS_UA_PATTERNS = [
    'python-requests', 'curl/', 'wget/', 'nikto', 'sqlmap',
    'dirbuster', 'gobuster', 'wfuzz', 'burp', 'zap',
    'MSIE 6.0', 'MSIE 5.0', 'compatible; MSIE'
]


def parse_logs():
    """Parsea el archivo de logs."""
    if not os.path.exists(LOG_FILE):
        console.print(f"[red]ERROR: No se encontró {LOG_FILE}[/red]")
        sys.exit(1)
    
    entries = []
    with open(LOG_FILE) as f:
        for line in f:
            match = LOG_PATTERN.match(line)
            if match:
                ip, timestamp, method, path, status, size, referer, ua = match.groups()
                entries.append({
                    'ip': ip,
                    'timestamp': timestamp,
                    'method': method,
                    'path': path,
                    'status': int(status),
                    'size': int(size),
                    'referer': referer,
                    'user_agent': ua,
                    'raw': line.strip()
                })
    return entries


def overview():
    """Vista general del tráfico."""
    entries = parse_logs()
    
    ip_counter = Counter(e['ip'] for e in entries)
    method_counter = Counter(e['method'] for e in entries)
    status_counter = Counter(e['status'] for e in entries)
    
    console.print(Panel.fit(
        f"[bold cyan]OVERVIEW DE TRÁFICO WEB[/bold cyan]\n"
        f"Total de requests: {len(entries)}\n"
        f"IPs únicas: {len(ip_counter)}\n"
        f"Período: {entries[0]['timestamp'][:11]} — {entries[-1]['timestamp'][:11]}",
        border_style="cyan"
    ))
    
    # Top IPs
    console.print("\n[bold]Top 10 IPs por volumen de requests:[/bold]")
    table = Table(box=box.SIMPLE)
    table.add_column("IP", width=18)
    table.add_column("Requests", justify="right", width=10)
    table.add_column("Tipo", width=12)
    
    for ip, count in ip_counter.most_common(10):
        ip_type = "INTERNA" if any(ip.startswith(r) for r in INTERNAL_RANGES) else "[red]EXTERNA[/red]"
        table.add_row(ip, str(count), ip_type)
    
    console.print(table)
    
    # Métodos
    console.print("\n[bold]Distribución de métodos HTTP:[/bold]")
    for method, count in method_counter.most_common():
        bar = "█" * min(count // 5, 40)
        console.print(f"  {method:6s} {count:5d} {bar}")
    
    # Status codes
    console.print("\n[bold]Códigos de respuesta:[/bold]")
    for status, count in sorted(status_counter.items()):
        color = "green" if status < 300 else "yellow" if status < 400 else "red"
        console.print(f"  [{color}]{status}[/{color}]: {count}")


def suspicious_ips():
    """Identifica IPs con comportamiento sospechoso."""
    entries = parse_logs()
    
    console.print(Panel.fit(
        "[bold red]ANÁLISIS DE IPs SOSPECHOSAS[/bold red]",
        border_style="red"
    ))
    
    ip_data = defaultdict(lambda: {
        'total': 0, 'posts': 0, 'gets': 0, 'errors_404': 0,
        'paths': set(), 'user_agents': set(), 'timestamps': []
    })
    
    for e in entries:
        ip = e['ip']
        ip_data[ip]['total'] += 1
        ip_data[ip]['paths'].add(e['path'])
        ip_data[ip]['user_agents'].add(e['user_agent'])
        ip_data[ip]['timestamps'].append(e['timestamp'])
        if e['method'] == 'POST':
            ip_data[ip]['posts'] += 1
        elif e['method'] == 'GET':
            ip_data[ip]['gets'] += 1
        if e['status'] == 404:
            ip_data[ip]['errors_404'] += 1
    
    # Evaluar sospecha
    suspicious = []
    for ip, data in ip_data.items():
        score = 0
        reasons = []
        
        # IP externa
        if not any(ip.startswith(r) for r in INTERNAL_RANGES):
            score += 2
            reasons.append("IP externa")
        
        # Muchos 404 (escaneo)
        if data['errors_404'] > 5:
            score += 3
            reasons.append(f"{data['errors_404']} errores 404 (posible escaneo)")
        
        # Ratio POST alto
        if data['posts'] > 0 and data['posts'] / max(data['total'], 1) > 0.3:
            score += 3
            reasons.append(f"Alto ratio POST ({data['posts']}/{data['total']})")
        
        # User-agent sospechoso
        for ua in data['user_agents']:
            if any(s in ua.lower() for s in SUSPICIOUS_UA_PATTERNS):
                score += 2
                reasons.append(f"User-Agent sospechoso: {ua[:40]}")
                break
        
        # Acceso a paths sensibles
        sensitive_paths = ['/admin', '/includes/config', '/uploads/', '/cache/cache_manager']
        for path in data['paths']:
            if any(s in path for s in sensitive_paths):
                score += 1
        
        if score >= 4:
            suspicious.append((ip, data, score, reasons))
    
    # Ordenar por score
    suspicious.sort(key=lambda x: x[2], reverse=True)
    
    for ip, data, score, reasons in suspicious:
        color = "red" if score >= 6 else "yellow"
        console.print(f"\n[{color}]{'═' * 60}[/{color}]")
        console.print(f"[{color}]  IP: {ip} (Score: {score}/10)[/{color}]")
        console.print(f"  Total requests: {data['total']} | POST: {data['posts']} | 404s: {data['errors_404']}")
        console.print(f"  Paths únicos: {len(data['paths'])}")
        console.print(f"  User-Agents: {', '.join(list(data['user_agents'])[:2])}")
        console.print(f"  Razones:")
        for r in reasons:
            console.print(f"    [yellow]⚠ {r}[/yellow]")


def analyze_post_requests():
    """Analiza requests POST sospechosos."""
    entries = parse_logs()
    posts = [e for e in entries if e['method'] == 'POST']
    
    console.print(Panel.fit(
        f"[bold yellow]ANÁLISIS DE REQUESTS POST[/bold yellow]\n"
        f"Total POST requests: {len(posts)}",
        border_style="yellow"
    ))
    
    # Agrupar por path
    post_paths = Counter(e['path'] for e in posts)
    
    console.print("\n[bold]Destinos de POST requests:[/bold]")
    for path, count in post_paths.most_common(20):
        # Marcar paths sospechosos
        suspicious = False
        if any(s in path for s in ['config.php', 'doc_processor', '.php.jpg', 'cache_manager']):
            suspicious = True
        
        color = "red" if suspicious else "white"
        console.print(f"  [{color}]{count:3d}x POST {path}[/{color}]")
    
    # Mostrar POST a archivos no-formulario (sospechoso)
    console.print("\n[bold red]POST a archivos que NO son formularios:[/bold red]")
    non_form_posts = [e for e in posts if not any(
        f in e['path'] for f in ['contact.php', 'login.php', 'upload.php', 'api/']
    )]
    
    for e in non_form_posts[:20]:
        is_external = not any(e['ip'].startswith(r) for r in INTERNAL_RANGES)
        if is_external:
            console.print(f"  [red]{e['ip']} → POST {e['path']}[/red]")
            console.print(f"    UA: {e['user_agent'][:60]}")
            console.print(f"    Time: {e['timestamp']}")


def attacker_profile():
    """Construye el perfil del atacante basado en los logs."""
    entries = parse_logs()
    
    console.print(Panel.fit(
        "[bold red]PERFIL DEL ATACANTE[/bold red]",
        border_style="red"
    ))
    
    # Identificar IPs externas con actividad sospechosa
    external_ips = set()
    for e in entries:
        if not any(e['ip'].startswith(r) for r in INTERNAL_RANGES):
            external_ips.add(e['ip'])
    
    for attacker_ip in external_ips:
        attacker_entries = [e for e in entries if e['ip'] == attacker_ip]
        
        if len(attacker_entries) < 5:
            continue
        
        console.print(f"\n[red]{'═' * 60}[/red]")
        console.print(f"[red bold]  ATACANTE: {attacker_ip}[/red bold]")
        console.print(f"[red]{'═' * 60}[/red]")
        
        # Actividad
        console.print(f"\n  Total de requests: {len(attacker_entries)}")
        console.print(f"  Primer acceso: {attacker_entries[0]['timestamp']}")
        console.print(f"  Último acceso: {attacker_entries[-1]['timestamp']}")
        
        # User-Agents usados
        uas = set(e['user_agent'] for e in attacker_entries)
        console.print(f"\n  User-Agents utilizados ({len(uas)}):")
        for ua in uas:
            console.print(f"    • {ua}")
        
        # Paths accedidos
        paths = [e['path'] for e in attacker_entries]
        console.print(f"\n  Paths accedidos ({len(set(paths))} únicos):")
        for path, count in Counter(paths).most_common(15):
            method = next((e['method'] for e in attacker_entries if e['path'] == path), 'GET')
            console.print(f"    {count:3d}x {method} {path}")
        
        # Fases del ataque
        console.print(f"\n  [bold]Fases del ataque identificadas:[/bold]")
        
        # Reconocimiento (404s)
        recon = [e for e in attacker_entries if e['status'] == 404]
        if recon:
            console.print(f"    1. Reconocimiento: {len(recon)} paths probados (404)")
        
        # Explotación (uploads)
        uploads = [e for e in attacker_entries if 'upload' in e['path'].lower() and e['method'] == 'POST']
        if uploads:
            console.print(f"    2. Explotación: {len(uploads)} uploads realizados")
        
        # Post-explotación (acceso a shells)
        shell_access = [e for e in attacker_entries if e['method'] == 'POST' and 
                       any(s in e['path'] for s in ['config.php', 'doc_processor', '.php.jpg', 'cache_manager'])]
        if shell_access:
            console.print(f"    3. Post-explotación: {len(shell_access)} accesos a web shells")


def main():
    if len(sys.argv) < 2:
        overview()
    elif sys.argv[1] == '--overview':
        overview()
    elif sys.argv[1] == '--suspicious-ips':
        suspicious_ips()
    elif sys.argv[1] == '--post-requests':
        analyze_post_requests()
    elif sys.argv[1] == '--attacker-profile':
        attacker_profile()
    elif sys.argv[1] == '--help':
        console.print("""
[bold]Uso:[/bold] python3 log_analyzer.py [OPCIÓN]

[bold]Opciones:[/bold]
  --overview          Vista general del tráfico
  --suspicious-ips    IPs con comportamiento anómalo
  --post-requests     Análisis de requests POST
  --attacker-profile  Perfil completo del atacante
  --help              Muestra esta ayuda
        """)
    else:
        overview()


if __name__ == "__main__":
    main()
