#!/usr/bin/env python3
"""
MAR404 - Clase 3 - Lab 5
Analizador de entropía de subdominios DNS para detectar tunneling.
La entropía alta (>3.5) en subdominios indica datos encoded (Base32/64/hex).
"""
import subprocess
import math
import sys
from collections import Counter

PCAP = "/pcap/dns_tunnel_lab.pcap"


def shannon_entropy(s):
    """Calcula la entropía de Shannon de un string."""
    if not s:
        return 0
    counter = Counter(s)
    length = len(s)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    return entropy


def extract_dns_queries():
    """Extrae queries DNS del PCAP."""
    cmd = f"tshark -r {PCAP} -Y 'dns.qry.name && dns.flags.response == 0' -T fields -e dns.qry.name -e dns.qry.type"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    queries = []
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            parts = line.split('\t')
            if parts:
                queries.append({
                    'name': parts[0],
                    'type': parts[1] if len(parts) > 1 else 'A'
                })
    return queries


def analyze():
    """Análisis principal."""
    queries = extract_dns_queries()
    
    if not queries:
        print("[!] No se encontraron queries DNS")
        return
    
    print(f"\n{'='*70}")
    print(f" ANÁLISIS DE ENTROPÍA DNS - Lab 5")
    print(f"{'='*70}")
    print(f"\n[+] Total queries DNS: {len(queries)}")
    
    # Extraer dominios base (últimos 2 niveles)
    domain_stats = {}
    for q in queries:
        parts = q['name'].rstrip('.').split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            if base_domain not in domain_stats:
                domain_stats[base_domain] = {'count': 0, 'subdomains': [], 'lengths': []}
            domain_stats[base_domain]['count'] += 1
            subdomain = '.'.join(parts[:-2])
            if subdomain:
                domain_stats[base_domain]['subdomains'].append(subdomain)
                domain_stats[base_domain]['lengths'].append(len(subdomain))
    
    # Mostrar dominios por volumen
    print(f"\n{'='*70}")
    print(f" DOMINIOS POR VOLUMEN DE QUERIES")
    print(f"{'='*70}")
    sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1]['count'], reverse=True)
    
    for domain, stats in sorted_domains[:15]:
        avg_len = sum(stats['lengths']) / len(stats['lengths']) if stats['lengths'] else 0
        print(f"  [{stats['count']:4d}] {domain:<35} avg_subdomain_len: {avg_len:.1f}")
    
    # Análisis de entropía por dominio
    print(f"\n{'='*70}")
    print(f" ANÁLISIS DE ENTROPÍA POR DOMINIO")
    print(f"{'='*70}")
    print(f"  {'Dominio':<35} {'Queries':>7} {'Avg Len':>8} {'Avg Entropy':>12} {'Sospechoso':>11}")
    print(f"  {'-'*35} {'-'*7} {'-'*8} {'-'*12} {'-'*11}")
    
    suspicious = []
    for domain, stats in sorted_domains:
        if stats['subdomains']:
            entropies = [shannon_entropy(sd) for sd in stats['subdomains']]
            avg_entropy = sum(entropies) / len(entropies)
            avg_len = sum(stats['lengths']) / len(stats['lengths'])
            
            is_suspicious = avg_entropy > 3.5 and avg_len > 20
            flag = "  ⚠ YES" if is_suspicious else ""
            
            print(f"  {domain:<35} {stats['count']:>7} {avg_len:>8.1f} {avg_entropy:>12.3f} {flag}")
            
            if is_suspicious:
                suspicious.append({
                    'domain': domain,
                    'count': stats['count'],
                    'avg_entropy': avg_entropy,
                    'avg_len': avg_len,
                    'subdomains': stats['subdomains']
                })
    
    # Detalle de dominios sospechosos
    if suspicious:
        print(f"\n{'='*70}")
        print(f" DOMINIOS SOSPECHOSOS (Entropía > 3.5 + Longitud > 20)")
        print(f"{'='*70}")
        
        for s in suspicious:
            print(f"\n  [!] TÚNEL DETECTADO: {s['domain']}")
            print(f"      Queries: {s['count']}")
            print(f"      Entropía promedio: {s['avg_entropy']:.3f}")
            print(f"      Longitud promedio subdominio: {s['avg_len']:.1f} chars")
            print(f"\n      Primeros 5 subdominios:")
            for sd in s['subdomains'][:5]:
                ent = shannon_entropy(sd)
                print(f"        [{ent:.2f}] {sd[:70]}...")
            
            print(f"\n      Para decodificar (Base32):")
            print(f"      $ echo '<subdominio>' | tr 'a-z' 'A-Z' | base64 -d  # o base32")
    else:
        print("\n  No se detectaron dominios con entropía sospechosa.")
    
    print(f"\n{'='*70}")
    print(f" UMBRAL DE REFERENCIA")
    print(f"{'='*70}")
    print(f"  Entropía de texto normal (ej: www.google): ~2.5-3.0")
    print(f"  Entropía de datos encoded (Base32/64):     ~3.5-4.5")
    print(f"  Entropía máxima teórica (aleatorio):       ~4.7 (log2(26))")


if __name__ == "__main__":
    analyze()
