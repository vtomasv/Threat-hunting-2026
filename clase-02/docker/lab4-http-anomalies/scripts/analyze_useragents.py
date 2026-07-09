#!/usr/bin/env python3
"""
MAR404 - Clase 2 - Lab 4
Herramienta de análisis de User-Agents en PCAP.
Extrae, clasifica y detecta anomalías en User-Agents HTTP.
"""
import subprocess
import sys
from collections import Counter

PCAP = "/pcap/http_useragent_lab.pcap"

def extract_user_agents():
    """Extrae User-Agents del PCAP usando tshark."""
    cmd = f"tshark -r {PCAP} -Y 'http.user_agent' -T fields -e ip.src -e ip.dst -e http.user_agent"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    entries = []
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 3:
                entries.append({
                    'src_ip': parts[0],
                    'dst_ip': parts[1],
                    'user_agent': parts[2]
                })
    return entries

def analyze():
    """Análisis principal de User-Agents."""
    entries = extract_user_agents()
    
    if not entries:
        print("[!] No se encontraron User-Agents en el PCAP")
        return
    
    print(f"\n{'='*70}")
    print(f" ANÁLISIS DE USER-AGENTS - Lab 4")
    print(f"{'='*70}")
    print(f"\n[+] Total de requests HTTP con UA: {len(entries)}")
    
    # Contar UAs únicos
    ua_counter = Counter(e['user_agent'] for e in entries)
    print(f"[+] User-Agents únicos: {len(ua_counter)}")
    
    print(f"\n{'='*70}")
    print(f" USER-AGENTS POR FRECUENCIA")
    print(f"{'='*70}")
    for ua, count in ua_counter.most_common():
        print(f"  [{count:3d}x] {ua[:80]}")
    
    # Análisis por host
    print(f"\n{'='*70}")
    print(f" USER-AGENTS POR HOST ORIGEN")
    print(f"{'='*70}")
    host_uas = {}
    for e in entries:
        src = e['src_ip']
        if src not in host_uas:
            host_uas[src] = set()
        host_uas[src].add(e['user_agent'])
    
    for host, uas in sorted(host_uas.items()):
        print(f"\n  Host: {host} ({len(uas)} UA(s) distintos)")
        for ua in uas:
            print(f"    - {ua[:75]}")
    
    # Detección de anomalías
    print(f"\n{'='*70}")
    print(f" ANOMALÍAS DETECTADAS")
    print(f"{'='*70}")
    
    anomalies = []
    for ua, count in ua_counter.items():
        # UA usado por un solo host
        hosts_using = set(e['src_ip'] for e in entries if e['user_agent'] == ua)
        if len(hosts_using) == 1 and count > 3:
            # UA con pocas palabras (UAs legítimos suelen ser largos)
            if len(ua) < 30:
                anomalies.append({
                    'ua': ua,
                    'count': count,
                    'host': list(hosts_using)[0],
                    'reason': 'UA corto, usado solo por 1 host, alta frecuencia'
                })
    
    if anomalies:
        for a in anomalies:
            print(f"\n  [!] SOSPECHOSO: \"{a['ua']}\"")
            print(f"      Host: {a['host']}")
            print(f"      Frecuencia: {a['count']} requests")
            print(f"      Razón: {a['reason']}")
    else:
        print("  No se detectaron anomalías automáticas.")
        print("  Tip: Revise manualmente UAs cortos o con versiones obsoletas.")
    
    # Destinos del UA sospechoso
    if anomalies:
        print(f"\n{'='*70}")
        print(f" DESTINOS DEL UA SOSPECHOSO")
        print(f"{'='*70}")
        for a in anomalies:
            dsts = set(e['dst_ip'] for e in entries if e['user_agent'] == a['ua'])
            for dst in dsts:
                count = sum(1 for e in entries if e['user_agent'] == a['ua'] and e['dst_ip'] == dst)
                print(f"  {a['host']} → {dst} ({count} requests)")

if __name__ == "__main__":
    analyze()
