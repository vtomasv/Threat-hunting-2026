#!/usr/bin/env python3
"""
webshell_hunter.py - Detecta web shells mediante múltiples técnicas
Curso MAR404 - Clase 10 - Lab 20
"""
import os, sys, math, re
from collections import Counter

EVIDENCE_DIR = "/evidence"
WEBROOT = f"{EVIDENCE_DIR}/var/www/html"

def calculate_entropy(data):
    if not data: return 0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    return entropy

def scan_suspicious_functions(filepath):
    suspicious = ['eval(', 'system(', 'shell_exec(', 'passthru(', 'exec(', 
                  'base64_decode', 'str_rot13', 'gzinflate', 'preg_replace.*e',
                  '$_POST', '$_REQUEST', '$_GET']
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
            for func in suspicious:
                if func in content:
                    findings.append(func)
    except: pass
    return findings

def scan_directory(path):
    results = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            if fname.endswith(('.php', '.php.jpg', '.phtml', '.php5')):
                fpath = os.path.join(root, fname)
                with open(fpath, 'r', errors='ignore') as f:
                    content = f.read()
                
                entropy = calculate_entropy(content)
                suspicious = scan_suspicious_functions(fpath)
                size = os.path.getsize(fpath)
                
                risk = "LOW"
                if len(suspicious) >= 3: risk = "HIGH"
                elif len(suspicious) >= 1: risk = "MEDIUM"
                if entropy > 5.5: risk = "HIGH"
                
                results.append({
                    "path": fpath.replace(WEBROOT, ""),
                    "size": size,
                    "entropy": round(entropy, 2),
                    "suspicious_functions": suspicious,
                    "risk": risk
                })
    return results

def analyze_logs():
    log_path = f"{EVIDENCE_DIR}/var/log/apache2/access.log"
    if not os.path.exists(log_path): return []
    
    findings = []
    with open(log_path) as f:
        for line in f:
            # POST to PHP files in unusual dirs
            if "POST" in line and (".php" in line):
                if any(x in line for x in ["/uploads/", "/images/", "config.php", "cache"]):
                    if "python-requests" in line or "203.0.113" in line:
                        findings.append(line.strip())
    return findings

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--scan"
    
    if mode == "--scan":
        print("=" * 70)
        print("  WEB SHELL HUNTER — File Scan")
        print("=" * 70)
        results = scan_directory(WEBROOT)
        for r in results:
            icon = "[!!!]" if r["risk"] == "HIGH" else "[!]" if r["risk"] == "MEDIUM" else "[OK]"
            print(f"\n  {icon} {r['path']}")
            print(f"      Size: {r['size']} bytes | Entropy: {r['entropy']}")
            print(f"      Risk: {r['risk']}")
            if r["suspicious_functions"]:
                print(f"      Suspicious: {', '.join(r['suspicious_functions'])}")
    
    elif mode == "--logs":
        print("=" * 70)
        print("  WEB SHELL HUNTER — Log Analysis")
        print("=" * 70)
        findings = analyze_logs()
        print(f"\n  Suspicious log entries: {len(findings)}")
        for f in findings:
            print(f"  [!] {f}")
    
    elif mode == "--yara":
        print("=" * 70)
        print("  WEB SHELL HUNTER — YARA Scan")
        print("=" * 70)
        try:
            import yara
            rules = yara.compile(filepath=f"{EVIDENCE_DIR}/yara/webshells.yar")
            for root, dirs, files in os.walk(WEBROOT):
                for fname in files:
                    if fname.endswith(('.php', '.php.jpg', '.phtml')):
                        fpath = os.path.join(root, fname)
                        matches = rules.match(fpath)
                        if matches:
                            print(f"\n  [!!!] MATCH: {fpath.replace(WEBROOT,'')}")
                            for m in matches:
                                print(f"       Rule: {m.rule}")
                                for s in m.strings:
                                    print(f"       String: {s}")
        except ImportError:
            print("  YARA not available. Install with: pip install yara-python")
    
    else:
        print("Uso: webshell_hunter [--scan|--logs|--yara]")

if __name__ == "__main__":
    main()
