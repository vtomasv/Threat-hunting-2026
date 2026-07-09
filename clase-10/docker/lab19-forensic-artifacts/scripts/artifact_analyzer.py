#!/usr/bin/env python3
"""
artifact_analyzer.py - Analiza artefactos forenses para hunting
Curso MAR404 - Clase 10 - Lab 19
"""
import json, sys

EVIDENCE_DIR = "/evidence"

def analyze_prefetch():
    with open(f"{EVIDENCE_DIR}/prefetch/prefetch_analysis.json") as f:
        entries = json.load(f)
    print("=" * 70)
    print("  PREFETCH ANALYSIS")
    print("=" * 70)
    for e in entries:
        flag = "[!]" if e["category"] == "malicious" else "[?]" if e["category"] == "suspicious" else "[OK]"
        print(f"\n  {flag} {e['exe']}")
        print(f"      Path: {e['path']}")
        print(f"      Run Count: {e['run_count']} | Last Run: {e['last_run']}")
        if e.get("note"):
            print(f"      → {e['note']}")

def analyze_amcache():
    with open(f"{EVIDENCE_DIR}/amcache/amcache_entries.json") as f:
        entries = json.load(f)
    print("=" * 70)
    print("  AMCACHE ANALYSIS")
    print("=" * 70)
    for e in entries:
        flag = "[!]" if e["category"] == "malicious" else "[?]" if e["category"] == "suspicious" else "[OK]"
        print(f"\n  {flag} {e['path']}")
        print(f"      SHA1: {e['sha1']}")
        print(f"      Size: {e['size']} | Publisher: {e.get('publisher','N/A')}")
        print(f"      First Run: {e['first_run']}")
        if e.get("note"):
            print(f"      → {e['note']}")

def analyze_mft():
    with open(f"{EVIDENCE_DIR}/mft/mft_timeline.json") as f:
        entries = json.load(f)
    print("=" * 70)
    print("  MFT TIMELINE ANALYSIS")
    print("=" * 70)
    for e in sorted(entries, key=lambda x: x["created"]):
        flag = "[!]" if e["category"] == "malicious" else "[?]" if e["category"] == "suspicious" else "[OK]"
        print(f"\n  {flag} {e['path']}{e['filename']}")
        print(f"      Size: {e['size']:,} bytes")
        print(f"      Created:  {e['created']}")
        print(f"      Modified: {e['modified']}")
        print(f"      Accessed: {e['accessed']}")
        if e.get("note"):
            print(f"      → {e['note']}")

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--all"
    if mode == "--prefetch": analyze_prefetch()
    elif mode == "--amcache": analyze_amcache()
    elif mode == "--mft": analyze_mft()
    elif mode == "--all":
        analyze_prefetch()
        print()
        analyze_amcache()
        print()
        analyze_mft()
    else:
        print("Uso: artifact_analyzer [--prefetch|--amcache|--mft|--all]")

if __name__ == "__main__":
    main()
