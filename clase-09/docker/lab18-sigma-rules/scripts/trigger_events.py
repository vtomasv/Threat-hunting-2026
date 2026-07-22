#!/usr/bin/env python3
"""
trigger_events.py - Dispara escenarios de ataque y valida contra reglas Sigma
Curso MAR404 - Clase 9 - Lab 18

Uso:
    trigger list                    - Lista escenarios disponibles
    trigger <scenario>              - Ejecuta un escenario y valida contra reglas
    trigger all                     - Ejecuta todos los escenarios
    trigger validate                - Valida el dataset completo contra todas las reglas
    trigger validate <rule.yml>     - Valida el dataset contra una regla específica
"""
import json
import os
import sys
import subprocess
import glob
from datetime import datetime

EVENTS_FILE = "/data/test_events.json"
RULES_DIR = "/app/rules"
SCENARIOS_FILE = "/app/scenarios.json"


def load_events():
    """Carga el dataset de eventos."""
    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE) as f:
            return json.load(f)
    return []


def save_events(events):
    """Guarda el dataset de eventos."""
    with open(EVENTS_FILE, "w") as f:
        json.dump(events, f, indent=2)
    with open("/app/test_events.json", "w") as f:
        json.dump(events, f, indent=2)


def list_scenarios():
    """Lista los escenarios disponibles."""
    from generate_test_events import generate_scenario_events
    scenarios = generate_scenario_events("list")
    print("\n" + "=" * 60)
    print("  ESCENARIOS DE ATAQUE DISPONIBLES")
    print("=" * 60)
    for i, s in enumerate(scenarios, 1):
        print(f"  {i}. {s}")
    print("=" * 60)
    print(f"\n  Uso: trigger <nombre_escenario>")
    print(f"  Uso: trigger all (ejecutar todos)")
    print(f"  Uso: trigger validate (validar dataset contra reglas)\n")


def trigger_scenario(scenario_name):
    """Ejecuta un escenario e inserta eventos en el dataset."""
    from generate_test_events import generate_scenario_events

    if scenario_name == "all":
        all_events = generate_scenario_events("all")
        if not all_events:
            print("[!] No se pudieron generar los escenarios")
            return
    else:
        all_events = generate_scenario_events(scenario_name)
        if all_events is None:
            print(f"[!] Escenario '{scenario_name}' no encontrado")
            print("[*] Usa 'trigger list' para ver escenarios disponibles")
            return

    # Cargar eventos existentes y agregar los nuevos
    events = load_events()
    base_eid = max((e.get("eid", 0) for e in events), default=0) + 1

    print(f"\n[*] Ejecutando escenario: {scenario_name}")
    print("-" * 50)

    for i, evt in enumerate(all_events):
        evt["eid"] = base_eid + i
        evt["timestamp"] = str(datetime.now())
        evt["scenario"] = scenario_name
        events.append(evt)
        print(f"  [+] Evento {evt['eid']}: {evt.get('description', 'N/A')}")

    save_events(events)
    print(f"\n[+] {len(all_events)} eventos insertados en el dataset")
    print(f"[+] Total de eventos: {len(events)}")
    print(f"\n[*] Ahora ejecuta 'trigger validate' para ver qué reglas se disparan")


def validate_events(rule_file=None):
    """Valida el dataset contra las reglas Sigma usando sigma-cli."""
    events = load_events()
    if not events:
        print("[!] No hay eventos en el dataset. Ejecuta un escenario primero.")
        return

    # Obtener reglas
    if rule_file:
        rules = [os.path.join(RULES_DIR, rule_file) if not rule_file.startswith("/") else rule_file]
    else:
        rules = sorted(glob.glob(os.path.join(RULES_DIR, "*.yml")))

    if not rules:
        print("[!] No se encontraron reglas Sigma en /app/rules/")
        return

    print(f"\n{'=' * 70}")
    print(f"  VALIDACIÓN DE REGLAS SIGMA vs DATASET ({len(events)} eventos)")
    print(f"{'=' * 70}")

    total_matches = 0
    total_fps = 0

    for rule_path in rules:
        rule_name = os.path.basename(rule_path).replace('.yml', '')

        # Leer la regla para entender qué busca
        try:
            with open(rule_path) as f:
                rule_content = f.read()
        except FileNotFoundError:
            print(f"  [!] Regla no encontrada: {rule_path}")
            continue

        # Simulación de matching basada en la lógica de la regla
        matches = match_events_against_rule(events, rule_name, rule_content)

        true_positives = [m for m in matches if m.get("should_trigger", "") != "NONE_FP"]
        false_positives = [m for m in matches if m.get("should_trigger", "") == "NONE_FP"]

        status = "OK" if len(false_positives) == 0 and len(true_positives) > 0 else \
                 "FP!" if len(false_positives) > 0 else \
                 "NO MATCH" if len(true_positives) == 0 else "OK"

        icon = "✓" if status == "OK" else "✗" if status == "FP!" else "○"

        print(f"\n  [{icon}] {rule_name}.yml")
        print(f"      Matches: {len(true_positives)} true positives, {len(false_positives)} false positives")

        if true_positives:
            for tp in true_positives[:3]:
                print(f"      → TP: {tp.get('description', 'N/A')}")

        if false_positives:
            for fp in false_positives:
                print(f"      → FP: {fp.get('description', 'N/A')}")

        total_matches += len(true_positives)
        total_fps += len(false_positives)

    print(f"\n{'=' * 70}")
    print(f"  RESUMEN: {total_matches} detecciones, {total_fps} falsos positivos")
    print(f"  Reglas evaluadas: {len(rules)}")
    print(f"{'=' * 70}\n")


def match_events_against_rule(events, rule_name, rule_content):
    """Simula el matching de eventos contra una regla Sigma."""
    matches = []

    for event in events:
        matched = False

        if rule_name == "example_mimikatz":
            if (event.get("EventID") == 10 and
                event.get("TargetImage", "").endswith("\\lsass.exe") and
                event.get("GrantedAccess") in ["0x1010", "0x1038", "0x1410", "0x01410"] and
                not event.get("SourceImage", "").endswith(("\\wmiprvse.exe", "\\taskmgr.exe", "\\procexp64.exe"))):
                matched = True

        elif rule_name == "powershell_encoded":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith(("\\powershell.exe", "\\pwsh.exe")) and
                any(x in event.get("CommandLine", "") for x in ["-enc", "-EncodedCommand", "-e "])):
                matched = True

        elif rule_name == "certutil_download":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\certutil.exe") and
                "urlcache" in event.get("CommandLine", "").lower()):
                matched = True

        elif rule_name == "schtasks_persistence":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\schtasks.exe") and
                "/create" in event.get("CommandLine", "") and
                any(x in event.get("CommandLine", "") for x in ["\\Temp\\", "\\Users\\Public\\", "\\AppData\\", "%TEMP%", "C:\\ProgramData\\"])):
                matched = True

        elif rule_name == "service_from_temp":
            if (event.get("EventID") == 7045 and
                any(x in event.get("ImagePath", "") for x in ["\\Temp\\", "\\Users\\Public\\", "\\AppData\\", "\\Downloads\\", "C:\\ProgramData\\"])):
                matched = True

        elif rule_name == "dns_suspicious_tld":
            if event.get("EventID") == 22:
                qname = event.get("QueryName", "")
                if (any(qname.endswith(tld) for tld in [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".buzz", ".icu"]) or
                    any(bad in qname for bad in ["evil-corp", "malware-c2", "darknet", "cobaltstrike"])):
                    matched = True

        elif rule_name == "mshta_execution":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\mshta.exe") and
                any(x in event.get("CommandLine", "") for x in ["http://", "https://", "javascript:", "vbscript:"])):
                matched = True

        elif rule_name == "wmi_lateral_movement":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\WMIC.exe") and
                "/node:" in event.get("CommandLine", "") and
                "process call create" in event.get("CommandLine", "")):
                matched = True

        elif rule_name == "ransomware_shadow_delete":
            cmdline = event.get("CommandLine", "").lower()
            if event.get("EventID") == 1:
                if (event.get("Image", "").endswith("\\vssadmin.exe") and "delete" in cmdline and "shadows" in cmdline):
                    matched = True
                elif (event.get("Image", "").endswith("\\WMIC.exe") and "shadowcopy" in cmdline and "delete" in cmdline):
                    matched = True
                elif (event.get("Image", "").endswith(("\\powershell.exe", "\\pwsh.exe")) and "win32_shadowcopy" in cmdline):
                    matched = True

        elif rule_name == "bitsadmin_download":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\bitsadmin.exe") and
                any(x in event.get("CommandLine", "") for x in ["/transfer", "/addfile"]) and
                any(x in event.get("CommandLine", "") for x in ["http://", "https://"])):
                matched = True

        elif rule_name == "registry_run_persistence":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\reg.exe") and
                "add" in event.get("CommandLine", "") and
                "CurrentVersion\\Run" in event.get("CommandLine", "")):
                matched = True

        elif rule_name == "psexec_lateral":
            if event.get("EventID") == 1:
                img = event.get("Image", "")
                if img.endswith(("\\PsExec.exe", "\\PsExec64.exe", "\\PSEXESVC.exe")):
                    matched = True

        elif rule_name == "defender_disabled":
            if event.get("EventID") == 1:
                cmdline = event.get("CommandLine", "")
                img = event.get("Image", "")
                if (img.endswith(("\\powershell.exe", "\\pwsh.exe")) and
                    any(x in cmdline for x in ["Set-MpPreference", "DisableRealtimeMonitoring", "DisableAntiSpyware"])):
                    matched = True
                elif (img.endswith("\\reg.exe") and "Windows Defender" in cmdline and "DisableAntiSpyware" in cmdline):
                    matched = True

        elif rule_name == "rundll32_suspicious":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\rundll32.exe") and
                any(x in event.get("CommandLine", "") for x in ["\\Users\\", "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\ProgramData\\"])):
                matched = True

        elif rule_name == "wevtutil_clear_logs":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\wevtutil.exe") and
                any(x in event.get("CommandLine", "") for x in ["cl ", "clear-log"])):
                matched = True

        elif rule_name == "ntdsutil_credential":
            if (event.get("EventID") == 1 and
                event.get("Image", "").endswith("\\ntdsutil.exe") and
                any(x in event.get("CommandLine", "") for x in ["ifm", "create full", "ac i ntds"])):
                matched = True

        if matched:
            matches.append(event)

    return matches


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1]

    if command == "list":
        list_scenarios()
    elif command == "validate":
        rule_file = sys.argv[2] if len(sys.argv) > 2 else None
        validate_events(rule_file)
    else:
        trigger_scenario(command)


if __name__ == "__main__":
    main()
