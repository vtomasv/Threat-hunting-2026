#!/usr/bin/env python3
"""
setup_kibana_lab16.py - Configura visualizaciones y dashboard en Kibana para Lab 16
Crea Data View, Saved Searches, Visualizaciones y Dashboard.
"""
import time, json, requests

KIBANA_URL = "http://kibana:5601"
ES_URL = "http://elasticsearch:9200"
INDEX_PATTERN = "windows-security"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


def wait_for_kibana():
    """Espera a que Kibana esté listo."""
    for i in range(120):
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status", {}).get("overall", {}).get("level") == "available":
                    print("[+] Kibana está listo")
                    return True
        except:
            pass
        time.sleep(5)
    print("[-] Timeout esperando Kibana")
    return False


def create_data_view():
    """Crea el Data View para windows-security."""
    payload = {
        "data_view": {
            "title": INDEX_PATTERN,
            "name": "Windows Security Events",
            "timeFieldName": "timestamp"
        }
    }
    r = requests.post(f"{KIBANA_URL}/api/data_views/data_view",
                      headers=HEADERS, json=payload)
    if r.status_code in [200, 409]:
        print(f"[+] Data View '{INDEX_PATTERN}' creado")
        return True
    print(f"[-] Error creando Data View: {r.text[:200]}")
    return False


def create_visualizations():
    """Crea visualizaciones usando Saved Objects API."""
    saved_objects = [
        # Timeline de eventos
        {
            "type": "visualization",
            "id": "lab16-timeline",
            "attributes": {
                "title": "Timeline de Eventos de Seguridad",
                "visState": json.dumps({
                    "title": "Timeline de Eventos de Seguridad",
                    "type": "histogram",
                    "params": {"addTimeMarker": True, "addLegend": True},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "date_histogram", "schema": "segment",
                         "params": {"field": "timestamp", "interval": "auto"}},
                        {"id": "3", "type": "terms", "schema": "group",
                         "params": {"field": "category", "size": 10}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # Event IDs más frecuentes
        {
            "type": "visualization",
            "id": "lab16-event-ids",
            "attributes": {
                "title": "Top Event IDs",
                "visState": json.dumps({
                    "title": "Top Event IDs",
                    "type": "pie",
                    "params": {"addLegend": True, "isDonut": True},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "segment",
                         "params": {"field": "event_id", "size": 15}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # Severidad de eventos
        {
            "type": "visualization",
            "id": "lab16-severity",
            "attributes": {
                "title": "Eventos por Severidad",
                "visState": json.dumps({
                    "title": "Eventos por Severidad",
                    "type": "horizontal_bar",
                    "params": {"addLegend": True},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "segment",
                         "params": {"field": "severity", "size": 5}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # MITRE Techniques
        {
            "type": "visualization",
            "id": "lab16-mitre",
            "attributes": {
                "title": "MITRE ATT&CK Techniques Detectadas",
                "visState": json.dumps({
                    "title": "MITRE ATT&CK Techniques",
                    "type": "tagcloud",
                    "params": {"scale": "linear", "minFontSize": 14, "maxFontSize": 40},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "segment",
                         "params": {"field": "mitre_technique", "size": 20}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # Actividad por host
        {
            "type": "visualization",
            "id": "lab16-hosts",
            "attributes": {
                "title": "Actividad por Host",
                "visState": json.dumps({
                    "title": "Actividad por Host",
                    "type": "horizontal_bar",
                    "params": {"addLegend": True},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "segment",
                         "params": {"field": "hostname", "size": 10}},
                        {"id": "3", "type": "terms", "schema": "group",
                         "params": {"field": "severity", "size": 5}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # Tabla de eventos críticos
        {
            "type": "visualization",
            "id": "lab16-critical-table",
            "attributes": {
                "title": "Eventos Críticos - Hunting Targets",
                "visState": json.dumps({
                    "title": "Eventos Críticos",
                    "type": "table",
                    "params": {"perPage": 20},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "bucket",
                         "params": {"field": "event_id", "size": 20}},
                        {"id": "3", "type": "terms", "schema": "bucket",
                         "params": {"field": "target_user", "size": 10}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "severity:critical", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # Logon Types
        {
            "type": "visualization",
            "id": "lab16-logon-types",
            "attributes": {
                "title": "Distribución de Logon Types",
                "visState": json.dumps({
                    "title": "Logon Types",
                    "type": "pie",
                    "params": {"addLegend": True, "isDonut": False},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "segment",
                         "params": {"field": "logon_type_desc", "size": 10}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "event_id:4624", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        # Attack Chains
        {
            "type": "visualization",
            "id": "lab16-attack-chains",
            "attributes": {
                "title": "Cadenas de Ataque Detectadas",
                "visState": json.dumps({
                    "title": "Attack Chains",
                    "type": "horizontal_bar",
                    "params": {"addLegend": False},
                    "aggs": [
                        {"id": "1", "type": "count", "schema": "metric"},
                        {"id": "2", "type": "terms", "schema": "segment",
                         "params": {"field": "attack_chain", "size": 15}}
                    ]
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "attack_chain:*", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
    ]
    
    # Saved Searches
    saved_searches = [
        {
            "type": "search",
            "id": "lab16-hunt-golden-ticket",
            "attributes": {
                "title": "HUNT: Golden Ticket (4769 + RC4)",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": 'event_id:4769 AND ticket_encryption:"0x17"', "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "type": "search",
            "id": "lab16-hunt-brute-force",
            "attributes": {
                "title": "HUNT: Brute Force (4625)",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "event_id:4625", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "type": "search",
            "id": "lab16-hunt-lateral",
            "attributes": {
                "title": "HUNT: Lateral Movement (Type 3 + 10)",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "event_id:4624 AND (logon_type:3 OR logon_type:10)", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "type": "search",
            "id": "lab16-hunt-ransomware",
            "attributes": {
                "title": "HUNT: Ransomware Indicators",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": 'command_line:(*vssadmin* OR *bcdedit* OR *wevtutil*)', "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "type": "search",
            "id": "lab16-hunt-simulated",
            "attributes": {
                "title": "HUNT: Eventos Simulados (Live)",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": INDEX_PATTERN,
                        "query": {"query": "simulated:true", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
    ]
    
    all_objects = saved_objects + saved_searches
    
    r = requests.post(
        f"{KIBANA_URL}/api/saved_objects/_bulk_create?overwrite=true",
        headers=HEADERS,
        json=all_objects
    )
    
    if r.status_code == 200:
        print(f"[+] {len(all_objects)} objetos creados (visualizaciones + saved searches)")
        return True
    print(f"[-] Error: {r.text[:300]}")
    return False


def create_dashboard():
    """Crea el dashboard principal."""
    panels = [
        {"panelIndex": "1", "gridData": {"x": 0, "y": 0, "w": 48, "h": 10, "i": "1"},
         "panelRefName": "panel_0", "type": "visualization", "id": "lab16-timeline"},
        {"panelIndex": "2", "gridData": {"x": 0, "y": 10, "w": 16, "h": 12, "i": "2"},
         "panelRefName": "panel_1", "type": "visualization", "id": "lab16-event-ids"},
        {"panelIndex": "3", "gridData": {"x": 16, "y": 10, "w": 16, "h": 12, "i": "3"},
         "panelRefName": "panel_2", "type": "visualization", "id": "lab16-severity"},
        {"panelIndex": "4", "gridData": {"x": 32, "y": 10, "w": 16, "h": 12, "i": "4"},
         "panelRefName": "panel_3", "type": "visualization", "id": "lab16-mitre"},
        {"panelIndex": "5", "gridData": {"x": 0, "y": 22, "w": 24, "h": 12, "i": "5"},
         "panelRefName": "panel_4", "type": "visualization", "id": "lab16-hosts"},
        {"panelIndex": "6", "gridData": {"x": 24, "y": 22, "w": 24, "h": 12, "i": "6"},
         "panelRefName": "panel_5", "type": "visualization", "id": "lab16-logon-types"},
        {"panelIndex": "7", "gridData": {"x": 0, "y": 34, "w": 24, "h": 12, "i": "7"},
         "panelRefName": "panel_6", "type": "visualization", "id": "lab16-attack-chains"},
        {"panelIndex": "8", "gridData": {"x": 24, "y": 34, "w": 24, "h": 12, "i": "8"},
         "panelRefName": "panel_7", "type": "visualization", "id": "lab16-critical-table"},
    ]
    
    dashboard = {
        "type": "dashboard",
        "id": "lab16-dashboard-winevt-hunting",
        "attributes": {
            "title": "Lab 16 - Windows Event IDs Hunting Dashboard",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"darkTheme": True, "useMargins": True}),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        }
    }
    
    r = requests.post(
        f"{KIBANA_URL}/api/saved_objects/_bulk_create?overwrite=true",
        headers=HEADERS,
        json=[dashboard]
    )
    
    if r.status_code == 200:
        print("[+] Dashboard 'Lab 16 - Windows Event IDs Hunting' creado")
        print(f"    URL: {KIBANA_URL}/app/dashboards#/view/lab16-dashboard-winevt-hunting")
        return True
    print(f"[-] Error: {r.text[:200]}")
    return False


if __name__ == "__main__":
    print("\n[*] Configurando Kibana para Lab 16...")
    if wait_for_kibana():
        time.sleep(5)
        create_data_view()
        create_visualizations()
        create_dashboard()
        print("\n[+] Configuración de Kibana completada")
        print(f"    Dashboard: {KIBANA_URL}/app/dashboards#/view/lab16-dashboard-winevt-hunting")
        print(f"    Discover:  {KIBANA_URL}/app/discover")
    else:
        print("[-] No se pudo configurar Kibana")
