#!/usr/bin/env python3
"""
setup_kibana.py
===============
Configura Kibana con:
1. Data View para los logs de Sysmon
2. Visualizaciones (Lens) para el ejercicio de hunting
3. Dashboard principal con todas las visualizaciones

Usa la API de Saved Objects de Kibana 8.x para crear objetos persistentes.

Curso MAR404 - Cacería de Amenazas - Clase 1
Universidad Mayor 2026
"""

import time
import json
import requests

KIBANA_HOST = "http://kibana:5601"
ES_HOST = "http://elasticsearch:9200"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

# ID fijo para el data view (necesario para referenciar en visualizaciones)
DATA_VIEW_ID = "sysmon-hunt-lab"


def wait_for_kibana():
    """Espera a que Kibana esté completamente disponible."""
    print("[*] Esperando a Kibana...")
    for i in range(120):
        try:
            r = requests.get(f"{KIBANA_HOST}/api/status", timeout=5)
            if r.status_code == 200:
                status = r.json()
                if status.get("status", {}).get("overall", {}).get("level") == "available":
                    print("[+] Kibana disponible")
                    return True
        except Exception:
            pass
        time.sleep(3)
    print("[-] Timeout esperando Kibana")
    return False


def wait_for_data():
    """Espera a que los datos estén indexados en Elasticsearch."""
    print("[*] Verificando datos en Elasticsearch...")
    for i in range(60):
        try:
            r = requests.get(f"{ES_HOST}/sysmon-*/_count", timeout=5)
            if r.status_code == 200:
                count = r.json().get("count", 0)
                if count > 0:
                    print(f"[+] Datos disponibles: {count} documentos")
                    return True
        except Exception:
            pass
        time.sleep(2)
    print("[-] No se encontraron datos")
    return False


def create_data_view():
    """Crea el Data View para sysmon-* con ID fijo."""
    # Primero intentar eliminar si existe
    requests.delete(
        f"{KIBANA_HOST}/api/data_views/data_view/{DATA_VIEW_ID}",
        headers=HEADERS
    )
    time.sleep(1)

    payload = {
        "data_view": {
            "id": DATA_VIEW_ID,
            "title": "sysmon-*",
            "name": "Sysmon Logs - Threat Hunt Lab",
            "timeFieldName": "@timestamp"
        }
    }

    r = requests.post(
        f"{KIBANA_HOST}/api/data_views/data_view",
        json=payload,
        headers=HEADERS
    )

    if r.status_code in (200, 201):
        print(f"[+] Data View creado: {DATA_VIEW_ID}")

        # Establecer como default
        requests.post(
            f"{KIBANA_HOST}/api/data_views/default",
            json={"defaultDataViewId": DATA_VIEW_ID, "force": True},
            headers=HEADERS
        )
        print("[+] Data View establecido como default")
        return True
    else:
        print(f"[-] Error creando Data View: {r.status_code} - {r.text}")
        return False


def create_visualizations():
    """Crea visualizaciones usando la API de Saved Objects."""

    # Definición de visualizaciones como saved objects tipo 'lens'
    visualizations = [
        {
            "id": "vis-process-events",
            "type": "visualization",
            "attributes": {
                "title": "Eventos por Proceso (Top 15)",
                "description": "Distribución de eventos Sysmon por nombre de proceso",
                "visState": json.dumps({
                    "title": "Eventos por Proceso (Top 15)",
                    "type": "pie",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {"field": "process.name", "orderBy": "1", "order": "desc", "size": 15}, "schema": "segment"}
                    ],
                    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "id": "vis-event-timeline",
            "type": "visualization",
            "attributes": {
                "title": "Timeline de Eventos Sysmon",
                "description": "Histograma temporal de eventos Sysmon por categoría",
                "visState": json.dumps({
                    "title": "Timeline de Eventos Sysmon",
                    "type": "histogram",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "date_histogram", "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1}, "schema": "segment"},
                        {"id": "3", "enabled": True, "type": "terms", "params": {"field": "event.category", "orderBy": "1", "order": "desc", "size": 5}, "schema": "group"}
                    ],
                    "params": {"type": "histogram", "addTooltip": True, "addLegend": True, "legendPosition": "right"}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "id": "vis-network-connections",
            "type": "visualization",
            "attributes": {
                "title": "Conexiones de Red (Destinos)",
                "description": "Top destinos de conexiones de red",
                "visState": json.dumps({
                    "title": "Conexiones de Red (Destinos)",
                    "type": "table",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {"field": "destination.ip", "orderBy": "1", "order": "desc", "size": 20}, "schema": "bucket"},
                        {"id": "3", "enabled": True, "type": "terms", "params": {"field": "destination.port", "orderBy": "1", "order": "desc", "size": 5}, "schema": "bucket"}
                    ],
                    "params": {"perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "event.code: \"3\"", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "id": "vis-suspicious-processes",
            "type": "visualization",
            "attributes": {
                "title": "Procesos Sospechosos (Hunting Targets)",
                "description": "Procesos que típicamente son usados en ataques LOTL",
                "visState": json.dumps({
                    "title": "Procesos Sospechosos (Hunting Targets)",
                    "type": "table",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {"field": "process.name", "orderBy": "1", "order": "desc", "size": 20}, "schema": "bucket"},
                        {"id": "3", "enabled": True, "type": "terms", "params": {"field": "user.name", "orderBy": "1", "order": "desc", "size": 5}, "schema": "bucket"}
                    ],
                    "params": {"perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "process.name: (certutil.exe OR powershell.exe OR schtasks.exe OR cmd.exe OR mshta.exe OR regsvr32.exe OR wmic.exe OR cscript.exe OR wscript.exe)", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "id": "vis-event-categories",
            "type": "visualization",
            "attributes": {
                "title": "Categorías de Eventos",
                "description": "Distribución por categoría de evento (process, network, file)",
                "visState": json.dumps({
                    "title": "Categorías de Eventos",
                    "type": "pie",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {"field": "event.category", "orderBy": "1", "order": "desc", "size": 10}, "schema": "segment"}
                    ],
                    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": False}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "id": "vis-user-activity",
            "type": "visualization",
            "attributes": {
                "title": "Actividad por Usuario",
                "description": "Eventos por usuario del sistema",
                "visState": json.dumps({
                    "title": "Actividad por Usuario",
                    "type": "horizontal_bar",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {"field": "user.name", "orderBy": "1", "order": "desc", "size": 10}, "schema": "segment"}
                    ],
                    "params": {"type": "horizontal_bar", "addTooltip": True, "addLegend": True, "legendPosition": "right"}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "id": "vis-command-lines",
            "type": "visualization",
            "attributes": {
                "title": "Líneas de Comando Ejecutadas",
                "description": "Tabla de command lines para análisis de hunting",
                "visState": json.dumps({
                    "title": "Líneas de Comando Ejecutadas",
                    "type": "table",
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {"field": "process.command_line", "orderBy": "1", "order": "desc", "size": 30}, "schema": "bucket"}
                    ],
                    "params": {"perPage": 20, "showPartialRows": False, "showMetricsAtAllLevels": False}
                }),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "event.code: \"1\"", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
    ]

    # Importar visualizaciones usando la API de Saved Objects
    saved_objects = []
    for vis in visualizations:
        saved_objects.append({
            "type": vis["type"],
            "id": vis["id"],
            "attributes": vis["attributes"],
            "references": vis["references"]
        })

    payload = {
        "objects": saved_objects,
        "overwrite": True
    }

    r = requests.post(
        f"{KIBANA_HOST}/api/saved_objects/_bulk_create?overwrite=true",
        json=saved_objects,
        headers=HEADERS
    )

    if r.status_code in (200, 201):
        results = r.json()
        success_count = 0
        for obj in results.get("saved_objects", results if isinstance(results, list) else []):
            if isinstance(obj, dict) and not obj.get("error"):
                success_count += 1
            elif isinstance(obj, dict) and obj.get("error"):
                print(f"  [-] Error en {obj.get('id', '?')}: {obj['error'].get('message', 'unknown')}")
        print(f"[+] Visualizaciones creadas: {success_count}/{len(visualizations)}")
        return True
    else:
        print(f"[-] Error creando visualizaciones: {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        return False


def create_dashboard():
    """Crea el dashboard principal con todas las visualizaciones."""

    # Panel references para el dashboard
    panels = [
        {"panelIndex": "1", "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"}, "type": "visualization", "id": "vis-event-timeline"},
        {"panelIndex": "2", "gridData": {"x": 24, "y": 0, "w": 12, "h": 15, "i": "2"}, "type": "visualization", "id": "vis-event-categories"},
        {"panelIndex": "3", "gridData": {"x": 36, "y": 0, "w": 12, "h": 15, "i": "3"}, "type": "visualization", "id": "vis-user-activity"},
        {"panelIndex": "4", "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "4"}, "type": "visualization", "id": "vis-process-events"},
        {"panelIndex": "5", "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "5"}, "type": "visualization", "id": "vis-network-connections"},
        {"panelIndex": "6", "gridData": {"x": 0, "y": 30, "w": 48, "h": 15, "i": "6"}, "type": "visualization", "id": "vis-suspicious-processes"},
        {"panelIndex": "7", "gridData": {"x": 0, "y": 45, "w": 48, "h": 15, "i": "7"}, "type": "visualization", "id": "vis-command-lines"},
    ]

    # Construir references del dashboard
    references = []
    for panel in panels:
        references.append({
            "id": panel["id"],
            "name": panel["panelIndex"] + ":panel_" + panel["panelIndex"],
            "type": "visualization"
        })

    dashboard_obj = {
        "type": "dashboard",
        "id": "dashboard-threat-hunt-lab",
        "attributes": {
            "title": "MAR404 - Threat Hunt Lab - Dashboard Principal",
            "description": "Dashboard de cacería de amenazas para el Lab 1 del curso MAR404. Contiene visualizaciones para identificar actividad sospechosa en logs Sysmon.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True, "syncTooltips": False, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeTo": "2026-01-15T17:00:00.000Z",
            "timeFrom": "2026-01-15T07:00:00.000Z",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": references
    }

    r = requests.post(
        f"{KIBANA_HOST}/api/saved_objects/_bulk_create?overwrite=true",
        json=[dashboard_obj],
        headers=HEADERS
    )

    if r.status_code in (200, 201):
        results = r.json()
        for obj in results if isinstance(results, list) else results.get("saved_objects", []):
            if isinstance(obj, dict) and not obj.get("error"):
                print(f"[+] Dashboard creado: dashboard-threat-hunt-lab")
                return True
            elif isinstance(obj, dict) and obj.get("error"):
                print(f"[-] Error en dashboard: {obj['error'].get('message', 'unknown')}")
                return False
    else:
        print(f"[-] Error creando dashboard: {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        return False


def create_saved_searches():
    """Crea búsquedas guardadas para los ejercicios de hunting."""

    searches = [
        {
            "type": "search",
            "id": "search-certutil-download",
            "attributes": {
                "title": "HUNT: certutil.exe Download (T1105)",
                "description": "Busca uso de certutil.exe con -urlcache para descargar archivos",
                "columns": ["@timestamp", "process.name", "process.command_line", "user.name"],
                "sort": [["@timestamp", "desc"]],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "process.name: certutil.exe AND process.command_line: *urlcache*", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "type": "search",
            "id": "search-powershell-encoded",
            "attributes": {
                "title": "HUNT: PowerShell Encoded Command (T1059.001)",
                "description": "Busca PowerShell con parámetro -Enc (encoded command)",
                "columns": ["@timestamp", "process.name", "process.command_line", "process.parent.name", "user.name"],
                "sort": [["@timestamp", "desc"]],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "process.name: powershell.exe AND process.command_line: *Enc*", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "type": "search",
            "id": "search-schtasks-creation",
            "attributes": {
                "title": "HUNT: Scheduled Task Creation (T1053.005)",
                "description": "Busca schtasks.exe creando tareas programadas",
                "columns": ["@timestamp", "process.name", "process.command_line", "process.parent.name", "user.name"],
                "sort": [["@timestamp", "desc"]],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "process.name: schtasks.exe AND process.command_line: *create*", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "type": "search",
            "id": "search-suspicious-parent-child",
            "attributes": {
                "title": "HUNT: Parent-Child Sospechoso",
                "description": "Busca procesos con relaciones padre-hijo inusuales",
                "columns": ["@timestamp", "process.name", "process.command_line", "process.parent.name", "process.parent.executable", "user.name"],
                "sort": [["@timestamp", "desc"]],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "process.parent.name: (cmd.exe OR powershell.exe) AND process.name: (certutil.exe OR schtasks.exe OR mshta.exe OR regsvr32.exe)", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
        {
            "type": "search",
            "id": "search-external-connections",
            "attributes": {
                "title": "HUNT: Conexiones a IPs Externas",
                "description": "Busca conexiones de red a IPs fuera de la red interna",
                "columns": ["@timestamp", "process.name", "destination.ip", "destination.port", "destination.domain", "user.name"],
                "sort": [["@timestamp", "desc"]],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": DATA_VIEW_ID,
                        "query": {"query": "event.code: \"3\" AND NOT destination.ip: (192.168.* OR 10.* OR 172.16.*)", "language": "kuery"},
                        "filter": []
                    })
                }
            },
            "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
        },
    ]

    r = requests.post(
        f"{KIBANA_HOST}/api/saved_objects/_bulk_create?overwrite=true",
        json=searches,
        headers=HEADERS
    )

    if r.status_code in (200, 201):
        results = r.json()
        success_count = 0
        for obj in results if isinstance(results, list) else results.get("saved_objects", []):
            if isinstance(obj, dict) and not obj.get("error"):
                success_count += 1
        print(f"[+] Saved Searches creadas: {success_count}/{len(searches)}")
        return True
    else:
        print(f"[-] Error creando saved searches: {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        return False


def main():
    if not wait_for_kibana():
        exit(1)

    # Esperar a que los datos estén disponibles
    if not wait_for_data():
        print("[!] Continuando sin datos confirmados...")

    time.sleep(10)  # Espera adicional para estabilidad de Kibana

    # Paso 1: Crear Data View
    print("\n[*] Paso 1: Creando Data View...")
    if not create_data_view():
        print("[-] FATAL: No se pudo crear el Data View")
        exit(1)

    time.sleep(3)

    # Paso 2: Crear Visualizaciones
    print("\n[*] Paso 2: Creando Visualizaciones...")
    create_visualizations()

    time.sleep(3)

    # Paso 3: Crear Saved Searches
    print("\n[*] Paso 3: Creando Saved Searches (queries de hunting)...")
    create_saved_searches()

    time.sleep(3)

    # Paso 4: Crear Dashboard
    print("\n[*] Paso 4: Creando Dashboard Principal...")
    create_dashboard()

    # Resumen final
    print("\n" + "=" * 70)
    print("  LABORATORIO LISTO PARA USAR")
    print("=" * 70)
    print(f"  Kibana:          http://localhost:5601")
    print(f"  Elasticsearch:   http://localhost:9200")
    print(f"  Índice:          sysmon-2026.01.15")
    print(f"  Data View:       sysmon-* (ID: {DATA_VIEW_ID})")
    print(f"  Dashboard:       MAR404 - Threat Hunt Lab - Dashboard Principal")
    print("=" * 70)
    print("\n  VISUALIZACIONES CREADAS:")
    print("  - Timeline de Eventos Sysmon (histograma temporal)")
    print("  - Categorías de Eventos (pie chart)")
    print("  - Actividad por Usuario (barras horizontales)")
    print("  - Eventos por Proceso - Top 15 (donut chart)")
    print("  - Conexiones de Red - Destinos (tabla)")
    print("  - Procesos Sospechosos - Hunting Targets (tabla)")
    print("  - Líneas de Comando Ejecutadas (tabla)")
    print("=" * 70)
    print("\n  SAVED SEARCHES (Queries de Hunting):")
    print("  - HUNT: certutil.exe Download (T1105)")
    print("  - HUNT: PowerShell Encoded Command (T1059.001)")
    print("  - HUNT: Scheduled Task Creation (T1053.005)")
    print("  - HUNT: Parent-Child Sospechoso")
    print("  - HUNT: Conexiones a IPs Externas")
    print("=" * 70)
    print("\n  ACCESO AL DASHBOARD:")
    print("  http://localhost:5601/app/dashboards#/view/dashboard-threat-hunt-lab")
    print("=" * 70)
    print("\n  EJERCICIOS DE HUNTING:")
    print("  1. Abrir Dashboard Principal y revisar la timeline")
    print("  2. Usar Saved Search 'certutil.exe Download' (T1105)")
    print("  3. Usar Saved Search 'PowerShell Encoded' (T1059.001)")
    print("  4. Usar Saved Search 'Scheduled Task' (T1053.005)")
    print("  5. Correlacionar los 3 eventos para reconstruir la cadena")
    print("=" * 70)


if __name__ == "__main__":
    main()
