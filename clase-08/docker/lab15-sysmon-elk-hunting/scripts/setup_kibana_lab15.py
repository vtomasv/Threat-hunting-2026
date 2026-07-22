#!/usr/bin/env python3
"""
setup_kibana_lab15.py - Configura Data View, Visualizaciones y Dashboard en Kibana
Curso MAR404 - Clase 8 - Lab 15
"""
import json, time, requests

KIBANA_HOST = "http://sysmon-hunt-kibana:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
DATA_VIEW_ID = "sysmon-hunting-dv"


def wait_for_kibana():
    print("[*] Esperando a Kibana...")
    for i in range(90):
        try:
            r = requests.get(f"{KIBANA_HOST}/api/status", timeout=5)
            if r.status_code == 200:
                print("[+] Kibana disponible")
                return True
        except:
            pass
        time.sleep(3)
    raise Exception("Kibana not available")


def create_data_view():
    requests.delete(f"{KIBANA_HOST}/api/data_views/data_view/{DATA_VIEW_ID}", headers=HEADERS)
    time.sleep(1)
    payload = {
        "data_view": {
            "id": DATA_VIEW_ID,
            "title": "sysmon-hunting*",
            "name": "Sysmon Hunting - Lab 15",
            "timeFieldName": "timestamp"
        }
    }
    r = requests.post(f"{KIBANA_HOST}/api/data_views/data_view", json=payload, headers=HEADERS)
    if r.status_code in (200, 201):
        print(f"[+] Data View creado: {DATA_VIEW_ID}")
        requests.post(f"{KIBANA_HOST}/api/data_views/default",
                      json={"defaultDataViewId": DATA_VIEW_ID, "force": True}, headers=HEADERS)
    else:
        print(f"[-] Error: {r.status_code}")


def create_saved_objects():
    """Crea visualizaciones, saved searches y dashboard."""
    saved_objects = [
        # === SAVED SEARCHES (Hunting Queries) ===
        {"type": "search", "id": "hunt-lsass-access", "attributes": {
            "title": "HUNT: LSASS Access (T1003.001)",
            "description": "Procesos accediendo a lsass.exe - posible credential dumping",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:10 AND target_image.keyword:*lsass*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-createremotethread", "attributes": {
            "title": "HUNT: CreateRemoteThread Injection (T1055)",
            "description": "Inyección de código via CreateRemoteThread",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:8", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-powershell-encoded", "attributes": {
            "title": "HUNT: PowerShell Encoded (T1059.001)",
            "description": "PowerShell con comandos codificados en Base64",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "command_line.keyword:*-enc* OR command_line.keyword:*-EncodedCommand*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-registry-persistence", "attributes": {
            "title": "HUNT: Registry Run Key Persistence (T1547.001)",
            "description": "Modificación de claves de registro para persistencia",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:13 AND target_object.keyword:*CurrentVersion*Run*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-lateral-movement", "attributes": {
            "title": "HUNT: Lateral Movement (T1021/T1047)",
            "description": "WMI, PsExec y herramientas de movimiento lateral",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "process_name:(WMIC.exe OR PsExec.exe OR psexec.exe) OR (destination_port:445 OR destination_port:135)", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-dga-dns", "attributes": {
            "title": "HUNT: DGA DNS Queries (T1568.002)",
            "description": "Consultas DNS a dominios generados algorítmicamente",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:22 AND query_name:*evil-corp*", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-c2-beacon", "attributes": {
            "title": "HUNT: C2 Beaconing (T1071)",
            "description": "Conexiones periódicas a IPs externas sospechosas",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "event_id:3 AND destination_ip:198.51.100.10", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-exfiltration", "attributes": {
            "title": "HUNT: Data Exfiltration (T1048)",
            "description": "Uso de bitsadmin, certutil o herramientas para exfiltración",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "process_name:(bitsadmin.exe OR certutil.exe) OR category:exfiltration", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "search", "id": "hunt-antiforensics", "attributes": {
            "title": "HUNT: Anti-Forensics (T1070)",
            "description": "Limpieza de logs y evidencia",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "process_name:wevtutil.exe OR (command_line.keyword:*cl* AND command_line.keyword:*Security*)", "language": "kuery"},
                "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        # === VISUALIZATIONS ===
        {"type": "visualization", "id": "vis-attack-chains", "attributes": {
            "title": "Cadenas de Ataque Detectadas",
            "description": "Distribución de eventos por cadena de ataque",
            "visState": json.dumps({
                "title": "Cadenas de Ataque", "type": "pie",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {"field": "attack_chain", "orderBy": "1", "order": "desc", "size": 10}, "schema": "segment"}
                ],
                "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True}
            }),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID, "query": {"query": "attack_chain:*", "language": "kuery"}, "filter": []
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "visualization", "id": "vis-severity-timeline", "attributes": {
            "title": "Timeline por Severidad",
            "description": "Histograma temporal de eventos por severidad",
            "visState": json.dumps({
                "title": "Timeline por Severidad", "type": "histogram",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "date_histogram", "params": {"field": "timestamp", "interval": "30m", "min_doc_count": 1}, "schema": "segment"},
                    {"id": "3", "enabled": True, "type": "terms", "params": {"field": "severity", "orderBy": "1", "order": "desc", "size": 5}, "schema": "group"}
                ],
                "params": {"type": "histogram", "addTooltip": True, "addLegend": True}
            }),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID, "query": {"query": "", "language": "kuery"}, "filter": []
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},

        {"type": "visualization", "id": "vis-mitre-techniques", "attributes": {
            "title": "MITRE ATT&CK Techniques Detectadas",
            "description": "Top técnicas MITRE observadas",
            "visState": json.dumps({
                "title": "MITRE Techniques", "type": "horizontal_bar",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {"field": "mitre_technique", "orderBy": "1", "order": "desc", "size": 15}, "schema": "segment"}
                ],
                "params": {"type": "horizontal_bar", "addTooltip": True, "addLegend": False}
            }),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID, "query": {"query": "mitre_technique:*", "language": "kuery"}, "filter": []
            })}
        }, "references": [{"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]},
    ]

    r = requests.post(f"{KIBANA_HOST}/api/saved_objects/_bulk_create?overwrite=true",
                      headers=HEADERS, json=saved_objects)
    if r.status_code == 200:
        print(f"[+] {len(saved_objects)} saved objects creados (searches + visualizations)")
    else:
        print(f"[-] Error creando saved objects: {r.status_code}")


def main():
    wait_for_kibana()
    time.sleep(10)  # Extra wait for data to be available
    create_data_view()
    time.sleep(3)
    create_saved_objects()
    print("\n[+] Kibana configurado exitosamente")
    print("[+] Dashboard: http://localhost:5601/app/discover")
    print("[+] Saved Searches disponibles en Kibana > Discover > Open")


if __name__ == "__main__":
    main()
