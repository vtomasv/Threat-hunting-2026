#!/usr/bin/env python3
"""
load_sysmon_data.py
===================
Carga los logs de Sysmon generados en Elasticsearch usando la Bulk API.

Curso MAR404 - Cacería de Amenazas - Clase 1
Universidad Mayor 2026
"""

import json
import os
import time
import requests

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
INDEX_NAME = os.environ.get("INDEX_NAME", "sysmon-2026.01.15")
DATA_FILE = "/data/sysmon_events.json"


def wait_for_elasticsearch():
    """Espera a que Elasticsearch esté disponible."""
    print("[*] Esperando a Elasticsearch...")
    for i in range(60):
        try:
            r = requests.get(f"{ES_HOST}/_cluster/health")
            if r.status_code == 200:
                health = r.json()
                if health["status"] in ("green", "yellow"):
                    print(f"[+] Elasticsearch disponible (status: {health['status']})")
                    return True
        except Exception:
            pass
        time.sleep(2)
    print("[-] Timeout esperando Elasticsearch")
    return False


def create_index_template():
    """Crea el template de índice para logs Sysmon."""
    template = {
        "index_patterns": ["sysmon-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event.code": {"type": "keyword"},
                    "event.category": {"type": "keyword"},
                    "event.type": {"type": "keyword"},
                    "host.name": {"type": "keyword"},
                    "process.name": {"type": "keyword"},
                    "process.executable": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "process.command_line": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "process.pid": {"type": "integer"},
                    "process.hash.sha256": {"type": "keyword"},
                    "process.parent.name": {"type": "keyword"},
                    "process.parent.executable": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "process.parent.pid": {"type": "integer"},
                    "user.name": {"type": "keyword"},
                    "source.ip": {"type": "ip"},
                    "source.port": {"type": "integer"},
                    "destination.ip": {"type": "ip"},
                    "destination.port": {"type": "integer"},
                    "destination.domain": {"type": "keyword"},
                    "network.direction": {"type": "keyword"},
                    "network.protocol": {"type": "keyword"},
                    "file.path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "winlog.event_id": {"type": "integer"},
                    "winlog.provider_name": {"type": "keyword"},
                    "threat.technique.id": {"type": "keyword"},
                    "threat.technique.name": {"type": "keyword"}
                }
            }
        }
    }
    
    r = requests.put(f"{ES_HOST}/_index_template/sysmon-template", json=template)
    if r.status_code in (200, 201):
        print("[+] Index template 'sysmon-template' creado")
    else:
        print(f"[-] Error creando template: {r.text}")


def bulk_load_data():
    """Carga los datos usando la Bulk API."""
    if not os.path.exists(DATA_FILE):
        print(f"[-] Archivo no encontrado: {DATA_FILE}")
        return False
    
    # Preparar bulk request
    bulk_body = ""
    count = 0
    
    with open(DATA_FILE, 'r') as f:
        for line in f:
            event = json.loads(line.strip())
            action = {"index": {"_index": INDEX_NAME}}
            bulk_body += json.dumps(action) + "\n"
            bulk_body += json.dumps(event) + "\n"
            count += 1
    
    # Enviar en lotes de 200
    lines = bulk_body.strip().split("\n")
    batch_size = 400  # 200 documentos * 2 líneas cada uno
    
    total_indexed = 0
    for i in range(0, len(lines), batch_size):
        batch = "\n".join(lines[i:i+batch_size]) + "\n"
        r = requests.post(
            f"{ES_HOST}/_bulk",
            data=batch,
            headers={"Content-Type": "application/x-ndjson"}
        )
        if r.status_code == 200:
            result = r.json()
            if not result.get("errors"):
                total_indexed += len(lines[i:i+batch_size]) // 2
            else:
                # Contar exitosos
                for item in result["items"]:
                    if item["index"]["status"] in (200, 201):
                        total_indexed += 1
        else:
            print(f"[-] Error en bulk request: {r.status_code}")
    
    print(f"[+] {total_indexed} documentos indexados en '{INDEX_NAME}'")
    return True


def main():
    if not wait_for_elasticsearch():
        exit(1)
    
    create_index_template()
    time.sleep(2)
    bulk_load_data()
    
    # Refresh index
    requests.post(f"{ES_HOST}/{INDEX_NAME}/_refresh")
    print("[+] Índice refrescado y listo para consultas")


if __name__ == "__main__":
    main()
