#!/usr/bin/env python3
"""
hunt_queries.py - Queries de hunting pre-construidas para Lab 16
Ejecuta queries contra Elasticsearch y muestra resultados formateados.
Curso MAR404 - Clase 8 - Lab 16

Uso:
    hunt list              # Listar queries disponibles
    hunt <query_name>      # Ejecutar una query específica
    hunt all               # Ejecutar todas las queries
"""
import sys, json
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200"
INDEX = "windows-security"

QUERIES = {
    "brute_force": {
        "name": "Detectar Brute Force (>10 fallos en 5 min desde misma IP)",
        "kql": 'event_id:4625 AND source_ip:*',
        "description": "Agrupa Event ID 4625 por IP origen y cuenta intentos fallidos",
        "query": {
            "bool": {"must": [{"term": {"event_id": 4625}}]}
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source_ip", "size": 10},
                "aggs": {"targets": {"terms": {"field": "target_user", "size": 5}}}
            }
        }
    },
    "pth_detection": {
        "name": "Detectar Pass-the-Hash (Logon Type 9 + seclogo)",
        "kql": 'event_id:4624 AND logon_type:9 AND logon_process:seclogo',
        "description": "Logon Type 9 (NewCredentials) con proceso seclogo indica PtH",
        "query": {
            "bool": {"must": [
                {"term": {"event_id": 4624}},
                {"term": {"logon_type": 9}},
                {"term": {"logon_process": "seclogo"}}
            ]}
        }
    },
    "suspicious_services": {
        "name": "Servicios instalados desde rutas sospechosas",
        "kql": 'event_id:7045 AND (service_file:*Temp* OR service_file:*AppData* OR service_file:*Users*)',
        "description": "Servicios con binarios en Temp, AppData o directorios de usuario",
        "query": {
            "bool": {"must": [{"term": {"event_id": 7045}}],
                     "should": [
                         {"wildcard": {"service_file.keyword": "*Temp*"}},
                         {"wildcard": {"service_file.keyword": "*AppData*"}},
                         {"wildcard": {"service_file.keyword": "*Users*"}}
                     ], "minimum_should_match": 1}
        }
    },
    "log_cleared": {
        "name": "Detectar limpieza de logs (Anti-Forensics)",
        "kql": 'event_id:1102',
        "description": "Event ID 1102 indica que el log de seguridad fue limpiado",
        "query": {"term": {"event_id": 1102}}
    },
    "hidden_accounts": {
        "name": "Cuentas ocultas (terminan en $)",
        "kql": 'event_id:4720 AND target_user:*$',
        "description": "Cuentas con $ al final no aparecen en 'net user'",
        "query": {
            "bool": {"must": [
                {"term": {"event_id": 4720}},
                {"wildcard": {"target_user": "*$"}}
            ]}
        }
    },
    "kerberoasting": {
        "name": "Detectar Kerberoasting (múltiples TGS con RC4)",
        "kql": 'event_id:4769 AND ticket_encryption:"0x17"',
        "description": "Múltiples solicitudes TGS con cifrado RC4 desde misma IP",
        "query": {
            "bool": {"must": [
                {"term": {"event_id": 4769}},
                {"term": {"ticket_encryption": "0x17"}}
            ]}
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source_ip", "size": 10},
                "aggs": {"spn_count": {"cardinality": {"field": "service_name_spn"}}}
            }
        }
    },
    "rdp_lateral": {
        "name": "Movimiento lateral RDP (Logon Type 10 desde workstation)",
        "kql": 'event_id:4624 AND logon_type:10',
        "description": "Logon Type 10 (RemoteInteractive) a múltiples hosts",
        "query": {
            "bool": {"must": [
                {"term": {"event_id": 4624}},
                {"term": {"logon_type": 10}}
            ]}
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "target_user", "size": 10},
                "aggs": {"hosts": {"terms": {"field": "hostname", "size": 10}}}
            }
        }
    },
    "encoded_powershell": {
        "name": "PowerShell con -enc (encoded commands)",
        "kql": 'event_id:4688 AND command_line:*-enc*',
        "description": "Procesos PowerShell con comandos codificados en Base64",
        "query": {
            "bool": {"must": [
                {"term": {"event_id": 4688}},
                {"match_phrase": {"command_line": "-enc"}}
            ]}
        }
    },
    "admin_share_access": {
        "name": "Acceso a admin shares (C$, ADMIN$)",
        "kql": 'event_id:5145 AND (share_name:*C$* OR share_name:*ADMIN$*)',
        "description": "Acceso a shares administrativos - posible exfiltración",
        "query": {
            "bool": {"must": [{"term": {"event_id": 5145}}],
                     "should": [
                         {"wildcard": {"share_name": "*C$*"}},
                         {"wildcard": {"share_name": "*ADMIN$*"}}
                     ], "minimum_should_match": 1}
        }
    },
    "process_from_temp": {
        "name": "Procesos ejecutados desde Temp o Downloads",
        "kql": 'event_id:4688 AND (new_process_name:*Temp* OR new_process_name:*Downloads*)',
        "description": "Binarios ejecutados desde directorios temporales - sospechoso",
        "query": {
            "bool": {"must": [{"term": {"event_id": 4688}}],
                     "should": [
                         {"wildcard": {"new_process_name.keyword": "*Temp*"}},
                         {"wildcard": {"new_process_name.keyword": "*Downloads*"}}
                     ], "minimum_should_match": 1}
        }
    },
    "privilege_escalation": {
        "name": "Escalamiento de privilegios (4672 + usuario no-SYSTEM)",
        "kql": 'event_id:4672 AND NOT target_user:"NT AUTHORITY\\\\SYSTEM"',
        "description": "Privilegios especiales asignados a cuentas no-SYSTEM",
        "query": {
            "bool": {
                "must": [{"term": {"event_id": 4672}}],
                "must_not": [{"term": {"target_user": "NT AUTHORITY\\SYSTEM"}}]
            }
        }
    },
    "dcsync": {
        "name": "DCSync (DS-Replication-Get-Changes)",
        "kql": 'event_id:4662 AND properties:*1131f6a*',
        "description": "Replicación de AD desde máquina no-DC = DCSync",
        "query": {
            "bool": {"must": [
                {"term": {"event_id": 4662}},
                {"wildcard": {"properties": "*1131f6a*"}}
            ]}
        }
    },
}


def get_es():
    return Elasticsearch(ES_HOST)


def run_query(es, name, info):
    """Ejecuta una query y muestra resultados."""
    print(f"\n{'─'*70}")
    print(f"  HUNT: {info['name']}")
    print(f"  KQL:  {info['kql']}")
    print(f"  Desc: {info['description']}")
    print(f"{'─'*70}")
    
    body = {"query": info["query"], "size": 20, "sort": [{"timestamp": "desc"}]}
    if "aggs" in info:
        body["aggs"] = info["aggs"]
    
    search_kwargs = {
        "index": INDEX,
        "query": body["query"],
        "size": body.get("size", 20),
        "sort": body.get("sort")
    }
    if "aggs" in body:
        search_kwargs["aggs"] = body["aggs"]
    result = es.search(**search_kwargs)
    hits = result["hits"]["total"]["value"]
    
    print(f"\n  Resultados: {hits} eventos encontrados")
    
    if hits > 0:
        print(f"\n  {'Timestamp':<22} {'Event':<6} {'User':<20} {'Detail'}")
        print(f"  {'─'*22} {'─'*6} {'─'*20} {'─'*30}")
        for hit in result["hits"]["hits"][:10]:
            src = hit["_source"]
            ts = src.get("timestamp", "N/A")[:19]
            eid = str(src.get("event_id", ""))
            user = src.get("target_user", src.get("subject_user", "N/A"))[:20]
            detail = src.get("hunt_note", src.get("command_line", src.get("service_name", "")))[:50]
            print(f"  {ts:<22} {eid:<6} {user:<20} {detail}")
    
    if "aggs" in info and "aggregations" in result:
        print(f"\n  Agregaciones:")
        for agg_name, agg_data in result["aggregations"].items():
            for bucket in agg_data.get("buckets", [])[:5]:
                print(f"    {bucket['key']}: {bucket['doc_count']} eventos")
    
    return hits


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    es = get_es()

    if command == "list":
        print("\n" + "="*70)
        print("  QUERIES DE HUNTING DISPONIBLES")
        print("="*70)
        for key, info in QUERIES.items():
            print(f"\n  {key}")
            print(f"    {info['name']}")
            print(f"    KQL: {info['kql']}")
        print(f"\n{'='*70}")
        print(f"  Uso: hunt <query_name>  |  hunt all")
        print(f"{'='*70}\n")

    elif command == "all":
        print("\n[*] Ejecutando TODAS las queries de hunting...\n")
        total_findings = 0
        for name, info in QUERIES.items():
            count = run_query(es, name, info)
            total_findings += count
        print(f"\n{'='*70}")
        print(f"  RESUMEN: {total_findings} hallazgos totales en {len(QUERIES)} queries")
        print(f"{'='*70}\n")

    elif command in QUERIES:
        run_query(es, command, QUERIES[command])
    else:
        print(f"[-] Query '{command}' no reconocida. Use 'hunt list'.")


if __name__ == "__main__":
    main()
