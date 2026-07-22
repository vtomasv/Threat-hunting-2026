# Lab 16: Correlación Avanzada de Windows Event IDs + Simulador en Vivo

## Escenario

Eres el Threat Hunter principal de **Meridian Financial Group**, una institución financiera que ha sido víctima de un ataque sofisticado. El equipo de respuesta a incidentes ha extraído los logs de seguridad de Windows de 5 servidores y estaciones de trabajo comprometidas. Los eventos han sido ingestados en Elasticsearch y están disponibles para análisis en Kibana.

El dataset contiene **más de 1,000 eventos de seguridad Windows** que documentan una cadena de ataque completa: desde el acceso inicial con credenciales robadas, pasando por escalamiento de privilegios, movimiento lateral, credential dumping, hasta la exfiltración de datos financieros.

Además, dispones de un **simulador de ataques en vivo** y un **asistente de queries de hunting** que te ayudarán a practicar la detección y correlación de eventos.

---

## Objetivos de Aprendizaje

1. Dominar los Windows Security Event IDs críticos para hunting (4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 5145)
2. Correlacionar eventos de múltiples hosts para reconstruir movimiento lateral
3. Detectar escalamiento de privilegios mediante análisis de logon types y privilegios especiales
4. Identificar credential dumping, golden ticket y pass-the-hash mediante patrones de eventos
5. Usar el simulador para generar escenarios de ataque y detectarlos en Kibana
6. Crear reglas de detección basadas en correlación de Event IDs

---

## Requisitos Previos

- Docker y Docker Compose instalados
- Mínimo 4 GB de RAM disponible
- Puertos 9200 y 5601 libres
- Conocimientos básicos de Windows Security Events

---

## Arquitectura del Laboratorio

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Network (elk-net)                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │Elasticsearch │  │    Kibana    │  │    Simulator       │    │
│  │  :9200       │  │    :5601     │  │  (interactivo)     │    │
│  │              │◄─┤              │  │                    │    │
│  │  1000+ events│  │  Dashboard   │  │  simulate <ataque> │    │
│  │  Windows Sec │  │  + Alerts    │  │  hunt <query>      │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│         ▲                                     │                  │
│         │         ┌──────────────┐            │                  │
│         └─────────┤    Loader    ├────────────┘                  │
│                   │ (dataset +   │                               │
│                   │  Kibana cfg) │                               │
│                   └──────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Campos Importantes del Índice

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `event_id` | integer | Windows Security Event ID |
| `target_user` | keyword | Cuenta objetivo del evento |
| `subject_user` | keyword | Cuenta que realizó la acción |
| `logon_type` | integer | Tipo de logon (2,3,5,7,9,10) |
| `logon_type_desc` | keyword | Descripción del tipo de logon |
| `source_ip` | ip | IP de origen del logon |
| `source_workstation` | keyword | Nombre del host de origen |
| `hostname` | keyword | Host donde ocurrió el evento |
| `new_process_name` | text | Ruta del nuevo proceso (4688) |
| `command_line` | text | Línea de comandos (4688) |
| `creator_process_name` | text | Proceso padre (4688) |
| `authentication_package` | keyword | Paquete de autenticación |
| `ticket_encryption` | keyword | Tipo de cifrado Kerberos |
| `service_name` | keyword | Nombre del servicio (4697) |
| `share_name` | keyword | Nombre del share (5145) |
| `relative_target` | text | Archivo accedido en share (5145) |
| `group_name` | keyword | Grupo modificado (4732) |
| `task_name` | text | Nombre de la tarea (4698) |
| `severity` | keyword | info, high, critical |
| `attack_chain` | keyword | Cadena de ataque asociada |
| `mitre_technique` | keyword | Técnica MITRE ATT&CK |

---

## Referencia Rápida: Windows Security Event IDs

| Event ID | Descripción | Relevancia |
|----------|-------------|------------|
| 4624 | Logon exitoso | Tipo de logon, origen, cuenta |
| 4625 | Logon fallido | Brute force, password spray |
| 4648 | Logon con credenciales explícitas | RunAs, lateral movement |
| 4672 | Privilegios especiales asignados | Admin logon detection |
| 4688 | Nuevo proceso creado | Ejecución de comandos |
| 4697 | Servicio instalado | Persistencia, PsExec |
| 4698 | Scheduled Task creada | Persistencia |
| 4720 | Cuenta de usuario creada | Backdoor accounts |
| 4732 | Miembro añadido a grupo local | Privilege escalation |
| 4768 | Kerberos TGT solicitado | Pass-the-ticket |
| 4769 | Kerberos service ticket | Kerberoasting |
| 4776 | NTLM authentication | Pass-the-hash |
| 5145 | Network share accessed | Lateral movement, exfil |

### Logon Types Críticos

| Tipo | Nombre | Significado para Hunting |
|------|--------|--------------------------|
| 2 | Interactive | Logon local (teclado) |
| 3 | Network | Acceso remoto (SMB, net use) |
| 4 | Batch | Scheduled task |
| 5 | Service | Inicio de servicio |
| 7 | Unlock | Desbloqueo de pantalla |
| 9 | NewCredentials | RunAs /netonly, Pass-the-Hash |
| 10 | RemoteInteractive | RDP |

---

## Despliegue

### Paso 1: Preparar el host

```bash
sudo sysctl -w vm.max_map_count=262144
```

### Paso 2: Levantar el entorno

```bash
cd clase-08/docker/lab16-windows-eventids
docker compose up -d
```

### Paso 3: Verificar servicios (~90 segundos)

```bash
# Verificar Elasticsearch
curl -s http://localhost:9200/_cluster/health | jq .status

# Verificar datos cargados
curl -s http://localhost:9200/windows-security/_count | jq .count
# Esperado: >1000

# Verificar Kibana
curl -s http://localhost:5601/api/status | jq .status.overall.level
```

### Paso 4: Acceder a Kibana

Abrir: **http://localhost:5601**

Ir a **Analytics → Discover** y seleccionar el data view **"Windows Security Events"**

### Paso 5: Conectarse al simulador

```bash
docker exec -it winevt-simulator bash
```

Comandos disponibles:
- `simulate list` — Ver escenarios de ataque
- `simulate <nombre>` — Ejecutar un escenario
- `simulate all` — Ejecutar todos
- `simulate reset` — Limpiar eventos simulados
- `hunt list` — Ver queries de hunting pre-construidas
- `hunt <nombre>` — Ejecutar query de hunting

---

## Ejercicios Guiados

### Ejercicio 1: Reconocimiento del Dataset en Kibana

**Paso 1**: En Kibana → Analytics → Discover → data view `Windows Security Events`

**Paso 2**: Ejecutar queries KQL:

```kql
# 1.1 Ver distribución de Event IDs
# Agregar campo "event_id" en la sidebar y ver breakdown

# 1.2 Filtrar logons exitosos
event_id: 4624

# 1.3 Ver todos los hosts
# Agregar campo "hostname" y ver distribución

# 1.4 Buscar eventos de alta severidad
severity: "critical"

# 1.5 Ver cadenas de ataque
attack_chain: * and not attack_chain: "baseline"
```

**Preguntas**:
- ¿Cuántos Event IDs diferentes hay?
- ¿Cuáles son los 3 hosts con más actividad?
- ¿Cuántas cadenas de ataque hay en el dataset?

---

### Ejercicio 2: Detección de Brute Force y Password Spray

**Hipótesis**: El atacante intentó múltiples credenciales antes de lograr acceso.

**En Kibana**:

```kql
# 2.1 Buscar logons fallidos
event_id: 4625

# 2.2 Filtrar por origen (IP del atacante)
event_id: 4625 and source_ip: "10.0.1.200"

# 2.3 Password spray: múltiples cuentas desde misma IP
event_id: 4625 and source_workstation: "KALI-BOX"

# 2.4 Brute force: múltiples intentos contra misma cuenta
event_id: 4625 and target_user: "CORP\\admin"

# 2.5 Logon exitoso después de múltiples fallos (el atacante logró entrar)
event_id: 4624 and source_ip: "10.0.1.200"

# 2.6 Correlación temporal: fallos seguidos de éxito
(event_id: 4625 or event_id: 4624) and source_ip: "10.0.1.200"

# 2.7 Ver toda la cadena de brute force
attack_chain: "brute_force_chain"
```

**Tarea**: Crear una visualización en Kibana tipo "Bar" con:
- X: `timestamp` (intervalo 1 minuto)
- Y: Count
- Split: `event_id` (4624 vs 4625)
- Filter: `source_ip: "10.0.1.200"`

Esto mostrará visualmente el patrón de brute force seguido del logon exitoso.

---

### Ejercicio 3: Análisis de Logon Types para Detectar Lateral Movement

**Hipótesis**: El adversario usa credenciales robadas para moverse lateralmente.

```kql
# 3.1 Logons tipo 3 (Network) - indicador de acceso remoto
event_id: 4624 and logon_type: 3

# 3.2 Logons tipo 10 (RDP) - acceso remoto interactivo
event_id: 4624 and logon_type: 10

# 3.3 Logons con credenciales explícitas (RunAs)
event_id: 4648

# 3.4 Logons desde hosts internos (lateral movement)
event_id: 4624 and logon_type: 3 and source_ip: "10.0.1.*"

# 3.5 Cuenta admin usada en múltiples hosts
event_id: 4624 and target_user: "CORP\\admin" and logon_type: (3 or 10)

# 3.6 RDP lateral movement chain
attack_chain: "rdp_lateral_chain"
```

**Tarea**: Crear tabla con columnas: `timestamp`, `hostname`, `target_user`, `source_ip`, `logon_type`
- Ordenar por timestamp
- Identificar el patrón de movimiento: Host A → Host B → Host C

---

### Ejercicio 4: Detección de Escalamiento de Privilegios

**Hipótesis**: El adversario escala privilegios creando cuentas o modificando grupos.

```kql
# 4.1 Privilegios especiales asignados (admin logon)
event_id: 4672

# 4.2 Cuentas de usuario creadas (backdoor)
event_id: 4720

# 4.3 Miembros añadidos a grupos privilegiados
event_id: 4732

# 4.4 Correlación: cuenta creada + añadida a Administrators
(event_id: 4720 or event_id: 4732) and target_user: *svc_update*

# 4.5 Servicios instalados (puede ser PsExec o persistencia)
event_id: 4697

# 4.6 Scheduled Tasks creadas
event_id: 4698 and not attack_chain: "baseline"

# 4.7 Cadena completa de cuenta oculta
attack_chain: "hidden_account_chain"
```

**Preguntas**:
- ¿Qué cuenta backdoor se creó? (Pista: tiene sufijo `$`)
- ¿A qué grupo fue añadida?
- ¿Qué usuario realizó la acción?

---

### Ejercicio 5: Detección de Credential Dumping

**Hipótesis**: El adversario extrae credenciales de la memoria o del dominio.

```kql
# 5.1 Procesos sospechosos ejecutados (Event ID 4688)
event_id: 4688 and (command_line: *mimikatz* or command_line: *procdump* or command_line: *sekurlsa*)

# 5.2 Acceso a SAM/NTDS
event_id: 4688 and (command_line: *ntdsutil* or command_line: *secretsdump* or command_line: *reg save*)

# 5.3 Kerberos TGT requests anómalos (pass-the-ticket)
event_id: 4768

# 5.4 Kerberoasting (service ticket requests masivos con RC4)
event_id: 4769 and ticket_encryption: "0x17"

# 5.5 NTLM authentication (pass-the-hash)
event_id: 4776

# 5.6 DCSync (replicación de directorio)
event_id: 4662 and properties: *1131f6aa*

# 5.7 PowerShell Mimikatz en memoria
event_id: 4688 and command_line: *Invoke-Mimikatz*

# 5.8 Cadena de Kerberoasting
attack_chain: "kerberoasting_chain"
```

---

### Ejercicio 6: Detección de Exfiltración via Network Shares

**Hipótesis**: El adversario accede a shares administrativos para robar datos.

```kql
# 6.1 Acceso a network shares
event_id: 5145

# 6.2 Acceso a shares administrativos (C$, ADMIN$)
event_id: 5145 and share_name: *C$*

# 6.3 Acceso a directorios sensibles
event_id: 5145 and relative_target: (*confidential* or *financial* or *passwords*)

# 6.4 Acceso masivo (múltiples archivos en poco tiempo)
event_id: 5145 and source_ip: "10.0.1.15"

# 6.5 Correlación: logon + share access desde misma IP
(event_id: 4624 or event_id: 5145) and source_ip: "10.0.1.15"

# 6.6 Cadena de exfiltración completa
attack_chain: "exfiltration_chain"
```

**Tarea**: Crear visualización tipo "Timeline" mostrando los accesos a shares por minuto.

---

### Ejercicio 7: Simulación en Vivo — Golden Ticket Attack

**Paso 1**: Conectarse al simulador
```bash
docker exec -it winevt-simulator bash
```

**Paso 2**: Ejecutar escenario
```bash
simulate golden_ticket
```

**Paso 3**: En Kibana, detectar el ataque:
```kql
# Buscar TGT request anómalo
event_id: 4768 and simulated: true

# Buscar logon con ticket forjado
event_id: 4624 and logon_type: 3 and simulated: true

# Buscar acceso con privilegios de Domain Admin
event_id: 4672 and simulated: true
```

**Indicadores de Golden Ticket**:
- TGT con lifetime anormalmente largo
- Logon desde cuenta que no debería tener acceso
- Uso de `krbtgt` account hash

---

### Ejercicio 8: Simulación en Vivo — DCOM Lateral Movement

```bash
simulate dcom_lateral
```

**En Kibana**:
```kql
# Proceso creado via DCOM
event_id: 4688 and simulated: true and creator_process_name: *mmc.exe*

# Logon asociado al lateral movement
event_id: 4624 and simulated: true and logon_type: 3
```

---

### Ejercicio 9: Simulación en Vivo — WMI Persistence

```bash
simulate wmi_persistence
```

**En Kibana**:
```kql
# Procesos WMI sospechosos
event_id: 4688 and command_line: *wmic* and simulated: true

# Scheduled task para WMI
event_id: 4698 and simulated: true
```

---

### Ejercicio 10: Simulación en Vivo — SAM Dump

```bash
simulate sam_dump
```

**En Kibana**:
```kql
# Acceso al registro SAM
event_id: 4688 and command_line: (*reg save* or *sam*) and simulated: true
```

---

### Ejercicio 11: Simulación en Vivo — DLL Search Order Hijacking

```bash
simulate dll_search_order
```

**En Kibana**:
```kql
# Servicio instalado con DLL sospechosa
event_id: 4697 and simulated: true

# Proceso creado por el servicio
event_id: 4688 and simulated: true and creator_process_name: *services.exe*
```

---

### Ejercicio 12: Simulación en Vivo — Ransomware Execution

```bash
simulate ransomware_execution
```

**En Kibana**:
```kql
# Procesos de eliminación de backups
event_id: 4688 and (command_line: *vssadmin* or command_line: *bcdedit* or command_line: *wbadmin*) and simulated: true

# Servicios de seguridad detenidos
event_id: 4688 and command_line: (*net stop* or *sc stop*) and simulated: true

# Scheduled task para ejecución masiva
event_id: 4698 and simulated: true
```

---

### Ejercicio 13: Simulación en Vivo — Cadena Completa

```bash
simulate all
```

**En Kibana**:
```kql
simulated: true
```

**Tarea**: Reconstruir la timeline completa del ataque:
1. Initial Access (golden ticket → logon)
2. Lateral Movement (DCOM → múltiples hosts)
3. Persistence (WMI + DLL hijacking)
4. Credential Access (SAM dump)
5. Impact (ransomware execution)

---

### Ejercicio 14: Usando el Hunt Helper

El Lab 16 incluye un asistente de queries pre-construidas:

```bash
# Ver queries disponibles
hunt list

# Ejecutar query específica
hunt brute_force
hunt pth_detection
hunt kerberoasting
hunt suspicious_services
hunt hidden_accounts
hunt rdp_lateral
hunt encoded_powershell
hunt admin_share_access
hunt process_from_temp
hunt privilege_escalation
hunt dcsync
hunt log_cleared
```

Cada query muestra:
- La query Elasticsearch ejecutada
- Los resultados formateados
- La explicación de qué buscar
- El mapeo MITRE ATT&CK

---

### Ejercicio 15: Crear Dashboard de Alertas en Kibana

**Paso 1**: Crear visualización "Metric" para logons fallidos:
- Filtro: `event_id: 4625`
- Mostrar count total

**Paso 2**: Crear visualización "Pie" para logon types:
- Filtro: `event_id: 4624`
- Slice by: `logon_type`

**Paso 3**: Crear visualización "Table" para cuentas sospechosas:
- Filtro: `event_id: (4720 or 4732 or 4697)`
- Columnas: `timestamp`, `event_id`, `subject_user`, `target_user`, `hostname`

**Paso 4**: Agregar todo a un nuevo Dashboard "SOC Alerts"

---

### Ejercicio 16: Correlación Multi-Host

**Objetivo**: Rastrear el movimiento del atacante entre hosts.

```kql
# Paso 1: Identificar el primer host comprometido (brute force)
event_id: 4624 and source_ip: "10.0.1.200" and logon_type: 3

# Paso 2: Desde ese host, buscar RDP lateral
event_id: 4624 and source_ip: "10.0.1.15" and logon_type: 10

# Paso 3: Buscar acceso a shares desde hosts comprometidos
event_id: 5145 and source_ip: "10.0.1.15"
```

**Tarea**: Dibujar el mapa de movimiento lateral:
```
Atacante (10.0.1.200) → Brute Force
    → SRV-DC01 (logon type 3)
        → WS-001 (10.0.1.15) [Pass-the-Hash]
            → SRV-FILE01 (RDP, logon type 10)
            → SRV-DC01 (RDP, logon type 10)
            → WS-003 (RDP, logon type 10)
                → Exfiltración datos financieros (5145 → C$)
```

---

### Ejercicio 17: Resetear y Practicar

```bash
# Limpiar eventos simulados
simulate reset

# Practicar detección de un escenario específico
simulate golden_ticket

# Usar el hunt helper para verificar
hunt pth_detection
```

---

## Escenarios del Simulador

| Comando | Técnica MITRE | Descripción |
|---------|---------------|-------------|
| `simulate golden_ticket` | T1558.001 | Forja de TGT con hash krbtgt |
| `simulate dcom_lateral` | T1021.003 | Lateral movement via DCOM |
| `simulate wmi_persistence` | T1546.003 | Persistencia fileless con WMI |
| `simulate sam_dump` | T1003.002 | Extracción de hashes SAM |
| `simulate dll_search_order` | T1574.001 | DLL Search Order Hijacking |
| `simulate token_impersonation` | T1134.001 | Impersonación de token |
| `simulate ransomware_execution` | T1486 | Despliegue de ransomware |
| `simulate supply_chain` | T1195.002 | Compromiso de software supply chain |
| `simulate ad_enumeration` | T1087.002 | Enumeración de Active Directory |
| `simulate firewall_disable` | T1562.004 | Deshabilitación de firewall |
| `simulate all` | — | Ejecutar todos los escenarios |
| `simulate reset` | — | Eliminar eventos simulados |

---

## Mapeo MITRE ATT&CK

| Técnica | ID | Event IDs | Query KQL |
|---------|-----|-----------|-----------|
| Brute Force | T1110 | 4625, 4624 | `event_id: 4625` (>10 en 5min) |
| Valid Accounts | T1078 | 4624 | `event_id: 4624 and logon_type: 10` |
| Create Account | T1136 | 4720 | `event_id: 4720` |
| Account Manipulation | T1098 | 4732 | `event_id: 4732` |
| Pass-the-Hash | T1550.002 | 4776, 4624 | `event_id: 4624 and logon_type: 9` |
| Golden Ticket | T1558.001 | 4768 | `event_id: 4768` (lifetime anómalo) |
| Kerberoasting | T1558.003 | 4769 | `event_id: 4769 and ticket_encryption: "0x17"` |
| Service Execution | T1569.002 | 4697 | `event_id: 4697` |
| Scheduled Task | T1053.005 | 4698 | `event_id: 4698 and not attack_chain: "baseline"` |
| Network Share | T1039 | 5145 | `event_id: 5145 and share_name: *C$*` |
| DCSync | T1003.006 | 4662 | `event_id: 4662 and properties: *1131f6aa*` |

---

## Cadena de Ataque en el Dataset Base

```
Password Spray (4625 ×50 desde KALI-BOX → 4624 exitoso)
    │
    ▼
Initial Access — Network Logon (4624, Logon Type 3, source: 10.0.1.200)
    │
    ▼
Pass-the-Hash (4624 Logon Type 9 + 4648 explicit credentials)
    │
    ▼
Privilege Escalation (4720: cuenta svc_update$ + 4732: → Administrators)
    │
    ▼
Credential Dumping (4688: PowerShell Mimikatz + 4769: Kerberoasting RC4)
    │
    ▼
Lateral Movement — RDP (4624 Type 10 → 3 hosts desde 10.0.1.15)
    │
    ▼
Persistence (4697: servicio malicioso + 4698: scheduled task)
    │
    ▼
DCSync (4662: DS-Replication-Get-Changes)
    │
    ▼
Data Access (5145 → C$ shares → archivos financieros)
    │
    ▼
Anti-Forensics (1102: Security log cleared)
```

---

## Limpieza

```bash
docker compose down -v
```

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| Kibana no carga | Esperar 90 segundos, verificar `docker logs winevt-kibana` |
| No hay datos | Verificar data view: `Windows Security Events` en Management → Data Views |
| `simulate` no responde | Verificar ES: `curl http://elasticsearch:9200` desde el contenedor |
| `hunt` da error | Verificar que el índice existe: `curl http://elasticsearch:9200/windows-security/_count` |
| Eventos simulados no aparecen | Refrescar Kibana (F5), ajustar tiempo a "Last 15 minutes" |
| Error vm.max_map_count | `sudo sysctl -w vm.max_map_count=262144` en el host |
| Puerto 5601 en uso | Verificar con `lsof -i :5601` y detener el proceso conflictivo |
| `_count` devuelve null | Verificar que el loader terminó: `docker logs winevt-loader` |
