# Lab 15: Hunting Avanzado con Sysmon + ELK Stack

## Escenario

Eres un Threat Hunter en el SOC de **GlobalTech Industries**. El equipo de Threat Intelligence ha recibido un reporte sobre una campaña APT que utiliza técnicas Living-off-the-Land (LOTL) combinadas con process injection y movimiento lateral. Tu misión es utilizar los logs de Sysmon indexados en Elasticsearch para detectar las técnicas del adversario usando **Kibana** como plataforma principal de análisis.

El entorno contiene **más de 1500 eventos Sysmon** que incluyen actividad legítima mezclada con **múltiples cadenas de ataque sofisticadas**: credential dumping, process injection, lateral movement, ransomware preparation, y exfiltración de datos.

Además, dispones de un **simulador de ataques en vivo** que te permite inyectar nuevos eventos de ataque en tiempo real y detectarlos inmediatamente en Kibana.

---

## Objetivos de Aprendizaje

1. Dominar queries KQL complejas en Kibana para hunting de amenazas
2. Identificar técnicas LOTL (certutil, mshta, wmic, bitsadmin, rundll32)
3. Detectar process injection y hollowing mediante análisis de eventos Sysmon
4. Correlacionar eventos para reconstruir cadenas de ataque completas
5. Usar el simulador para generar eventos y validar hipótesis de hunting
6. Crear visualizaciones y alertas personalizadas en Kibana

---

## Requisitos Previos

- Docker y Docker Compose instalados
- Mínimo 4 GB de RAM disponible
- Puertos 9200 y 5601 libres
- Conocimientos básicos de Sysmon Event IDs

---

## Arquitectura del Laboratorio

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network (elk-net)                   │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │Elasticsearch │  │    Kibana    │  │   Simulator      │  │
│  │  :9200       │  │    :5601     │  │ (interactivo)    │  │
│  │              │◄─┤              │  │                  │  │
│  │  1500+ events│  │  Dashboard   │  │ simulate <ataque>│  │
│  │  Sysmon      │  │  + Queries   │  │ → inyecta en ES  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│         ▲                                     │              │
│         │         ┌──────────────┐            │              │
│         └─────────┤    Loader    ├────────────┘              │
│                   │ (dataset +   │                           │
│                   │  Kibana cfg) │                           │
│                   └──────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Despliegue

### Paso 1: Preparar el host

```bash
sudo sysctl -w vm.max_map_count=262144
```

### Paso 2: Levantar el entorno

```bash
cd clase-08/docker/lab15-sysmon-elk-hunting
docker compose up -d
```

### Paso 3: Verificar que los servicios están listos (~90 segundos)

```bash
# Verificar Elasticsearch
curl -s http://localhost:9200/_cluster/health | jq .status
# Esperado: "green" o "yellow"

# Verificar que los datos se cargaron
curl -s http://localhost:9200/sysmon-hunting/_count | jq .count
# Esperado: >1500

# Verificar Kibana
curl -s http://localhost:5601/api/status | jq .status.overall.level
# Esperado: "available"
```

### Paso 4: Acceder a Kibana

Abrir en el navegador: **http://localhost:5601**

Ir a **Analytics → Discover** y seleccionar el data view **"Sysmon Hunting - Lab 15"**

### Paso 5: Conectarse al simulador

```bash
docker exec -it sysmon-hunt-sim bash
```

Verás el banner de bienvenida con los comandos disponibles.

---

## Referencia Rápida: Sysmon Event IDs

| Event ID | Descripción | Relevancia para Hunting |
|----------|-------------|------------------------|
| 1 | Process Create | Ejecución de binarios sospechosos |
| 3 | Network Connection | Conexiones C2, exfiltración |
| 7 | Image Loaded | DLL injection, side-loading |
| 8 | CreateRemoteThread | Process injection |
| 10 | Process Access | Credential dumping (LSASS) |
| 11 | File Create | Dropper, staging |
| 12/13 | Registry | Persistencia |
| 17 | Pipe Created | Cobalt Strike, named pipes |
| 19/20 | WMI Event | Fileless persistence |
| 22 | DNS Query | DGA, tunneling |
| 25 | Process Tampering | Hollowing, herpaderping |

---

## Campos Importantes del Índice

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `event_id` | integer | ID del evento Sysmon |
| `process_name` | keyword | Nombre del proceso |
| `image` | text | Ruta completa del ejecutable |
| `command_line` | text | Línea de comandos completa |
| `user` | keyword | Usuario que ejecutó |
| `parent_name` | keyword | Nombre del proceso padre |
| `parent_image` | text | Ruta del proceso padre |
| `target_name` | keyword | Proceso objetivo (Event 8, 10) |
| `target_image` | text | Ruta del proceso objetivo |
| `granted_access` | keyword | Máscara de acceso (Event 10) |
| `image_loaded` | text | DLL cargada (Event 7) |
| `target_filename` | text | Archivo creado (Event 11) |
| `target_object` | text | Clave de registro (Event 13) |
| `query_name` | keyword | Dominio DNS consultado (Event 22) |
| `destination_ip` | ip | IP destino (Event 3) |
| `destination_port` | integer | Puerto destino (Event 3) |
| `bytes_sent` | long | Bytes enviados (Event 3) |
| `initiated` | boolean | Conexión saliente (Event 3) |
| `mitre_technique` | keyword | Técnica MITRE ATT&CK |
| `attack_chain` | keyword | Cadena de ataque asociada |
| `severity` | keyword | info, high, critical |

---

## Ejercicios Guiados

### Ejercicio 1: Reconocimiento del Dataset en Kibana

**Objetivo**: Familiarizarse con la estructura de datos y Kibana como herramienta de hunting.

**Paso 1**: En Kibana, ir a **Analytics → Discover**

**Paso 2**: Seleccionar el data view `Sysmon Hunting - Lab 15`

**Paso 3**: Ejecutar las siguientes queries KQL en la barra de búsqueda:

```kql
# 1.1 Ver todos los eventos de creación de procesos
event_id: 1

# 1.2 Contar eventos por hostname
# Usar la barra lateral izquierda → campo "hostname" → ver distribución

# 1.3 Buscar actividad del usuario SYSTEM
user: "NT AUTHORITY\\SYSTEM"

# 1.4 Ver solo eventos maliciosos
severity: "critical"

# 1.5 Ver cadenas de ataque disponibles
attack_chain: *
```

**Paso 4**: Crear una tabla con columnas: `timestamp`, `event_id`, `process_name`, `command_line`, `user`

**Preguntas guía**:
- ¿Cuántos Event IDs diferentes hay?
- ¿Cuáles son los 5 procesos más ejecutados?
- ¿Cuántas cadenas de ataque diferentes hay en el dataset?

---

### Ejercicio 2: Detección de LOTL Binaries en Kibana

**Hipótesis**: El adversario utiliza binarios legítimos de Windows para descargar y ejecutar payloads.

**En Kibana** (Analytics → Discover, data view `Sysmon Hunting - Lab 15`):

```kql
# 2.1 Buscar certutil para descargas
event_id: 1 and process_name: "certutil.exe" and command_line: *urlcache*

# 2.2 Buscar PowerShell con encoded commands
event_id: 1 and process_name: "powershell.exe" and command_line: (*-enc* or *hidden*)

# 2.3 Buscar mshta ejecutando contenido remoto
event_id: 1 and process_name: "mshta.exe" and command_line: *http*

# 2.4 Buscar bitsadmin para transferencias
event_id: 1 and process_name: "bitsadmin.exe" and command_line: (*transfer* or *upload*)

# 2.5 Buscar wmic para ejecución remota
event_id: 1 and process_name: "WMIC.exe" and command_line: *process*

# 2.6 Buscar rundll32 sin argumentos (Cobalt Strike)
event_id: 1 and process_name: "rundll32.exe" and parent_name: "powershell.exe"

# 2.7 Query combinada: TODOS los LOTL binaries sospechosos
event_id: 1 and (process_name: "certutil.exe" or process_name: "mshta.exe" or process_name: "bitsadmin.exe" or process_name: "WMIC.exe") and command_line: (*http* or *urlcache* or *transfer* or *process*)
```

**Respuestas esperadas**:
- certutil: Descarga de `update.exe` desde IP externa (cadena `lotl_certutil`)
- PowerShell: Comando encoded que descarga y ejecuta en memoria (cadena `macro_powershell`)
- bitsadmin: Upload de datos comprimidos al C2 (cadena `exfiltration`)
- wmic: Ejecución remota en otro host (cadena `lateral_movement`)

---

### Ejercicio 3: Detección de Process Injection en Kibana

**Hipótesis**: El adversario inyecta código en procesos legítimos para evadir detección.

```kql
# 3.1 CreateRemoteThread (indicador clásico de injection)
event_id: 8

# 3.2 Injection en procesos críticos del sistema
event_id: 8 and (target_name: "explorer.exe" or target_name: "svchost.exe")

# 3.3 Process Tampering (hollowing/herpaderping)
event_id: 25

# 3.4 Acceso a LSASS (credential dumping)
event_id: 10 and target_name: "lsass.exe" and granted_access: ("0x1010" or "0x1FFFFF")

# 3.5 DLL sospechosas cargadas desde rutas no estándar
event_id: 7 and (image_loaded: *Temp* or image_loaded: *AppData* or image_loaded: *Public*)

# 3.6 Correlación: proceso que inyecta Y luego hace conexión de red
# Primero encontrar el source de la injection:
event_id: 8 and source_name: "update.exe"

# Luego buscar conexiones del proceso inyectado (explorer con C2):
event_id: 3 and process_name: "explorer.exe" and destination_port: 443
```

**Tarea**: Documenta el PID del proceso inyector, el proceso víctima, y la IP de C2.

---

### Ejercicio 4: Detección de Movimiento Lateral en Kibana

**Hipótesis**: El adversario se mueve lateralmente usando herramientas administrativas.

```kql
# 4.1 PsExec o herramientas similares
event_id: 1 and (process_name: "PsExec.exe" or command_line: *\\\\*)

# 4.2 WMI remoto
event_id: 1 and process_name: "WMIC.exe" and command_line: */node*

# 4.3 Conexiones a puertos de administración (SMB, WMI)
event_id: 3 and destination_port: (445 or 135)

# 4.4 RDP
event_id: 3 and destination_port: 3389

# 4.5 Scheduled Tasks remotas
event_id: 1 and process_name: "schtasks.exe" and command_line: */create*

# 4.6 Lateral movement completo (toda la cadena)
attack_chain: "lateral_movement"
```

---

### Ejercicio 5: Detección de Persistencia en Kibana

**Hipótesis**: El adversario establece mecanismos para mantener acceso.

```kql
# 5.1 Registry Run Keys
event_id: 13 and target_object: *Run*

# 5.2 Scheduled Tasks creadas
event_id: 1 and process_name: "schtasks.exe" and command_line: */create*

# 5.3 Servicios instalados
event_id: 1 and process_name: "sc.exe" and command_line: *create*

# 5.4 WMI Event Subscriptions (fileless persistence)
event_id: (19 or 20) 

# 5.5 Archivos en Startup folder
event_id: 11 and target_filename: *Startup*

# 5.6 Toda la cadena de persistencia
attack_chain: "persistence"
```

---

### Ejercicio 6: Detección de Exfiltración en Kibana

**Hipótesis**: El adversario exfiltra datos usando protocolos comunes.

```kql
# 6.1 Conexiones salientes a IPs externas (no RFC1918)
event_id: 3 and initiated: true and not destination_ip: "10.*"

# 6.2 DNS con queries DGA (dominios aleatorios largos)
event_id: 22 and query_name: *evil-corp*

# 6.3 Grandes transferencias (bytes_sent alto)
event_id: 3 and bytes_sent > 1000000

# 6.4 Procesos inusuales con conexiones de red (explorer.exe no debería conectar a IPs externas)
event_id: 3 and process_name: "explorer.exe" and destination_ip: "198.51.100.10"

# 6.5 Archivos comprimidos en staging
event_id: 11 and target_filename: (*.7z or *.zip or *.rar)

# 6.6 BITS transfer para exfiltración
event_id: 1 and process_name: "bitsadmin.exe" and command_line: *upload*

# 6.7 Toda la cadena de exfiltración
attack_chain: "exfiltration"
```

---

### Ejercicio 7: Simulación en Vivo — Process Hollowing

**Objetivo**: Generar un evento de Process Hollowing en vivo y detectarlo en Kibana.

**Paso 1**: Conectarse al simulador
```bash
docker exec -it sysmon-hunt-sim bash
```

**Paso 2**: Ver escenarios disponibles
```bash
simulate list
```

**Paso 3**: Ejecutar Process Hollowing
```bash
simulate process_hollowing
```

**Paso 4**: En Kibana → Discover, ajustar tiempo a "Last 15 minutes" y buscar:
```kql
# Buscar el acceso sospechoso al proceso
event_id: 10 and granted_access: "0x1FFFFF" and simulated: true

# Buscar la conexión C2 del proceso hollowed
event_id: 3 and process_name: "svchost.exe" and destination_port: 443 and simulated: true
```

**Paso 5**: Analizar:
- ¿Qué proceso accedió a svchost.exe con FULL_ACCESS?
- ¿Desde qué ruta se ejecutó el proceso inyector?
- ¿A qué IP se conecta el svchost hollowed?
- ¿Qué técnica MITRE corresponde? (T1055.012)

---

### Ejercicio 8: Simulación en Vivo — DLL Side-Loading

```bash
simulate dll_sideloading
```

**En Kibana**:
```kql
# DLL no firmada cargada por proceso legítimo
event_id: 7 and signed: false and simulated: true

# Conexión C2 desde el proceso afectado
event_id: 3 and destination_port: 8443 and simulated: true
```

**Preguntas**:
- ¿Qué aplicación legítima fue abusada para cargar la DLL?
- ¿La DLL está firmada? ¿Cuál es su ruta?
- ¿A qué puerto no estándar se conecta?

---

### Ejercicio 9: Simulación en Vivo — Kerberoasting

```bash
simulate kerberoasting
```

**En Kibana**:
```kql
# PowerShell ejecutando Invoke-Kerberoast
event_id: 1 and command_line: *Kerberoast* and simulated: true

# Conexiones al DC (puerto 88 = Kerberos)
event_id: 3 and destination_port: 88 and simulated: true
```

**Indicadores de Kerberoasting**:
- Múltiples conexiones al puerto 88 en ráfaga
- PowerShell importando módulos de ataque
- Solicitudes TGS para múltiples SPNs

---

### Ejercicio 10: Simulación en Vivo — Ransomware

```bash
simulate ransomware
```

**En Kibana**:
```kql
# Eliminación de shadow copies
event_id: 1 and command_line: *vssadmin* and command_line: *delete* and simulated: true

# Deshabilitación de recovery
event_id: 1 and command_line: *bcdedit* and command_line: *recoveryenabled* and simulated: true

# Archivos cifrados (.locked)
event_id: 11 and target_filename: *.locked and simulated: true

# Ransom note
event_id: 11 and target_filename: *DECRYPT* and simulated: true
```

---

### Ejercicio 11: Simulación en Vivo — Cobalt Strike Beacon

```bash
simulate cobalt_strike
```

**En Kibana**:
```kql
# rundll32 sin argumentos (beacon spawn)
event_id: 1 and process_name: "rundll32.exe" and simulated: true

# Named pipe de Cobalt Strike
event_id: 17 and pipe_name: *MSSE* and simulated: true

# Beacon callbacks periódicos (~60s interval)
event_id: 3 and process_name: "rundll32.exe" and destination_port: 443 and simulated: true
```

**Indicadores de beaconing**:
- Mismo proceso → misma IP → intervalos regulares (~60s con jitter)
- Named pipe con patrón `MSSE-*-server`
- rundll32.exe sin argumentos de línea de comandos

---

### Ejercicio 12: Simulación en Vivo — DCSync Attack

```bash
simulate dcsync
```

**En Kibana**:
```kql
# lsass.exe conectando al DC (LDAP + SMB)
event_id: 3 and process_name: "lsass.exe" and destination_port: (389 or 445) and simulated: true
```

**Preguntas**:
- ¿Por qué es anómalo que lsass.exe de una workstation se conecte al DC?
- ¿Qué protocolo usa DCSync? (MS-DRSR sobre RPC)
- ¿Cómo diferenciar un DCSync malicioso de replicación legítima?

---

### Ejercicio 13: Simulación en Vivo — NTDS.dit Dump

```bash
simulate ntds_dump
```

**En Kibana**:
```kql
# ntdsutil ejecutado
event_id: 1 and process_name: "ntdsutil.exe" and simulated: true

# Archivos ntds.dit y SYSTEM hive creados
event_id: 11 and target_filename: (*ntds.dit or *SYSTEM*) and simulated: true
```

---

### Ejercicio 14: Simulación en Vivo — AMSI Bypass

```bash
simulate amsi_bypass
```

**En Kibana**:
```kql
# PowerShell con reflection para bypass AMSI
event_id: 1 and command_line: *AmsiUtils* and simulated: true

# amsi.dll cargada (será parcheada en memoria)
event_id: 7 and image_loaded: *amsi.dll* and simulated: true
```

---

### Ejercicio 15: Simulación en Vivo — Token Manipulation

```bash
simulate token_manipulation
```

**En Kibana**:
```kql
# Acceso a winlogon.exe para robar token
event_id: 10 and target_name: "winlogon.exe" and simulated: true

# cmd.exe ejecutado como SYSTEM desde proceso de usuario
event_id: 1 and user: "NT AUTHORITY\\SYSTEM" and parent_name: "update.exe" and simulated: true
```

---

### Ejercicio 16: Simulación en Vivo — Cadena Completa APT

**Objetivo**: Ejecutar todos los escenarios y reconstruir la kill chain completa.

```bash
simulate all
```

**En Kibana**, buscar todos los eventos simulados:
```kql
simulated: true
```

**Tarea**: Ordenar cronológicamente y mapear a Cyber Kill Chain:
1. Delivery → 2. Exploitation → 3. Installation → 4. C2 → 5. Lateral Movement → 6. Actions on Objectives

---

### Ejercicio 17: Crear Visualización Personalizada en Kibana

**Paso 1**: Ir a Analytics → Visualize Library → Create new visualization

**Paso 2**: Seleccionar "Lens" → tipo "Donut"

**Paso 3**: Configurar:
- Slice by: `mitre_technique.keyword` (Top 10)
- Metric: Count

**Paso 4**: Guardar como "MITRE Techniques Distribution"

**Paso 5**: Crear visualización tipo "Bar" para timeline:
- X-axis: `timestamp` (Date histogram, 1 minuto)
- Y-axis: Count
- Split by: `severity`

---

### Ejercicio 18: Resetear y Repetir

```bash
# Limpiar eventos simulados
simulate reset

# Verificar en Kibana que solo quedan eventos base
simulated: true
# (debería dar 0 resultados)

# Ejecutar un escenario específico
simulate cobalt_strike
```

---

## Escenarios del Simulador

| Comando | Técnica MITRE | Descripción |
|---------|---------------|-------------|
| `simulate process_hollowing` | T1055.012 | Svchost.exe hollowed con C2 |
| `simulate dll_sideloading` | T1574.002 | DLL maliciosa via OneDrive |
| `simulate kerberoasting` | T1558.003 | Solicitud masiva de tickets TGS |
| `simulate dcsync` | T1003.006 | Replicación de credenciales del DC |
| `simulate ransomware` | T1486 | Shadow copies + cifrado de archivos |
| `simulate fileless_wmi` | T1546.003 | WMI Event Subscription persistence |
| `simulate cobalt_strike` | T1071.001 | Beacon HTTPS con named pipe |
| `simulate token_manipulation` | T1134.001 | Robo de token SYSTEM |
| `simulate amsi_bypass` | T1562.001 | Parcheo de AmsiScanBuffer |
| `simulate ntds_dump` | T1003.003 | Extracción de ntds.dit |
| `simulate all` | — | Ejecutar todos los escenarios |
| `simulate reset` | — | Eliminar eventos simulados |

---

## Mapeo MITRE ATT&CK

| Técnica | ID | Tactic | Query KQL |
|---------|-----|--------|-----------|
| Process Injection | T1055.001 | Defense Evasion | `event_id: 8` |
| Process Hollowing | T1055.012 | Defense Evasion | `event_id: 10 and granted_access: "0x1FFFFF"` |
| LSASS Memory | T1003.001 | Credential Access | `event_id: 10 and target_name: "lsass.exe"` |
| Scheduled Task | T1053.005 | Persistence | `process_name: "schtasks.exe" and command_line: */create*` |
| Registry Run Keys | T1547.001 | Persistence | `event_id: 13 and target_object: *Run*` |
| Certutil | T1105 | Command & Control | `process_name: "certutil.exe" and command_line: *urlcache*` |
| PowerShell | T1059.001 | Execution | `process_name: "powershell.exe" and command_line: *-enc*` |
| WMI | T1047 | Execution | `process_name: "WMIC.exe" and command_line: */node*` |
| DGA/DNS | T1568.002 | C2 | `event_id: 22 and query_name: *evil-corp*` |
| Shadow Copy Delete | T1490 | Impact | `command_line: *vssadmin* and command_line: *delete*` |
| DLL Side-Loading | T1574.002 | Persistence | `event_id: 7 and signed: false` |
| Cobalt Strike | T1071.001 | C2 | `event_id: 17 and pipe_name: *MSSE*` |
| AMSI Bypass | T1562.001 | Defense Evasion | `command_line: *AmsiUtils*` |
| Token Manipulation | T1134.001 | Privilege Escalation | `event_id: 10 and target_name: "winlogon.exe"` |

---

## Cadena de Ataque en el Dataset Base

```
Delivery (Phishing → Macro en WINWORD.EXE)
    │
    ▼
Execution (cmd.exe → PowerShell encoded → download cradle)
    │
    ▼
Persistence (Registry Run Key + Scheduled Task + Service)
    │
    ▼
Defense Evasion (DLL Injection → CreateRemoteThread → explorer.exe)
    │
    ▼
Credential Access (Mimikatz renamed → LSASS dump → 0x1FFFFF)
    │
    ▼
Lateral Movement (WMI /node: + PsExec → 10.0.1.100)
    │
    ▼
Collection (7z.exe → archivos comprimidos con password)
    │
    ▼
Exfiltration (bitsadmin upload + DNS DGA via explorer.exe)
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
| Kibana no carga | Esperar 90 segundos después del `docker compose up` |
| No hay datos en Discover | Verificar data view: Management → Data Views → `Sysmon Hunting - Lab 15` |
| `simulate` no funciona | Verificar conexión: `curl http://elasticsearch:9200` desde el simulador |
| Dashboard vacío | Verificar loader: `docker logs sysmon-hunt-loader` |
| Eventos simulados no aparecen | Refrescar (F5) y ajustar tiempo a "Last 15 minutes" |
| Error vm.max_map_count | Ejecutar `sudo sysctl -w vm.max_map_count=262144` en el host |
| `_count` devuelve null | Verificar que el loader terminó: `docker logs sysmon-hunt-loader` |
