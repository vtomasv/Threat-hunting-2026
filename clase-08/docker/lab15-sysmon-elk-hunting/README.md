# Lab 15: Hunting Avanzado con Sysmon + ELK Stack

## Escenario

Eres un Threat Hunter en el SOC de **GlobalTech Industries**. El equipo de Threat Intelligence ha recibido un reporte sobre una campaña APT que utiliza técnicas Living-off-the-Land (LOTL) combinadas con process injection y movimiento lateral. Tu misión es utilizar los logs de Sysmon indexados en Elasticsearch para detectar las técnicas del adversario usando **Kibana** como plataforma principal de análisis.

El entorno contiene **más de 800 eventos Sysmon** que incluyen actividad legítima mezclada con **múltiples cadenas de ataque sofisticadas**: credential dumping, process injection, lateral movement, ransomware preparation, y exfiltración de datos.

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
│  │  800+ eventos│  │  Dashboard   │  │ simulate <ataque>│  │
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
# Esperado: >800

# Verificar Kibana
curl -s http://localhost:5601/api/status | jq .status.overall.level
# Esperado: "available"
```

### Paso 4: Acceder a Kibana

Abrir en el navegador: **http://localhost:5601**

Ir a **Analytics → Dashboard** y seleccionar **"Sysmon Threat Hunting - Lab 15"**

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
| 22 | DNS Query | DGA, tunneling |
| 25 | Process Tampering | Hollowing, herpaderping |

---

## Ejercicios Guiados

### Ejercicio 1: Reconocimiento del Dataset en Kibana

**Objetivo**: Familiarizarse con la estructura de datos y Kibana como herramienta de hunting.

**Paso 1**: En Kibana, ir a **Analytics → Discover**

**Paso 2**: Seleccionar el data view `sysmon-hunting*`

**Paso 3**: Ejecutar las siguientes queries KQL en la barra de búsqueda:

```kql
# 1.1 Ver todos los eventos de creación de procesos
event_id: 1

# 1.2 Contar eventos por hostname
# Usar la barra lateral izquierda → campo "hostname" → ver distribución

# 1.3 Buscar actividad del usuario SYSTEM
user: "NT AUTHORITY\\SYSTEM"

# 1.4 Ver todos los Event IDs disponibles
# Agregar campo "event_id" como columna y ver breakdown en sidebar
```

**Paso 4**: Crear una tabla con columnas: `@timestamp`, `event_id`, `process_name`, `command_line`, `user`

**Preguntas guía**:
- ¿Cuántos Event IDs diferentes hay?
- ¿Cuáles son los 5 procesos más ejecutados?
- ¿Cuántos hosts diferentes aparecen?

---

### Ejercicio 2: Detección de LOTL Binaries en Kibana

**Hipótesis**: El adversario utiliza binarios legítimos de Windows para descargar y ejecutar payloads.

**En Kibana** (Analytics → Discover, data view `sysmon-hunting*`):

```kql
# 2.1 Buscar certutil para descargas
event_id: 1 and process_name: "certutil.exe" and command_line: *urlcache*

# 2.2 Buscar PowerShell con encoded commands
event_id: 1 and process_name: "powershell.exe" and command_line: (*-enc* or *-EncodedCommand* or *hidden*)

# 2.3 Buscar mshta ejecutando contenido remoto
event_id: 1 and process_name: "mshta.exe" and command_line: *http*

# 2.4 Buscar bitsadmin para transferencias
event_id: 1 and process_name: "bitsadmin.exe" and command_line: (*transfer* or *download*)

# 2.5 Buscar wmic para ejecución remota
event_id: 1 and process_name: "wmic.exe" and command_line: *process*

# 2.6 Buscar rundll32 con argumentos sospechosos
event_id: 1 and process_name: "rundll32.exe" and command_line: (*javascript* or *vbscript* or *http* or *temp*)

# 2.7 Query combinada: TODOS los LOTL binaries sospechosos
event_id: 1 and (process_name: "certutil.exe" or process_name: "mshta.exe" or process_name: "bitsadmin.exe" or process_name: "wmic.exe") and command_line: (*http* or *urlcache* or *transfer* or *process*)
```

**Respuestas esperadas**:
- certutil: Descarga de `update.exe` desde IP externa
- PowerShell: Comando encoded que descarga y ejecuta en memoria
- mshta: Ejecución de HTA desde servidor C2
- bitsadmin: Transferencia de payload disfrazado como `.jpg`

---

### Ejercicio 3: Detección de Process Injection en Kibana

**Hipótesis**: El adversario inyecta código en procesos legítimos para evadir detección.

```kql
# 3.1 CreateRemoteThread (indicador clásico de injection)
event_id: 8

# 3.2 Injection en procesos críticos del sistema
event_id: 8 and (target_process: *svchost* or target_process: *explorer* or target_process: *lsass*)

# 3.3 Process Tampering (hollowing/herpaderping)
event_id: 25

# 3.4 Acceso a LSASS (credential dumping)
event_id: 10 and target_process: *lsass* and access_mask: ("0x1010" or "0x1FFFFF")

# 3.5 DLL sospechosas cargadas desde rutas no estándar
event_id: 7 and (image_loaded: *temp* or image_loaded: *appdata* or image_loaded: *public*)

# 3.6 Correlación: proceso que inyecta Y luego hace conexión de red
# Primero encontrar el target de la injection:
event_id: 8

# Luego buscar conexiones del proceso inyectado:
event_id: 3 and process_name: "svchost.exe" and destination_port: (443 or 8443 or 4443)
```

**Tarea**: Documenta el PID del proceso inyector, el proceso víctima, y la IP de C2.

---

### Ejercicio 4: Detección de Movimiento Lateral en Kibana

**Hipótesis**: El adversario se mueve lateralmente usando herramientas administrativas.

```kql
# 4.1 PsExec o herramientas similares
event_id: 1 and (process_name: "psexec.exe" or process_name: "psexesvc.exe" or command_line: *\\\\*)

# 4.2 WMI remoto
event_id: 1 and process_name: "wmiprvse.exe"

# 4.3 Servicios creados remotamente
event_id: 1 and parent_process: *services.exe* and command_line: *cmd*

# 4.4 RDP
event_id: 3 and destination_port: 3389

# 4.5 PowerShell Remoting (WinRM)
event_id: 1 and process_name: "wsmprovhost.exe"

# 4.6 Scheduled Tasks remotas
event_id: 1 and process_name: "schtasks.exe" and command_line: */s *
```

---

### Ejercicio 5: Detección de Persistencia en Kibana

**Hipótesis**: El adversario establece mecanismos para mantener acceso.

```kql
# 5.1 Registry Run Keys
event_id: 13 and registry_key: (*Run* or *RunOnce*)

# 5.2 Scheduled Tasks creadas
event_id: 1 and process_name: "schtasks.exe" and command_line: */create*

# 5.3 Servicios instalados
event_id: 1 and process_name: "sc.exe" and command_line: *create*

# 5.4 WMI Event Subscriptions
event_id: 1 and process_name: "wmic.exe" and command_line: *EventFilter*

# 5.5 Startup folder
event_id: 11 and file_path: *Startup*
```

---

### Ejercicio 6: Detección de Exfiltración en Kibana

**Hipótesis**: El adversario exfiltra datos usando protocolos comunes.

```kql
# 6.1 Conexiones a puertos no estándar
event_id: 3 and direction: "outbound" and not destination_port: (80 or 443 or 53 or 22)

# 6.2 DNS con queries largos (tunneling)
event_id: 22 and dns_query_length: > 50

# 6.3 Grandes transferencias
event_id: 3 and direction: "outbound" and bytes_sent: > 1000000

# 6.4 Procesos inusuales con conexiones de red
event_id: 3 and (process_name: "notepad.exe" or process_name: "calc.exe")

# 6.5 Archivos comprimidos en staging
event_id: 11 and (file_path: *.zip or file_path: *.7z or file_path: *.rar) and file_path: *temp*
```

---

### Ejercicio 7: Simulación en Vivo — DLL Injection

**Objetivo**: Generar un evento de DLL injection en vivo y detectarlo en Kibana.

**Paso 1**: Conectarse al simulador
```bash
docker exec -it sysmon-hunt-sim bash
```

**Paso 2**: Ver escenarios disponibles
```bash
simulate list
```

**Paso 3**: Ejecutar DLL injection
```bash
simulate dll_injection
```

**Paso 4**: En Kibana → Discover, ajustar tiempo a "Last 15 minutes" y buscar:
```kql
event_id: 7 and image_loaded: *malicious* and @timestamp > now-5m
```

**Paso 5**: Analizar:
- ¿Qué proceso cargó la DLL?
- ¿Desde qué ruta se cargó?
- ¿La DLL está firmada?
- ¿Qué técnica MITRE corresponde?

---

### Ejercicio 8: Simulación en Vivo — Process Hollowing

```bash
simulate process_hollowing
```

**En Kibana**:
```kql
# Process Tampering
event_id: 25 and @timestamp > now-5m

# Correlacionar con creación del proceso
event_id: 1 and process_name: "svchost.exe" and parent_process: *cmd* and @timestamp > now-5m
```

**Preguntas**:
- ¿Por qué es sospechoso que `cmd.exe` sea padre de `svchost.exe`?
- ¿Qué Event ID indica el tampering?
- ¿Cómo diferenciarías esto de un `svchost.exe` legítimo?

---

### Ejercicio 9: Simulación en Vivo — Credential Dumping

```bash
simulate credential_dump
```

**En Kibana**:
```kql
# Acceso a LSASS
event_id: 10 and target_process: *lsass* and @timestamp > now-5m

# Herramienta usada
event_id: 1 and (command_line: *sekurlsa* or command_line: *mimikatz*) and @timestamp > now-5m
```

---

### Ejercicio 10: Simulación en Vivo — Ransomware Preparation

```bash
simulate ransomware_prep
```

**En Kibana**:
```kql
# Eliminación de shadow copies
event_id: 1 and (command_line: *vssadmin* or command_line: *wmic shadowcopy*) and @timestamp > now-5m

# Deshabilitación de recovery
event_id: 1 and command_line: *bcdedit* and command_line: *recoveryenabled* and @timestamp > now-5m

# Archivos cifrados
event_id: 11 and (file_path: *.encrypted or file_path: *.locked) and @timestamp > now-5m
```

---

### Ejercicio 11: Simulación en Vivo — Lateral Movement con WMI

```bash
simulate lateral_wmi
```

**En Kibana**:
```kql
# WMI remoto
event_id: 1 and process_name: "wmic.exe" and command_line: */node:* and @timestamp > now-5m

# Proceso hijo creado por WMI
event_id: 1 and parent_process: *wmiprvse* and @timestamp > now-5m
```

---

### Ejercicio 12: Simulación en Vivo — Exfiltración DNS

```bash
simulate dns_exfil
```

**En Kibana**:
```kql
# DNS queries con alta entropía
event_id: 22 and dns_query_length: > 40 and @timestamp > now-5m

# Patrón de subdominios codificados
event_id: 22 and dns_query: *data.* and @timestamp > now-5m
```

---

### Ejercicio 13: Simulación en Vivo — Cadena Completa APT

**Objetivo**: Ejecutar todos los escenarios y reconstruir la kill chain completa.

```bash
simulate all
```

**En Kibana**, buscar todos los eventos recientes:
```kql
@timestamp > now-10m
```

**Tarea**: Ordenar cronológicamente y mapear a Cyber Kill Chain:
1. Delivery → 2. Exploitation → 3. Installation → 4. C2 → 5. Lateral Movement → 6. Actions on Objectives

---

### Ejercicio 14: Crear Visualización Personalizada en Kibana

**Paso 1**: Ir a Analytics → Visualize Library → Create new visualization

**Paso 2**: Seleccionar "Lens" → tipo "Donut"

**Paso 3**: Configurar:
- Slice by: `mitre_technique.keyword` (Top 10)
- Metric: Count

**Paso 4**: Guardar como "MITRE Techniques Distribution"

**Paso 5**: Crear visualización tipo "Bar" para timeline:
- X-axis: `@timestamp` (Date histogram, 1 minuto)
- Y-axis: Count
- Split by: `event_category.keyword`

---

### Ejercicio 15: Hunting Hypothesis — Detectar C2 Beaconing

**Hipótesis**: Un proceso comprometido se comunica periódicamente con un C2.

```kql
event_id: 3 and direction: "outbound" and destination_port: (443 or 8443)
```

**En Kibana**: Crear tabla con columnas: `process_name`, `destination_ip`, `destination_port`, `@timestamp`

**Indicadores de beaconing**:
- Mismo proceso → misma IP → intervalos regulares
- Puertos altos no estándar
- Procesos inusuales con conexiones (notepad, calc)

---

### Ejercicio 16: Resetear y Repetir

```bash
# Limpiar eventos simulados
simulate reset

# Verificar en Kibana que solo quedan eventos base
# Ejecutar un escenario específico
simulate dll_injection
```

---

## Mapeo MITRE ATT&CK

| Técnica | ID | Tactic | Query KQL |
|---------|-----|--------|-----------|
| Process Injection | T1055 | Defense Evasion | `event_id: 8` |
| Process Hollowing | T1055.012 | Defense Evasion | `event_id: 25` |
| LSASS Memory | T1003.001 | Credential Access | `event_id: 10 and target_process: *lsass*` |
| Scheduled Task | T1053.005 | Persistence | `process_name: "schtasks.exe" and command_line: */create*` |
| Registry Run Keys | T1547.001 | Persistence | `event_id: 13 and registry_key: *Run*` |
| Certutil | T1105 | Command & Control | `process_name: "certutil.exe" and command_line: *urlcache*` |
| PowerShell | T1059.001 | Execution | `process_name: "powershell.exe" and command_line: *-enc*` |
| WMI | T1047 | Execution | `process_name: "wmic.exe" and command_line: */node*` |
| DNS Tunneling | T1071.004 | C2 | `event_id: 22 and dns_query_length: > 50` |
| Shadow Copy Delete | T1490 | Impact | `command_line: *vssadmin* and command_line: *delete*` |

---

## Cadena de Ataque en el Dataset

```
Delivery (Phishing)
    │
    ▼
Execution (mshta.exe → HTA payload)
    │
    ▼
Persistence (Registry Run Key + Scheduled Task)
    │
    ▼
Defense Evasion (Process Hollowing → svchost.exe)
    │
    ▼
Credential Access (LSASS dump → mimikatz)
    │
    ▼
Lateral Movement (WMI + PsExec → 3 hosts)
    │
    ▼
Collection (Archivos comprimidos en staging)
    │
    ▼
Exfiltration (DNS tunneling + HTTPS)
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
| No hay datos en Discover | Verificar data view: Management → Data Views → `sysmon-hunting*` |
| `simulate` no funciona | Verificar conexión: `curl http://elasticsearch:9200` desde el simulador |
| Dashboard vacío | Verificar loader: `docker logs sysmon-hunt-loader` |
| Eventos simulados no aparecen | Refrescar (F5) y ajustar tiempo a "Last 15 minutes" |
| Error vm.max_map_count | Ejecutar `sudo sysctl -w vm.max_map_count=262144` en el host |
