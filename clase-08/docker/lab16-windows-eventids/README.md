# Lab 16: Correlación Avanzada de Windows Event IDs + Simulador en Vivo

## Escenario

Eres el Threat Hunter principal de **Meridian Financial Group**, una institución financiera que ha sido víctima de un ataque sofisticado. El equipo de respuesta a incidentes ha extraído los logs de seguridad de Windows de 5 servidores y estaciones de trabajo comprometidas. Los eventos han sido ingestados en Elasticsearch y están disponibles para análisis en Kibana.

El dataset contiene **más de 1,200 eventos de seguridad Windows** que documentan una cadena de ataque completa: desde el acceso inicial con credenciales robadas, pasando por escalamiento de privilegios, movimiento lateral, credential dumping, hasta la exfiltración de datos financieros.

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
│  │  1200+ events│  │  Dashboard   │  │  simulate <ataque> │    │
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
| 9 | NewCredentials | RunAs /netonly |
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
curl -s http://localhost:9200/winevt-security/_count | jq .count
# Esperado: >1200

# Verificar Kibana
curl -s http://localhost:5601/api/status | jq .status.overall.level
```

### Paso 4: Acceder a Kibana

Abrir: **http://localhost:5601**

Ir a **Analytics → Dashboard** → **"Windows Security Hunting - Lab 16"**

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

**Paso 1**: En Kibana → Analytics → Discover → data view `winevt-security*`

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

# 1.5 Ver la timeline de eventos
# Ajustar rango de tiempo y ver el histograma
```

**Preguntas**:
- ¿Cuántos Event IDs diferentes hay?
- ¿Cuáles son los 3 hosts con más actividad?
- ¿Cuál es el rango temporal del incidente?

---

### Ejercicio 2: Detección de Brute Force y Password Spray

**Hipótesis**: El atacante intentó múltiples credenciales antes de lograr acceso.

**En Kibana**:

```kql
# 2.1 Buscar logons fallidos
event_id: 4625

# 2.2 Filtrar por origen (IP del atacante)
event_id: 4625 and source_ip: *

# 2.3 Password spray: múltiples cuentas desde misma IP
event_id: 4625 and source_ip: "10.0.1.50"

# 2.4 Brute force: múltiples intentos contra misma cuenta
event_id: 4625 and target_user: "admin"

# 2.5 Logon exitoso después de múltiples fallos (el atacante logró entrar)
event_id: 4624 and source_ip: "10.0.1.50"

# 2.6 Correlación temporal: fallos seguidos de éxito
event_id: (4625 or 4624) and source_ip: "10.0.1.50"
```

**Tarea**: Crear una visualización en Kibana tipo "Bar" con:
- X: `@timestamp` (intervalo 1 minuto)
- Y: Count
- Split: `event_id` (4624 vs 4625)
- Filter: `source_ip: "10.0.1.50"`

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
event_id: 4624 and logon_type: 3 and source_ip: "10.0.*"

# 3.5 Cuenta admin usada en múltiples hosts
event_id: 4624 and subject_user: "CORP\\admin" and logon_type: (3 or 10)

# 3.6 Logons en horarios inusuales (fuera de oficina)
event_id: 4624 and logon_type: 10
# Luego filtrar por timestamp en horario nocturno en Kibana
```

**Tarea**: Crear tabla con columnas: `@timestamp`, `hostname`, `subject_user`, `source_ip`, `logon_type`
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
event_id: (4720 or 4732) and target_user: *

# 4.5 Servicios instalados (puede ser PsExec o persistencia)
event_id: 4697

# 4.6 Scheduled Tasks creadas
event_id: 4698
```

**Preguntas**:
- ¿Qué cuenta backdoor se creó?
- ¿A qué grupo fue añadida?
- ¿Qué proceso/usuario realizó la acción?

---

### Ejercicio 5: Detección de Credential Dumping

**Hipótesis**: El adversario extrae credenciales de la memoria o del dominio.

```kql
# 5.1 Procesos sospechosos ejecutados (Event ID 4688)
event_id: 4688 and (new_process: *mimikatz* or new_process: *procdump* or new_process: *sekurlsa*)

# 5.2 Acceso a SAM/NTDS
event_id: 4688 and (command_line: *ntdsutil* or command_line: *secretsdump* or command_line: *reg save*)

# 5.3 Kerberos TGT requests anómalos (pass-the-ticket)
event_id: 4768

# 5.4 Kerberoasting (service ticket requests masivos)
event_id: 4769

# 5.5 NTLM authentication (pass-the-hash)
event_id: 4776

# 5.6 DCSync (replicación de directorio)
event_id: 4688 and command_line: *dcsync*
```

---

### Ejercicio 6: Detección de Exfiltración via Network Shares

**Hipótesis**: El adversario accede a shares administrativos para robar datos.

```kql
# 6.1 Acceso a network shares
event_id: 5145

# 6.2 Acceso a shares administrativos (C$, ADMIN$)
event_id: 5145 and share_name: (*C$* or *ADMIN$*)

# 6.3 Acceso a directorios sensibles
event_id: 5145 and relative_target: (*confidential* or *financial* or *passwords*)

# 6.4 Acceso masivo (múltiples archivos en poco tiempo)
event_id: 5145 and source_ip: "10.0.1.15"

# 6.5 Correlación: logon + share access desde misma IP
event_id: (4624 or 5145) and source_ip: "10.0.1.15"
```

**Tarea**: Crear visualización tipo "Timeline" mostrando los accesos a shares por minuto.

---

### Ejercicio 7: Simulación en Vivo — Brute Force Attack

**Paso 1**: Conectarse al simulador
```bash
docker exec -it winevt-simulator bash
```

**Paso 2**: Ejecutar escenario
```bash
simulate brute_force
```

**Paso 3**: En Kibana, detectar el ataque:
```kql
# Buscar ráfaga de logons fallidos
event_id: 4625 and @timestamp > now-5m

# Buscar el logon exitoso posterior
event_id: 4624 and source_ip: "10.0.1.50" and @timestamp > now-5m
```

**Paso 4**: Crear alerta visual:
- Ir a Analytics → Visualize → New → Metric
- Filtro: `event_id: 4625 and @timestamp > now-15m`
- Si el count > 10 en 5 minutos = posible brute force

---

### Ejercicio 8: Simulación en Vivo — Golden Ticket Attack

```bash
simulate golden_ticket
```

**En Kibana**:
```kql
# Buscar TGT request anómalo
event_id: 4768 and @timestamp > now-5m

# Buscar logon con ticket forjado (Logon Type 3 sin evento 4768 previo normal)
event_id: 4624 and logon_type: 3 and subject_user: *krbtgt* and @timestamp > now-5m

# Buscar acceso con privilegios de Domain Admin
event_id: 4672 and @timestamp > now-5m
```

**Indicadores de Golden Ticket**:
- TGT con lifetime anormalmente largo
- Logon desde cuenta que no debería tener acceso
- Uso de `krbtgt` account hash

---

### Ejercicio 9: Simulación en Vivo — Pass-the-Hash

```bash
simulate pass_the_hash
```

**En Kibana**:
```kql
# NTLM authentication events
event_id: 4776 and @timestamp > now-5m

# Logon tipo 3 con NTLM (sin Kerberos)
event_id: 4624 and logon_type: 3 and auth_package: "NTLM" and @timestamp > now-5m

# Correlación: logon sin evento 4648 previo
event_id: 4624 and logon_type: 9 and @timestamp > now-5m
```

---

### Ejercicio 10: Simulación en Vivo — Kerberoasting

```bash
simulate kerberoasting
```

**En Kibana**:
```kql
# Service ticket requests masivos
event_id: 4769 and @timestamp > now-5m

# Filtrar por encryption type débil (RC4 = 0x17)
event_id: 4769 and encryption_type: "0x17" and @timestamp > now-5m
```

**Indicadores de Kerberoasting**:
- Múltiples 4769 desde misma cuenta en poco tiempo
- Encryption type RC4 (0x17) en vez de AES
- Service accounts con SPNs

---

### Ejercicio 11: Simulación en Vivo — DLL Injection via Service

```bash
simulate dll_injection_service
```

**En Kibana**:
```kql
# Servicio instalado con DLL sospechosa
event_id: 4697 and @timestamp > now-5m

# Proceso creado por el servicio
event_id: 4688 and parent_process: *services.exe* and @timestamp > now-5m

# Correlación: servicio + proceso + conexión de red
event_id: (4697 or 4688) and @timestamp > now-5m
```

---

### Ejercicio 12: Simulación en Vivo — Ransomware Deployment

```bash
simulate ransomware
```

**En Kibana**:
```kql
# Procesos de eliminación de backups
event_id: 4688 and (command_line: *vssadmin* or command_line: *bcdedit* or command_line: *wbadmin*) and @timestamp > now-5m

# Servicios de seguridad detenidos
event_id: 4688 and command_line: (*net stop* or *sc stop*) and @timestamp > now-5m

# Scheduled task para ejecución masiva
event_id: 4698 and @timestamp > now-5m
```

---

### Ejercicio 13: Simulación en Vivo — Cadena Completa

```bash
simulate all
```

**En Kibana**:
```kql
@timestamp > now-10m
```

**Tarea**: Reconstruir la timeline completa del ataque:
1. Initial Access (brute force → logon)
2. Privilege Escalation (cuenta creada → grupo admin)
3. Credential Access (mimikatz → hashes)
4. Lateral Movement (PtH → múltiples hosts)
5. Collection (share access → datos financieros)
6. Impact (ransomware prep)

---

### Ejercicio 14: Usar el Asistente de Queries

El Lab 16 incluye un asistente de queries pre-construidas:

```bash
# Ver queries disponibles
hunt list

# Ejecutar query específica
hunt brute_force
hunt lateral_movement
hunt privilege_escalation
hunt credential_dump
hunt data_exfiltration
hunt persistence
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
- Columnas: `@timestamp`, `event_id`, `subject_user`, `target_user`, `hostname`

**Paso 4**: Agregar todo a un nuevo Dashboard "SOC Alerts"

---

### Ejercicio 16: Correlación Multi-Host

**Objetivo**: Rastrear el movimiento del atacante entre hosts.

```kql
# Paso 1: Identificar el primer host comprometido
event_id: 4624 and source_ip: "10.0.1.50" and logon_type: 10

# Paso 2: Desde ese host, buscar logons salientes
event_id: 4624 and source_ip: "10.0.1.100" and logon_type: 3

# Paso 3: Repetir para cada host descubierto
event_id: 4624 and source_ip: "10.0.1.101" and logon_type: 3
```

**Tarea**: Dibujar el mapa de movimiento lateral:
```
Atacante (10.0.1.50)
    → WS-FINANCE01 (10.0.1.100) [RDP]
        → SRV-DC01 (10.0.1.10) [PtH]
        → SRV-FILE01 (10.0.1.20) [SMB]
            → Exfiltración datos financieros
```

---

### Ejercicio 17: Resetear y Practicar

```bash
# Limpiar eventos simulados
simulate reset

# Practicar detección de un escenario específico
simulate golden_ticket

# Usar el hunt helper para verificar
hunt credential_dump
```

---

## Mapeo MITRE ATT&CK

| Técnica | ID | Event IDs | Query KQL |
|---------|-----|-----------|-----------|
| Brute Force | T1110 | 4625, 4624 | `event_id: 4625` (>10 en 5min) |
| Valid Accounts | T1078 | 4624 | `event_id: 4624 and logon_type: 10` |
| Create Account | T1136 | 4720 | `event_id: 4720` |
| Account Manipulation | T1098 | 4732 | `event_id: 4732` |
| Pass-the-Hash | T1550.002 | 4776, 4624 | `event_id: 4776` |
| Golden Ticket | T1558.001 | 4768 | `event_id: 4768` (lifetime anómalo) |
| Kerberoasting | T1558.003 | 4769 | `event_id: 4769 and encryption_type: "0x17"` |
| Service Execution | T1569.002 | 4697 | `event_id: 4697` |
| Scheduled Task | T1053.005 | 4698 | `event_id: 4698` |
| Network Share | T1039 | 5145 | `event_id: 5145 and share_name: *C$*` |

---

## Cadena de Ataque

```
Password Spray (4625 ×50 → 4624)
    │
    ▼
Initial Access — RDP (4624, Logon Type 10)
    │
    ▼
Privilege Escalation (4720 + 4732 → Administrators)
    │
    ▼
Credential Dumping (4688: mimikatz → 4776: NTLM hashes)
    │
    ▼
Lateral Movement — Pass-the-Hash (4624 Type 3 + 4776)
    │
    ▼
Golden Ticket (4768 → Domain Admin)
    │
    ▼
Data Access (5145 → C$ shares → financial data)
    │
    ▼
Ransomware Prep (4688: vssadmin + bcdedit + 4697: service)
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
| No hay datos | Verificar data view: `winevt-security*` en Management → Data Views |
| `simulate` no responde | Verificar ES: `curl http://elasticsearch:9200` desde el contenedor |
| `hunt` da error | Verificar que el índice existe: `curl http://elasticsearch:9200/winevt-security/_count` |
| Eventos simulados no aparecen | Refrescar Kibana (F5), ajustar tiempo a "Last 15 minutes" |
| Error vm.max_map_count | `sudo sysctl -w vm.max_map_count=262144` en el host |
| Puerto 5601 en uso | Verificar con `lsof -i :5601` y detener el proceso conflictivo |
