# Lab 18 — Sigma Rules: Escritura, Conversión y Validación
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 09

---

## Descripción del Escenario
El equipo de Threat Intelligence ha recibido un reporte sobre una nueva campaña de malware que utiliza técnicas de evasión de defensas y robo de credenciales. Se han recolectado varios eventos de logs de sistemas comprometidos, pero el equipo de SOC no tiene reglas de detección para estos comportamientos. Tu misión como Threat Hunter es analizar los eventos de prueba, escribir reglas Sigma para detectar estas tácticas, convertirlas a consultas específicas para los SIEMs de la organización, y validar su efectividad contra un dataset de ataques simulados.

El laboratorio incluye un **sistema de trigger y validación en vivo** que permite disparar escenarios de ataque y verificar automáticamente qué reglas Sigma los detectan.

## Objetivos de Aprendizaje
- Comprender la estructura y sintaxis de las reglas Sigma.
- Escribir reglas Sigma personalizadas para detectar comportamientos maliciosos específicos.
- Utilizar `sigma-cli` para validar y convertir reglas Sigma a diferentes lenguajes de consulta (Elasticsearch, Splunk).
- Disparar escenarios de ataque en vivo y validar la cobertura de detección.
- Analizar falsos positivos y ajustar reglas para minimizarlos.

## Requisitos Previos
- **Docker y Docker Compose:** Instalados y configurados en el sistema host.
- **RAM:** Mínimo 1 GB de RAM disponible.
- **Puertos:** No se requieren puertos expuestos, todo el trabajo se realiza dentro del contenedor.

## Despliegue Paso a Paso

1. **Iniciar el entorno:**
   ```bash
   cd clase-09/docker/lab18-sigma-rules/
   docker compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y asegúrate de que el contenedor `sigma-analyst` esté en estado "Up".

2. **Acceder al contenedor:**
   ```bash
   docker exec -it sigma-analyst bash
   ```

3. **Verificar herramientas:**
   ```bash
   sigma version
   jq --version
   trigger list
   ```
   *Verificación:* Los tres comandos deben funcionar sin errores.

---

## Reglas Sigma Incluidas (16)

El laboratorio viene con 16 reglas Sigma pre-escritas en `/app/rules/`:

| Regla | Técnica MITRE | Descripción |
|-------|---------------|-------------|
| `example_mimikatz.yml` | T1003.001 | Acceso a LSASS (credential dumping) |
| `powershell_encoded.yml` | T1059.001 | PowerShell con comandos encoded (-enc) |
| `certutil_download.yml` | T1105 | certutil.exe descargando archivos |
| `schtasks_persistence.yml` | T1053.005 | Tareas programadas sospechosas |
| `service_from_temp.yml` | T1543.003 | Servicios instalados desde Temp |
| `dns_suspicious_tld.yml` | T1568.002 | DNS queries a TLDs sospechosos |
| `mshta_execution.yml` | T1218.005 | mshta.exe con URLs/scripts |
| `wmi_lateral_movement.yml` | T1047 | WMIC ejecución remota |
| `ransomware_shadow_delete.yml` | T1490 | Borrado de shadow copies |
| `bitsadmin_download.yml` | T1197 | BITS transfer sospechoso |
| `registry_run_persistence.yml` | T1547.001 | Persistencia via reg.exe + Run key |
| `psexec_lateral.yml` | T1021.002 | PsExec lateral movement |
| `defender_disabled.yml` | T1562.001 | Deshabilitación de Defender |
| `rundll32_suspicious.yml` | T1218.011 | rundll32 cargando DLLs sospechosas |
| `wevtutil_clear_logs.yml` | T1070.001 | Borrado de logs con wevtutil |
| `ntdsutil_credential.yml` | T1003.003 | Extracción de NTDS.dit |

---

## Ejercicios Paso a Paso

### Ejercicio 1: Análisis de Eventos y Detección de Mimikatz

**Hipótesis:** Los atacantes utilizan herramientas como Mimikatz para extraer credenciales de la memoria. Si un atacante accede a LSASS, veremos eventos con `GrantedAccess` específicos.

**Comandos:**
```bash
# 1. Inspeccionar eventos de acceso a LSASS en el dataset
cat /app/test_events.json | jq '.[] | select(.EventID == 10 and (.TargetImage | test("lsass"; "i")))'

# 2. Validar la regla de ejemplo
sigma check rules/example_mimikatz.yml

# 3. Convertir a Splunk
sigma convert -t splunk -p sysmon rules/example_mimikatz.yml

# 4. Convertir a Elasticsearch
sigma convert -t elasticsearch -p ecs_windows rules/example_mimikatz.yml
```

**Qué buscar:**
- Eventos con `TargetImage` = `lsass.exe` y `GrantedAccess` = `0x1010` o `0x1038`
- Excluir procesos legítimos como `wmiprvse.exe`, `taskmgr.exe`

**Preguntas de Análisis:**
1. ¿Qué `SourceImage` está accediendo a LSASS con permisos sospechosos?
2. ¿Por qué `GrantedAccess: 0x1010` es un indicador de Mimikatz?
3. ¿Cómo modificarías la regla para reducir falsos positivos?

**Respuestas Esperadas:**
1. Un ejecutable renombrado (ej. `debug.exe`) desde `C:\Windows\Temp\` — Mimikatz renombrado.
2. `0x1010` = `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` — los permisos mínimos para leer la memoria de LSASS.
3. Agregar exclusiones para procesos legítimos conocidos y filtrar por `SourceImage` no estándar.

---

### Ejercicio 2: Creación de Regla para Evasión de Defensas (Borrado de Logs)

**Hipótesis:** Los atacantes borran logs de eventos Windows para ocultar sus rastros.

**Comandos:**
```bash
# 1. Buscar eventos de wevtutil en el dataset
cat /app/test_events.json | jq '.[] | select(.Image | test("wevtutil"; "i"))'

# 2. Examinar la regla existente
cat rules/wevtutil_clear_logs.yml

# 3. Validar y convertir
sigma check rules/wevtutil_clear_logs.yml
sigma convert -t splunk -p sysmon rules/wevtutil_clear_logs.yml
sigma convert -t elasticsearch -p ecs_windows rules/wevtutil_clear_logs.yml
```

**Ejercicio práctico — Crear tu propia regla:**
```bash
nano rules/my_clear_logs.yml
```

Escribe una regla que detecte TANTO `wevtutil cl` como `wevtutil clear-log`:
```yaml
title: Borrado de Logs via Wevtutil (Variantes)
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: experimental
description: Detecta borrado de logs usando wevtutil con variantes cl y clear-log.
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\wevtutil.exe'
    selection_cmd:
        CommandLine|contains:
            - 'cl '
            - 'clear-log'
    condition: selection_image and selection_cmd
falsepositives:
    - Scripts de mantenimiento legítimos del administrador.
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.001
```

---

### Ejercicio 3: Detección de PowerShell Encoded

**Hipótesis:** PowerShell con `-enc` o `-EncodedCommand` es un fuerte indicador de ejecución maliciosa.

**Comandos:**
```bash
# 1. Buscar PowerShell encoded en el dataset
cat /app/test_events.json | jq '.[] | select(.CommandLine | test("-enc"; "i"))'

# 2. Examinar la regla
cat rules/powershell_encoded.yml

# 3. Convertir a múltiples backends
sigma convert -t splunk -p sysmon rules/powershell_encoded.yml
sigma convert -t elasticsearch -p ecs_windows rules/powershell_encoded.yml
```

**Preguntas:**
1. ¿Cuántos eventos de PowerShell encoded hay en el dataset?
2. ¿Cuáles son los `ParentImage` de estos procesos? ¿Son legítimos?
3. ¿Cómo decodificarías el contenido del parámetro `-enc`?

---

### Ejercicio 4: Detección de Ransomware (Shadow Copy Deletion)

**Hipótesis:** Antes de cifrar archivos, el ransomware elimina las shadow copies para impedir la recuperación.

**Comandos:**
```bash
# 1. Buscar eventos de borrado de shadow copies
cat /app/test_events.json | jq '.[] | select(.CommandLine | test("shadow|vssadmin|shadowcopy"; "i"))'

# 2. Examinar la regla
cat rules/ransomware_shadow_delete.yml

# 3. La regla detecta 3 variantes:
#    - vssadmin.exe delete shadows
#    - wmic shadowcopy delete
#    - PowerShell Win32_ShadowCopy
sigma convert -t splunk -p sysmon rules/ransomware_shadow_delete.yml
```

---

## Sistema de Trigger y Validación en Vivo

### Comandos del Trigger
```bash
trigger list                    # Ver escenarios disponibles
trigger <escenario>             # Disparar un escenario específico
trigger all                     # Disparar todos los escenarios
trigger validate                # Validar dataset contra TODAS las reglas
trigger validate <regla.yml>    # Validar contra una regla específica
```

### Escenarios Disponibles (6)

| Escenario | Descripción | Reglas que Deben Alertar |
|-----------|-------------|--------------------------|
| `apt_initial_access` | Macro maliciosa → PowerShell encoded | `powershell_encoded` |
| `ransomware_attack` | Shadow delete + clear logs + PS encoded | `ransomware_shadow_delete`, `wevtutil_clear_logs`, `powershell_encoded` |
| `lateral_movement_chain` | PsExec + WMI remoto | `psexec_lateral`, `wmi_lateral_movement` |
| `data_exfiltration` | certutil download + BITS upload | `certutil_download`, `bitsadmin_download` |
| `defense_evasion_full` | Disable Defender + clear logs | `defender_disabled`, `wevtutil_clear_logs` |
| `credential_theft` | LSASS access + ntdsutil | `example_mimikatz`, `ntdsutil_credential` |

### Flujo de Trabajo Recomendado

```bash
# 1. Disparar un escenario de ataque
trigger ransomware_attack

# 2. Validar qué reglas lo detectan
trigger validate

# 3. Ver el resultado:
#    [✓] ransomware_shadow_delete.yml → 1 true positive
#    [✓] wevtutil_clear_logs.yml → 1 true positive
#    [✓] powershell_encoded.yml → 1 true positive
#    [○] certutil_download.yml → NO MATCH (correcto, no aplica)

# 4. Disparar todos los escenarios
trigger all

# 5. Validar cobertura completa
trigger validate
```

### Ejemplo Completo: Detectar APT Initial Access

```bash
# Paso 1: Disparar el escenario
trigger apt_initial_access

# Paso 2: Ver qué eventos se insertaron
cat /app/test_events.json | jq '.[] | select(.scenario == "apt_initial_access")'

# Paso 3: Validar contra la regla de PowerShell encoded
trigger validate powershell_encoded.yml

# Paso 4: Convertir la regla a query de Elasticsearch para buscar en el SIEM
sigma convert -t elasticsearch -p ecs_windows rules/powershell_encoded.yml
```

---

### Ejercicio 5: Crear una Regla Nueva y Validarla

**Desafío:** Crear una regla Sigma para detectar `certutil.exe` descargando archivos.

```bash
# 1. Ver qué eventos de certutil hay
cat /app/test_events.json | jq '.[] | select(.Image | test("certutil"; "i"))'

# 2. Crear tu regla
nano rules/my_certutil_rule.yml
```

```yaml
title: Certutil Download Abuse
id: c3d4e5f6-a7b8-9012-3456-789012abcdef
status: experimental
description: Detecta uso de certutil para descargar archivos remotos.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: 'urlcache'
    condition: selection
falsepositives:
    - Administradores descargando certificados legítimos.
level: high
tags:
    - attack.command_and_control
    - attack.t1105
```

```bash
# 3. Validar sintaxis
sigma check rules/my_certutil_rule.yml

# 4. Disparar el escenario de exfiltración
trigger data_exfiltration

# 5. Validar que tu regla detecta el evento
trigger validate my_certutil_rule.yml

# 6. Convertir a Splunk y Elasticsearch
sigma convert -t splunk -p sysmon rules/my_certutil_rule.yml
sigma convert -t elasticsearch -p ecs_windows rules/my_certutil_rule.yml
```

---

### Ejercicio 6: Análisis de Falsos Positivos

**Objetivo:** Entender por qué las reglas pueden generar falsos positivos y cómo ajustarlas.

```bash
# 1. Validar todas las reglas contra el dataset completo
trigger validate

# 2. Buscar reglas con FP (marcadas con ✗)
# Si una regla marca un evento benigno como malicioso, aparecerá como FP

# 3. Examinar los eventos benignos del dataset
cat /app/test_events.json | jq '.[] | select(.should_trigger == "NONE_FP")'

# 4. Ajustar la regla para excluir falsos positivos
# Ejemplo: agregar exclusiones en la sección 'filter' de la regla
```

---

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre | Regla Sigma | Escenario |
|:---|:---|:---|:---|
| T1003.001 | LSASS Memory | `example_mimikatz.yml` | `credential_theft` |
| T1003.003 | NTDS.dit | `ntdsutil_credential.yml` | `credential_theft` |
| T1021.002 | SMB/Admin Shares | `psexec_lateral.yml` | `lateral_movement_chain` |
| T1047 | WMI | `wmi_lateral_movement.yml` | `lateral_movement_chain` |
| T1053.005 | Scheduled Task | `schtasks_persistence.yml` | — |
| T1059.001 | PowerShell | `powershell_encoded.yml` | `apt_initial_access`, `ransomware_attack` |
| T1070.001 | Clear Event Logs | `wevtutil_clear_logs.yml` | `ransomware_attack`, `defense_evasion_full` |
| T1105 | Ingress Tool Transfer | `certutil_download.yml` | `data_exfiltration` |
| T1197 | BITS Jobs | `bitsadmin_download.yml` | `data_exfiltration` |
| T1218.005 | Mshta | `mshta_execution.yml` | — |
| T1218.011 | Rundll32 | `rundll32_suspicious.yml` | — |
| T1490 | Inhibit System Recovery | `ransomware_shadow_delete.yml` | `ransomware_attack` |
| T1543.003 | Windows Service | `service_from_temp.yml` | — |
| T1547.001 | Registry Run Keys | `registry_run_persistence.yml` | — |
| T1562.001 | Disable Tools | `defender_disabled.yml` | `defense_evasion_full` |
| T1568.002 | DGA | `dns_suspicious_tld.yml` | — |

---

## Cadena de Ataque Completa

```text
[Initial Access]                    [Execution]                [Persistence]
 apt_initial_access:          ransomware_attack:           schtasks_persistence
 Word macro → PS encoded      vssadmin delete shadows      registry_run_persistence
                              wevtutil cl Security
        |                           |                            |
        v                           v                            v
[Credential Access]           [Defense Evasion]           [Lateral Movement]
 credential_theft:            defense_evasion_full:       lateral_movement_chain:
 LSASS access (0x1010)       Disable Defender            PsExec + WMI /node:
 ntdsutil ifm                wevtutil clear-log
        |                           |                            |
        v                           v                            v
[Exfiltration]               [Impact]                    [C2 Communication]
 data_exfiltration:          ransomware_attack:          dns_suspicious_tld
 certutil download           File encryption             DGA domains
 BITS upload
```

---

## Limpieza
```bash
# Salir del contenedor
exit

# Detener y eliminar
docker compose down
```

---

## Troubleshooting

- **Problema:** `sigma: command not found` dentro del contenedor.
  **Solución:** Asegúrate de estar dentro del contenedor `sigma-analyst` (`docker exec -it sigma-analyst bash`).
- **Problema:** `trigger: command not found`.
  **Solución:** Verifica que estás dentro del contenedor correcto. El comando `trigger` es un wrapper instalado durante el build.
- **Problema:** Error al convertir: `Pipeline sysmon is not supported`.
  **Solución:** Usa `-p ecs_windows` para Elasticsearch o `-p sysmon` para Splunk. Lista pipelines con `sigma list pipelines`.
- **Problema:** `trigger validate` muestra "NO MATCH" para todas las reglas.
  **Solución:** Primero ejecuta `trigger all` o un escenario específico para insertar eventos en el dataset.
- **Problema:** `jq` devuelve error de parseo.
  **Solución:** Verifica que `/app/test_events.json` existe y tiene formato JSON válido. Si se corrompió, ejecuta `trigger all` para regenerar.
- **Problema:** La regla Sigma falla la validación con `sigma check`.
  **Solución:** Revisa la indentación YAML (no uses tabs). Campos requeridos: `title`, `logsource`, `detection`, `condition`.
