# Lab 17 — Hunting con Osquery
## Curso: MAR404 — Cacería de Amenazas
## Clase: 09

---

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha recibido una alerta de comportamiento anómalo proveniente de un endpoint crítico de la organización. Se sospecha que un actor de amenazas ha logrado comprometer el sistema, estableciendo persistencia y abriendo canales de comunicación hacia el exterior. Como Threat Hunter, tu misión es utilizar Osquery para interrogar el sistema operativo, identificar los procesos maliciosos, descubrir las tareas programadas ocultas y rastrear las conexiones de red sospechosas para reconstruir la cadena de ataque.

El laboratorio incluye un **simulador de ataques en vivo** que permite inyectar nuevos indicadores de compromiso en tiempo real para practicar la detección.

## Objetivos de Aprendizaje
* Comprender el uso de Osquery como herramienta de interrogación de endpoints mediante sintaxis SQL.
* Identificar técnicas de persistencia comunes, como tareas programadas ocultas y elementos de inicio maliciosos.
* Detectar procesos ejecutándose desde rutas inusuales y conexiones de red anómalas.
* Mapear los hallazgos técnicos con las tácticas y técnicas del framework MITRE ATT&CK.
* Practicar la detección de ataques simulados en vivo (DLL injection, ransomware, credential dump, etc.).

## Requisitos Previos
* **Docker y Docker Compose:** Instalados y configurados en el sistema host.
* **Memoria RAM:** Mínimo 2 GB de RAM disponibles para el contenedor.
* **Puertos:** No se requieren puertos expuestos hacia el host, la interacción es mediante consola interactiva.

## Despliegue Paso a Paso

1. **Clonar o acceder al directorio del laboratorio:**
   ```bash
   cd clase-09/docker/lab17-osquery-hunting/
   ```

2. **Levantar el entorno:**
   ```bash
   docker compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y confirma que el contenedor `osquery-hunter` está en estado "Up".

3. **Acceder al contenedor:**
   ```bash
   docker exec -it osquery-hunter bash
   ```

4. **Iniciar Osquery:**
   ```bash
   osqueryi
   ```
   *Verificación:* Verás el prompt de Osquery (`osquery>`), listo para recibir consultas SQL.

---

## Tablas Disponibles (12)

| Tabla | Descripción | Campos Clave |
|-------|-------------|--------------|
| `processes` | Procesos activos | pid, name, path, cmdline, parent, is_elevated |
| `process_open_sockets` | Conexiones de red | pid, remote_address, remote_port, state |
| `scheduled_tasks` | Tareas programadas | name, action, hidden, username |
| `startup_items` | Items de inicio | name, path, source, status |
| `listening_ports` | Puertos en escucha | pid, port, address |
| `hash` | Hashes de archivos | path, md5, sha256, sha1 |
| `file_events` | Eventos de filesystem | target_path, action, time, size, process_pid |
| `registry` | Claves de registro | path, name, type, data, mtime |
| `drivers` | Drivers cargados | name, path, signed, manufacturer |
| `logged_in_users` | Sesiones activas | type, user, host, time |
| `process_events` | Log de ejecución | pid, path, cmdline, parent, parent_path, time |
| `dns_cache` | Cache DNS | name, type, answer, ttl, time_queried |

**Comandos útiles:**
```sql
.tables              -- Lista todas las tablas
.schema processes    -- Muestra el schema de una tabla
.count processes     -- Cuenta registros
.hunting             -- Muestra 15 queries de hunting sugeridas
.help                -- Ayuda completa
```

---

## Ejercicios de Hunting Paso a Paso

### Ejercicio 1: Detección de Procesos en Rutas Inusuales (Masquerading)
**Hipótesis:** Los atacantes ejecutan binarios con nombres legítimos (svchost.exe, lsass.exe) desde rutas no estándar para evadir detección.

**Query:**
```sql
SELECT pid, name, path, parent FROM processes 
WHERE path NOT LIKE 'C:\Windows\System32%' 
  AND path NOT LIKE 'C:\Windows\SysWOW64%'
  AND path NOT LIKE 'C:\Program Files%' 
  AND path NOT LIKE 'C:\Windows\explorer.exe'
  AND path != '' AND name IN ('svchost.exe','lsass.exe','csrss.exe','services.exe');
```

**Qué buscar:** Procesos como `svchost.exe` ejecutándose desde `C:\Users\Public\` o `C:\Windows\Temp\`.

**Preguntas de Análisis:**
1. ¿Qué proceso sospechoso encontraste y desde qué ruta se ejecuta?
2. ¿Por qué un atacante elegiría usar el nombre `svchost.exe`?
3. ¿Cuál es el PID padre de este proceso? ¿Es coherente con un svchost legítimo?

**Respuestas Esperadas:**
1. `svchost.exe` (PID 7788) ejecutándose desde `C:\Users\Public\svchost.exe` — un svchost legítimo SIEMPRE está en `C:\Windows\System32\`.
2. Porque `svchost.exe` es uno de los procesos más comunes en Windows y los analistas podrían ignorarlo. Técnica MITRE T1036.005 (Masquerading).
3. Su padre es PID 2400 (`explorer.exe`), lo cual es anómalo — un svchost legítimo siempre es hijo de `services.exe` (PID 800).

---

### Ejercicio 2: Anomalías Parent-Child
**Hipótesis:** Los procesos legítimos de Windows tienen relaciones padre-hijo bien definidas. Una violación indica compromiso.

**Query:**
```sql
SELECT p.pid, p.name, p.path, p.parent, pp.name as parent_name, pp.path as parent_path
FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid
WHERE p.name = 'svchost.exe' AND pp.name != 'services.exe';
```

**Qué buscar:** Instancias de `svchost.exe` cuyo padre NO sea `services.exe`.

---

### Ejercicio 3: Conexiones C2 (Command & Control)
**Hipótesis:** El malware establece conexiones salientes hacia IPs externas para recibir comandos.

**Query:**
```sql
SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port 
FROM processes p JOIN process_open_sockets s ON p.pid = s.pid 
WHERE s.remote_address NOT LIKE '10.%' 
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.16.%'
  AND s.remote_address != '127.0.0.1';
```

**Qué buscar:** Procesos sospechosos (svchost falso, rundll32, notepad) con conexiones a IPs como `198.51.100.10` o `203.0.113.50` en puertos como 443, 4444, 8443.

**Preguntas de Análisis:**
1. ¿Cuántas IPs externas sospechosas identificas?
2. ¿Por qué `notepad.exe` (PID 9800) tiene una conexión de red? ¿Qué técnica indica esto?
3. ¿Qué proceso tiene conexión al puerto 4444?

**Respuestas Esperadas:**
1. Tres IPs C2: `198.51.100.10`, `203.0.113.50`, y `185.220.101.45` (si se ejecutó DLL injection).
2. Notepad.exe con conexión de red indica **Process Hollowing** (T1055.012) — el proceso fue vaciado y reemplazado con código malicioso.
3. `rundll32.exe` (PID 8500) conectado a `203.0.113.50:4444` — típico de Meterpreter reverse shell.

---

### Ejercicio 4: Persistencia — Tareas Programadas Ocultas
**Hipótesis:** Los atacantes crean tareas programadas ocultas para mantener acceso tras reinicio.

**Query:**
```sql
SELECT name, action, hidden, username FROM scheduled_tasks 
WHERE hidden = 1 OR action LIKE '%Users%' OR action LIKE '%Temp%';
```

**Qué buscar:** Tareas con `hidden = 1` o que ejecutan binarios desde rutas sospechosas.

---

### Ejercicio 5: Persistencia — Registry Run Keys
**Hipótesis:** Las claves de registro Run se usan para ejecutar malware al inicio de sesión.

**Query:**
```sql
SELECT path, name, data, mtime FROM registry 
WHERE path LIKE '%CurrentVersion\Run%' 
  AND data LIKE '%Users%';
```

**Qué buscar:** Entradas que apunten a `C:\Users\Public\svchost.exe` o `rundll32.exe` con DLLs en Temp.

---

### Ejercicio 6: Drivers Sin Firma (Rootkit Detection)
**Hipótesis:** Los rootkits cargan drivers sin firma digital para operar a nivel kernel.

**Query:**
```sql
SELECT name, path, manufacturer FROM drivers WHERE signed = 0;
```

**Qué buscar:** Drivers sin firma con nombres similares a legítimos (`WdFilter2`, `tcplp`).

---

### Ejercicio 7: LOLBins en Uso
**Hipótesis:** Los atacantes abusan de binarios legítimos de Windows (Living-off-the-Land) para evadir detección.

**Query:**
```sql
SELECT pid, name, cmdline, parent, start_time FROM processes 
WHERE name IN ('certutil.exe','mshta.exe','WMIC.exe','bitsadmin.exe','rundll32.exe','regsvr32.exe');
```

**Qué buscar:**
- `certutil.exe` con `-urlcache` (descarga de payloads)
- `mshta.exe` con URLs (ejecución de HTA malicioso)
- `WMIC.exe` con `/node:` (ejecución remota)
- `bitsadmin.exe` con `/transfer` (descarga persistente)

---

### Ejercicio 8: PowerShell Sospechoso
**Hipótesis:** PowerShell con flags como `-enc`, `-w hidden`, `IEX`, o `DownloadString` indica ejecución maliciosa.

**Query:**
```sql
SELECT pid, cmdline, parent, start_time FROM processes 
WHERE name = 'powershell.exe' 
  AND (cmdline LIKE '%-enc%' OR cmdline LIKE '%-w hidden%' OR cmdline LIKE '%DownloadString%' OR cmdline LIKE '%IEX%');
```

---

### Ejercicio 9: Cadena de Ejecución Completa (Process Tree)
**Hipótesis:** Reconstruir la cadena de ejecución revela la secuencia completa del ataque.

**Query:**
```sql
SELECT pe.eid, pe.pid, pe.path, pe.cmdline, pe.parent, pe.parent_path, pe.time
FROM process_events pe ORDER BY pe.time;
```

**Qué buscar:** La secuencia temporal: `explorer.exe` → `svchost.exe` (falso) → `powershell.exe` → `rundll32.exe` / `cmd.exe` / `certutil.exe` / etc.

---

### Ejercicio 10: DNS Sospechoso (DGA Detection)
**Hipótesis:** Los dominios generados algorítmicamente (DGA) tienen alta entropía y TLDs inusuales.

**Query:**
```sql
SELECT name, answer, time_queried FROM dns_cache 
WHERE length(name) > 20 OR name LIKE '%.xyz' OR name LIKE '%.top'
ORDER BY time_queried DESC;
```

**Qué buscar:** Dominios como `xkjh7f2m9p.com`, `m3kf9x2lp7.net` que resuelven a la misma IP C2.

---

### Ejercicio 11: Credential Access
**Hipótesis:** Herramientas como Mimikatz acceden a lsass.exe o extraen SAM.

**Query:**
```sql
SELECT pid, name, path, cmdline FROM processes 
WHERE cmdline LIKE '%lsass%' OR cmdline LIKE '%SAM%' OR cmdline LIKE '%sekurlsa%'
  OR name = 'procdump.exe' OR (name = 'lsass.exe' AND path NOT LIKE '%System32%');
```

**Qué buscar:** Un segundo `lsass.exe` ejecutándose desde `C:\Windows\Temp\` (PID 9200).

---

### Ejercicio 12: Windows Defender Deshabilitado
**Hipótesis:** Los atacantes deshabilitan el antivirus antes de ejecutar payloads.

**Query:**
```sql
SELECT path, name, data, mtime FROM registry 
WHERE (name LIKE '%Disable%' AND data = '1') 
  AND path LIKE '%Defender%';
```

**Qué buscar:** `DisableAntiSpyware = 1` y `DisableRealtimeMonitoring = 1`.

---

## Simulador de Ataques en Vivo

El lab incluye un simulador que inyecta nuevos indicadores de compromiso en la base de datos para practicar detección en tiempo real.

### Comandos del Simulador
```bash
simulate list                  # Ver todos los escenarios disponibles
simulate <escenario>           # Ejecutar un escenario específico
simulate all                   # Ejecutar TODOS los escenarios
simulate reset                 # Reiniciar la BD al estado original
```

### Escenarios Disponibles (15)

| Escenario | Técnica MITRE | Descripción |
|-----------|---------------|-------------|
| `dll_injection` | T1055.001 | Inyección de DLL maliciosa en explorer.exe |
| `ransomware` | T1486 | Cifrado masivo + borrado de shadow copies |
| `credential_dump` | T1003.001 | Mimikatz renombrado accediendo a LSASS |
| `reverse_shell` | T1059.004 | PowerShell reverse shell hacia C2 |
| `lateral_movement` | T1021.002 | PsExec hacia otro host de la red |
| `persistence_registry` | T1547.001 | Persistencia via Registry Run Key |
| `persistence_schtask` | T1053.005 | Tarea programada para persistencia |
| `lolbin_certutil` | T1105 | certutil.exe descargando payload |
| `lolbin_mshta` | T1218.005 | mshta.exe ejecutando HTA malicioso |
| `lolbin_wmic` | T1047 | WMIC ejecución remota |
| `data_exfiltration` | T1048.002 | Exfiltración de datos via HTTPS |
| `fileless_powershell` | T1059.001 | Payload en memoria sin tocar disco |
| `defender_disable` | T1562.001 | Deshabilitación de Windows Defender |
| `process_hollowing` | T1055.012 | Process hollowing en svchost.exe |
| `dga_communication` | T1568.002 | Comunicación con dominios DGA |

### Ejemplo de Uso del Simulador

```bash
# 1. Simular un ataque de DLL Injection
simulate dll_injection

# 2. Abrir osqueryi para detectarlo
osqueryi

# 3. Buscar el indicador
SELECT pid, name, path FROM processes WHERE path LIKE '%AppData%Roaming%';
SELECT target_path, action FROM file_events WHERE category = 'suspicious' AND target_path LIKE '%.dll';
SELECT p.pid, p.name, s.remote_address FROM processes p JOIN process_open_sockets s ON p.pid = s.pid WHERE p.pid = 2400;
```

### Flujo de Trabajo Recomendado

1. **Ejecutar un escenario:** `simulate ransomware`
2. **Leer las pistas** que el simulador imprime en pantalla
3. **Abrir osqueryi** y escribir queries para detectar los indicadores
4. **Documentar hallazgos** con técnica MITRE correspondiente
5. **Repetir** con otro escenario o ejecutar `simulate all` para un desafío completo

---

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre | Evidencia en el Laboratorio |
|:---|:---|:---|
| T1036.005 | Masquerading: Match Legitimate Name | `svchost.exe` desde `C:\Users\Public\` |
| T1055.001 | Process Injection: DLL Injection | `injector.exe` inyectando DLL en explorer.exe |
| T1055.012 | Process Hollowing | `notepad.exe` con conexión de red (hollowed) |
| T1071.001 | Application Layer Protocol: Web | Conexiones C2 en puerto 443 |
| T1053.005 | Scheduled Task | Tarea oculta `WindowsDefenderUpdate` |
| T1547.001 | Registry Run Keys | Persistencia en `HKLM\...\Run` |
| T1003.001 | LSASS Memory | `lsass.exe` falso desde Temp |
| T1486 | Data Encrypted for Impact | Archivos `.encrypted` / `.locked` |
| T1218.005 | Mshta | `mshta.exe` ejecutando HTA remoto |
| T1105 | Ingress Tool Transfer | `certutil.exe -urlcache` |
| T1562.001 | Disable or Modify Tools | Defender deshabilitado via registro |
| T1568.002 | Domain Generation Algorithms | Dominios DGA en dns_cache |

---

## Cadena de Ataque Completa (Dataset Base)

```text
[Compromiso Inicial]           [Ejecución]              [Persistencia]
  Phishing → explorer.exe  →  svchost.exe (falso)  →  Scheduled Task (hidden)
                                    |                   Registry Run Key
                                    v
                              [Post-Explotación]
                              powershell -enc → rundll32 (DLL) → cmd (recon)
                                    |              |
                                    v              v
                              [Credential Access]  [Lateral Movement]
                              lsass.exe (falso)    WMIC /node:10.0.1.100
                                    |
                                    v
                              [C2 Communication]
                              198.51.100.10:443 (principal)
                              203.0.113.50:4444 (exfiltración)
                              DGA domains → misma IP C2
```

---

## Limpieza

```bash
# Salir de osqueryi
.quit

# Salir del contenedor
exit

# Detener y eliminar
docker compose down
```

---

## Troubleshooting

* **Problema:** `osqueryi` no devuelve resultados.
  **Solución:** Verifica la sintaxis SQL (terminar con `;`). Usa `.tables` para ver tablas disponibles.
* **Problema:** `simulate` no se reconoce como comando.
  **Solución:** Asegúrate de estar dentro del contenedor (`docker exec -it osquery-hunter bash`).
* **Problema:** Después de `simulate reset`, los escenarios anteriores desaparecen.
  **Solución:** Esto es intencional — `reset` regenera la BD al estado original. Vuelve a ejecutar los escenarios que necesites.
* **Problema:** Las queries no encuentran los eventos simulados.
  **Solución:** Sal de `osqueryi` (`.quit`) y vuelve a entrar para que la BD se recargue con los nuevos datos.
