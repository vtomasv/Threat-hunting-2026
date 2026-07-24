# Laboratorio 19 — Análisis Forense de Artefactos Windows

## Curso MAR404 — Cacería de Amenazas (Threat Hunter) | Clase 10
### Universidad Mayor 2026

---

## Información del Laboratorio

| Campo | Detalle |
|-------|---------|
| **Código** | LAB-19 |
| **Duración estimada** | 2.5 — 3 horas |
| **Nivel** | Avanzado |
| **Prerequisitos** | Clases 1-9 completadas, conocimientos de Windows Internals |
| **Plataforma** | Docker + noVNC (ARM64 / AMD64) |
| **Acceso** | `http://localhost:6080/vnc.html` — Password: `hunter2026` |

---

## Hipótesis de Caza

> El equipo de SOC ha detectado actividad anómala en un endpoint Windows crítico (Hostname: **SRV-FIN-01**). Las alertas iniciales indican posibles ejecuciones de herramientas de post-explotación y descargas sospechosas. El equipo de respuesta a incidentes ha recolectado artefactos forenses clave del sistema comprometido, incluyendo **Prefetch**, **Amcache**, **UserAssist** y la **MFT** (Master File Table). Tu misión como Threat Hunter es analizar estos artefactos para reconstruir la línea de tiempo del ataque, identificar las herramientas utilizadas por el adversario y descubrir técnicas de evasión de defensas como el **timestomping**.

---

## Objetivos de Aprendizaje

Al completar este laboratorio, el estudiante será capaz de:

1. Comprender la estructura y contenido de los principales artefactos forenses de Windows (Prefetch, Amcache, UserAssist, MFT).
2. Utilizar herramientas de parsing para extraer información de ejecución de programas.
3. Detectar el uso de LOLBins (Living Off the Land Binaries) como vectores de descarga.
4. Identificar técnicas de masquerading (T1036.005) mediante análisis de paths y hashes.
5. Detectar timestomping (T1070.006) comparando atributos `$STANDARD_INFORMATION` vs `$FILE_NAME` en la MFT.
6. Construir una línea de tiempo consolidada del ataque correlacionando múltiples fuentes de evidencia.
7. Mapear las actividades del atacante al framework MITRE ATT&CK.

---

## Contexto del Caso

El servidor **SRV-FIN-01** es un Windows Server 2019 que aloja aplicaciones financieras críticas en el dominio `CORPFINANCE.local`. El 15 de julio de 2026, CrowdStrike Falcon generó una alerta crítica: un proceso `svchost.exe` fue spawneado desde un parent process inusual (`WINWORD.EXE`). Alertas adicionales de Cortex XDR y Microsoft Defender for Endpoint confirmaron actividad de descarga con `certutil.exe` y acceso a LSASS.

El equipo de IR aisló el servidor y recolectó artefactos con **KAPE** (Kroll Artifact Parser and Extractor). Tu trabajo como Threat Hunter es analizar la evidencia recolectada.

---

## Despliegue del Laboratorio

### Requisitos del Sistema

- Docker Desktop 4.x o superior
- Docker Compose v2
- Mínimo 4 GB de RAM disponible
- Puertos 6080 y 5901 disponibles

### Paso 1: Clonar o acceder al directorio

```bash
cd clase-10-labs/lab19-forensic-artifacts/
```

### Paso 2: Construir y levantar el entorno

```bash
docker-compose up -d --build
```

Este comando construirá la imagen Docker con todas las herramientas forenses y generará automáticamente la evidencia del caso. El proceso toma aproximadamente 2-3 minutos la primera vez.

### Paso 3: Verificar que el contenedor está corriendo

```bash
docker ps | grep lab19
```

Deberías ver el contenedor `lab19-forensic-workstation` en estado "Up".

### Paso 4: Acceder al escritorio gráfico

Abre tu navegador web y navega a:

```
http://localhost:6080/vnc.html
```

Ingresa la contraseña: `hunter2026`

Verás un escritorio XFCE4 con un terminal disponible. En el escritorio encontrarás la carpeta `Lab19-ForensicArtifacts` con enlaces a la evidencia y las herramientas.

### Paso 5: Verificación inicial (dentro del contenedor)

Abre una terminal en el escritorio (clic derecho → "Open Terminal Here") y ejecuta:

```bash
bash /tools/scripts/hunt_helper.sh status
```

Esto mostrará el estado de toda la evidencia disponible.

---

## Ejercicio 1: Reconocimiento del Caso y Evidencia Disponible (20 minutos)

### Objetivo
Familiarizarse con el caso, la estructura de evidencia y las herramientas disponibles.

### Paso 1.1: Leer el briefing del caso

```bash
bash /tools/scripts/hunt_helper.sh briefing
```

**¿Qué observar?** Lee cuidadosamente la información del caso. Anota:
- Hostname y sistema operativo del servidor comprometido
- Las alertas iniciales que dispararon la investigación
- Los artefactos que fueron recolectados

### Paso 1.2: Explorar la estructura de evidencia

```bash
tree /cases/SRV-FIN-01/ -L 2
```

**Explicación:** El comando `tree` muestra la estructura de directorios de forma jerárquica. La opción `-L 2` limita la profundidad a 2 niveles para una vista general.

### Paso 1.3: Ver el contexto completo en formato JSON

```bash
cat /cases/SRV-FIN-01/context/case_briefing.json | jq .
```

**Explicación:** `jq .` formatea el JSON de forma legible con colores. Observa los campos `initial_alert` y `additional_alerts` para entender qué disparó la investigación.

### Paso 1.4: Ejecutar Quick Wins (búsqueda rápida)

```bash
bash /tools/scripts/hunt_helper.sh quick-wins
```

**¿Qué observar?** Este script ejecuta búsquedas rápidas en todos los artefactos. Anota los primeros indicadores que aparecen — estos serán tu punto de partida para la investigación profunda.

**Pregunta para el estudiante:** ¿Cuántos archivos se ejecutaron desde paths no estándar? ¿Cuántos binarios no tienen firma digital?

---

## Ejercicio 2: Análisis de Prefetch — Reconstrucción de Ejecuciones (40 minutos)

### Contexto Teórico

Los archivos **Prefetch** (`.pf`) de Windows registran información sobre cada programa ejecutado en el sistema. Cada archivo contiene:
- Nombre del ejecutable y hash del path
- Número total de ejecuciones (run count)
- Timestamps de las últimas 8 ejecuciones
- Lista de archivos y directorios accedidos durante la ejecución
- Información del volumen

Los archivos Prefetch se almacenan en `C:\Windows\Prefetch\` y tienen el formato: `NOMBRE.EXE-HASH.pf`

**Importancia para Threat Hunting:** Un atacante que ejecuta herramientas en el sistema dejará rastros en Prefetch, incluso si elimina las herramientas después. El hash en el nombre del archivo cambia según el path de ejecución, lo que permite detectar el mismo ejecutable corriendo desde diferentes ubicaciones.

### Paso 2.1: Análisis completo de Prefetch

```bash
python3 /tools/parsers/prefetch_parser.py
```

**¿Qué observar?** La tabla muestra todos los archivos Prefetch con su categorización. Enfócate en:
- Entradas marcadas como `MAL` (maliciosas) o `SUS` (sospechosas)
- El `Run Count` — ¿cuántas veces se ejecutó cada programa?
- La `Última Ejecución` — ¿cuándo fue la última vez?

### Paso 2.2: Filtrar solo entradas sospechosas/maliciosas

```bash
python3 /tools/parsers/prefetch_parser.py --suspicious
```

**Pregunta:** ¿Por qué `SVCHOST.EXE-1A2B3C4D.pf` es diferente de `SVCHOST.EXE-3530F672.pf`? La respuesta está en el hash del path: el hash `1A2B3C4D` corresponde a `\Users\Public\Downloads\` mientras que `3530F672` corresponde a `\Windows\System32\`. Esto es **masquerading** (T1036.005).

### Paso 2.3: Detectar LOLBins abusados

```bash
python3 /tools/parsers/prefetch_parser.py --lolbins
```

**Explicación:** Los LOLBins (Living Off the Land Binaries) son herramientas legítimas de Windows que los atacantes abusan para evitar detección. `certutil.exe` y `bitsadmin.exe` son LOLBins clásicos usados para descarga de archivos (T1105).

**Pregunta:** ¿Por qué `certutil.exe` ejecutado 4 veces en 7 minutos es sospechoso? En un servidor financiero, `certutil` se usa raramente y para operaciones de certificados, no para descargas repetidas.

### Paso 2.4: Generar timeline de ejecuciones

```bash
python3 /tools/parsers/prefetch_parser.py --timeline
```

**¿Qué observar?** La timeline ordenada cronológicamente revela la secuencia del ataque:
1. WINWORD.EXE (apertura del documento malicioso)
2. POWERSHELL.EXE (ejecución de macro)
3. CERTUTIL.EXE (descarga de herramientas)
4. SVCHOST.EXE desde path anómalo (beacon C2)
5. PRINTSPOOFER64.EXE (escalación de privilegios)
6. Y así sucesivamente...

### Paso 2.5: Análisis detallado de un archivo específico

```bash
python3 /tools/parsers/prefetch_parser.py --file "CERTUTIL"
```

**¿Qué observar?** Los directorios accedidos por `certutil.exe` revelan dónde descargó los archivos: `\Users\Public\Downloads\` y `\Windows\Temp\`. Estos son los directorios de staging del atacante.

### Preguntas de Análisis — Ejercicio 2

1. ¿Cuántas herramientas diferentes descargó el atacante con certutil?
2. ¿Qué indica un `run_count = 1` para PrintSpoofer? (Pista: un exploit exitoso solo necesita ejecutarse una vez)
3. ¿Por qué `wevtutil.exe` se ejecutó exactamente 3 veces? (Pista: Security, System, PowerShell)
4. ¿Qué programa legítimo fue el punto de entrada del ataque?

---

## Ejercicio 3: Análisis de Amcache — Inventario de Aplicaciones (35 minutos)

### Contexto Teórico

**Amcache.hve** es un registry hive de Windows que mantiene un inventario de todas las aplicaciones ejecutadas. A diferencia de Prefetch, Amcache almacena:
- **SHA1 hash** del ejecutable (permite búsqueda en VirusTotal)
- **Publisher** y firma digital
- **Versión del producto**
- **Link date** (fecha de compilación del PE)
- **Timestamp de primera ejecución**

**Importancia para Threat Hunting:** Amcache proporciona hashes que pueden ser buscados en plataformas de Threat Intelligence. Un binario sin firma digital, sin publisher, y con un link date reciente es altamente sospechoso.

### Paso 3.1: Análisis completo de Amcache

```bash
python3 /tools/parsers/amcache_parser.py
```

### Paso 3.2: Identificar binarios sin firma digital

```bash
python3 /tools/parsers/amcache_parser.py --unsigned
```

**¿Qué observar?** En un entorno corporativo, la mayoría de los binarios legítimos están firmados digitalmente. Los binarios sin firma son sospechosos, especialmente si:
- Están en directorios temporales (`\Windows\Temp\`)
- Tienen un PE Checksum de `0x00000000` (no calculado)
- No tienen publisher ni versión

### Paso 3.3: Detectar masquerading comparando paths

```bash
python3 /tools/parsers/amcache_parser.py --compare-paths
```

**Concepto clave:** Si existe `svchost.exe` tanto en `C:\Windows\System32\` (legítimo, firmado por Microsoft) como en `C:\Users\Public\Downloads\` (sin firma, hash diferente), esto es **masquerading** — el atacante nombró su malware igual que un proceso legítimo para pasar desapercibido.

### Paso 3.4: Detectar anomalías avanzadas

```bash
python3 /tools/parsers/amcache_parser.py --anomalies
```

**¿Qué observar?** Las anomalías incluyen:
- Binarios sin firma en directorios de sistema
- PE Checksum = 0 (herramientas compiladas ad-hoc)
- Link date reciente (compilado días antes del ataque)
- Metadata vacía (sin publisher, sin versión)

### Paso 3.5: Exportar hashes para Threat Intelligence

```bash
python3 /tools/parsers/amcache_parser.py --hashes
```

**Siguiente paso real:** En un caso real, estos hashes se buscarían en VirusTotal, MISP, OTX AlienVault, o cualquier plataforma de TI. Aquí el estudiante debe anotar los hashes y entender por qué son valiosos como IOCs.

```bash
cat /cases/SRV-FIN-01/iocs/amcache_hashes_for_vt.txt
```

### Preguntas de Análisis — Ejercicio 3

1. ¿Cuál es la diferencia entre el `svchost.exe` legítimo y el malicioso en Amcache?
2. ¿Por qué PsExec aparece como "firmado por Microsoft" pero sigue siendo sospechoso?
3. ¿Qué indica que `mimikatz.exe` tiene language "French (France)"?
4. ¿Por qué el tamaño de `rclone.exe` (55MB) es relevante para la investigación?

---

## Ejercicio 4: Análisis de UserAssist — Programas Ejecutados via Shell (25 minutos)

### Contexto Teórico

**UserAssist** es una clave del registro de Windows que rastrea programas ejecutados por el usuario a través del shell de Windows (Explorer.exe). Los datos están codificados en **ROT13** (un cifrado de sustitución simple donde cada letra se rota 13 posiciones). UserAssist registra:
- Nombre del programa (codificado en ROT13)
- **Run count** (número de ejecuciones)
- **Focus count** (veces que la ventana tuvo el foco)
- **Focus time** (tiempo total con el foco)
- **Última ejecución** (timestamp FILETIME)

**Importancia para Threat Hunting:** El `focus_count` y `focus_time` son especialmente reveladores:
- `focus_count = 0` y `focus_time = 0` indica ejecución en **background** sin ventana visible — típico de beacons C2 y herramientas automatizadas.
- `focus_count > 0` con poco `focus_time` indica ejecución interactiva breve — típico de herramientas de post-explotación.

### Paso 4.1: Ver datos RAW (codificados en ROT13)

```bash
python3 /tools/parsers/userassist_decoder.py --raw
```

**Ejercicio educativo:** Intenta decodificar manualmente una entrada. Por ejemplo, `JVAJBEQ.RKR` en ROT13 se decodifica como `WINWORD.EXE` (W→J, I→V, N→A, W→J, O→B, R→E, D→Q... invirtiendo: J→W, V→I, A→N, etc.).

### Paso 4.2: Decodificación paso a paso

```bash
python3 /tools/parsers/userassist_decoder.py --decode
```

### Paso 4.3: Análisis completo decodificado

```bash
python3 /tools/parsers/userassist_decoder.py
```

### Paso 4.4: Análisis de Focus Time (interactivo vs background)

```bash
python3 /tools/parsers/userassist_decoder.py --focus
```

**Hallazgo crítico:** El falso `svchost.exe` tiene `focus_count = 0` y `focus_time = 0 seconds`. Esto confirma que es un beacon C2 ejecutándose en background sin interfaz gráfica. En contraste, `mimikatz.exe` tiene `focus_time = 2 minutes`, indicando que el atacante lo usó interactivamente para ejecutar comandos.

### Preguntas de Análisis — Ejercicio 4

1. ¿Por qué el atacante no puede evitar dejar rastros en UserAssist?
2. ¿Qué indica que `rclone.exe` se ejecutó con un GUID diferente al resto?
3. ¿Cómo distingues entre uso legítimo de `cmd.exe` y uso por un atacante?

---

## Ejercicio 5: Análisis de MFT y Detección de Timestomping (45 minutos)

### Contexto Teórico

La **MFT** (Master File Table) es la estructura central del sistema de archivos NTFS. Cada archivo tiene una entrada MFT con dos conjuntos de timestamps:

- **$STANDARD_INFORMATION (SI):** Timestamps que pueden ser modificados por APIs de modo usuario (como `SetFileTime()`). El atacante puede cambiarlos.
- **$FILE_NAME (FN):** Timestamps que **SOLO el kernel de Windows puede modificar**. El atacante NO puede cambiarlos sin un driver de kernel.

**Timestomping (T1070.006):** Es la técnica de modificar los timestamps SI para hacer que un archivo malicioso parezca más antiguo de lo que realmente es. El objetivo es evadir análisis forenses basados en timeline.

**Detección:** Si `SI.Created ≠ FN.Created`, especialmente si SI es significativamente más antiguo que FN, es un fuerte indicador de timestomping.

### Paso 5.1: Análisis general de la MFT

```bash
python3 /tools/parsers/mft_analyzer.py
```

**¿Qué observar?** La tabla muestra las columnas `SI Created` y `FN Created` lado a lado. Cuando son diferentes, la columna `Stomp?` muestra `YES!` en rojo.

### Paso 5.2: Detección específica de timestomping

```bash
python3 /tools/parsers/mft_analyzer.py --timestomp
```

**Este es el ejercicio más importante del laboratorio.** Para cada archivo con timestomping detectado, observa:
- La diferencia en años entre SI y FN
- Qué timestamp "falso" eligió el atacante (¿copió de un archivo legítimo?)
- Los flags del archivo (Hidden, System = intento adicional de ocultamiento)

### Paso 5.3: Ver archivos eliminados (recuperables)

```bash
python3 /tools/parsers/mft_analyzer.py --deleted
```

**Concepto:** Cuando un archivo se elimina en NTFS, su entrada MFT no se borra inmediatamente — solo se marca como "no asignada" (`is_allocated = False`). Esto permite recuperar archivos eliminados y sus metadatos.

**¿Qué observar?** El atacante eliminó:
- `PrintSpoofer64.exe` (después de usarlo)
- `rclone.conf` (configuración de exfiltración)
- `financial_data_Q2_2026.7z` (datos exfiltrados)
- `debug.dmp` (volcado de LSASS renombrado)
- `timestomp.exe` (la propia herramienta de timestomping)

### Paso 5.4: Timeline real basada en $FILE_NAME

```bash
python3 /tools/parsers/mft_analyzer.py --timeline
```

**Concepto clave:** Esta timeline usa SOLO los timestamps de `$FILE_NAME` (que el atacante no puede modificar), por lo que muestra el orden REAL de creación de archivos, independientemente del timestomping.

### Paso 5.5: Detección avanzada de timestomping

```bash
python3 /tools/parsers/timestomp_detector.py
```

### Paso 5.6: Análisis profundo con heurísticas

```bash
python3 /tools/parsers/timestomp_detector.py --deep
```

**Heurísticas avanzadas:**
1. **Timestamps copiados:** ¿El archivo malicioso tiene exactamente el mismo timestamp que un archivo legítimo? Esto indica que el atacante usó el timestamp de otro archivo como "plantilla".
2. **Precisión de nanosegundos:** Las herramientas de timestomping a menudo no setean los nanosegundos correctamente, dejando `.000000`.
3. **Orden cronológico imposible:** Un archivo no puede ser más antiguo que el directorio que lo contiene.

### Paso 5.7: Correlación multi-artefacto

```bash
python3 /tools/parsers/timestomp_detector.py --correlate
```

**Este paso es crucial:** Correlaciona los timestamps de MFT con los datos de Prefetch y Amcache. Si la MFT dice que `mimikatz.exe` fue creado en 2020, pero Prefetch muestra su primera ejecución en julio 2026, y Amcache confirma `first_run` en julio 2026 — entonces el timestamp de MFT es FALSO.

### Preguntas de Análisis — Ejercicio 5

1. ¿Por qué el atacante eligió copiar el timestamp del `svchost.exe` legítimo para su beacon?
2. ¿Qué archivo tiene "timestomping parcial" y qué error cometió el atacante?
3. ¿Por qué es irónico que `timestomp.exe` también fue timestomped?
4. ¿Cómo confirmas timestomping si solo tienes la MFT (sin Prefetch/Amcache)?

---

## Ejercicio 6: Construcción de Timeline Consolidada y Reporte (30 minutos)

### Paso 6.1: Generar timeline completa del ataque

```bash
python3 /tools/parsers/timeline_builder.py
```

### Paso 6.2: Ver el ataque por fases

```bash
python3 /tools/parsers/timeline_builder.py --phases
```

### Paso 6.3: Mapeo MITRE ATT&CK

```bash
python3 /tools/parsers/timeline_builder.py --mitre
```

### Paso 6.4: Generar reporte ejecutivo

```bash
python3 /tools/parsers/timeline_builder.py --report
```

### Paso 6.5: Revisar IOCs completos del caso

```bash
cat /cases/SRV-FIN-01/iocs/iocs_complete.json | jq .
```

---

## Mapeo MITRE ATT&CK del Laboratorio

| Táctica | Técnica | ID | Evidencia |
|---------|---------|-----|-----------|
| Initial Access | Spearphishing Attachment | T1566.001 | Prefetch: WINWORD.EXE |
| Execution | PowerShell | T1059.001 | Prefetch: POWERSHELL.EXE |
| Persistence | — | — | Beacon con reinicio automático |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Prefetch: PRINTSPOOFER64.EXE |
| Defense Evasion | Masquerading | T1036.005 | Amcache: svchost.exe en path anómalo |
| Defense Evasion | Timestomp | T1070.006 | MFT: SI ≠ FN timestamps |
| Defense Evasion | Indicator Removal: Clear Event Logs | T1070.001 | Prefetch: WEVTUTIL.EXE x3 |
| Credential Access | OS Credential Dumping: LSASS | T1003.001 | Prefetch: MIMIKATZ + PROCDUMP |
| Discovery | Domain Trust Discovery | T1482 | Prefetch: NLTEST.EXE |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | Prefetch: PSEXEC.EXE x3 |
| Collection | Archive Collected Data | T1560.001 | MFT: financial_data_Q2_2026.7z |
| Command and Control | Ingress Tool Transfer | T1105 | Prefetch: CERTUTIL + BITSADMIN |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | Prefetch: RCLONE.EXE |

---

## Limpieza

```bash
# Salir del escritorio noVNC (cerrar pestaña del navegador)
# Detener el laboratorio:
docker-compose down

# Eliminar volúmenes (opcional):
docker-compose down -v
```

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| noVNC no carga | Verificar que el puerto 6080 no esté en uso: `lsof -i :6080` |
| Pantalla negra en VNC | Esperar 30 segundos para que XFCE4 inicie completamente |
| Scripts no encuentran evidencia | Ejecutar: `bash /tools/scripts/hunt_helper.sh status` |
| Error "Permission denied" | Ejecutar con `sudo` o verificar permisos de `/cases/` |
| Contenedor no inicia | Revisar logs: `docker-compose logs lab19-forensic` |

---

*MAR404 — Cacería de Amenazas (Threat Hunter) — Universidad Mayor 2026*
