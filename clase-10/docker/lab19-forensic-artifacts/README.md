# Lab 19 — Análisis de Artefactos Forenses
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 10 — Artefactos Forenses y Timeline Analysis

## Descripción del Escenario
El equipo de SOC ha detectado actividad anómala en un endpoint Windows crítico (Hostname: `SRV-FIN-01`). Las alertas iniciales indican posibles ejecuciones de herramientas de post-explotación y descargas sospechosas. El equipo de respuesta a incidentes ha recolectado artefactos forenses clave del sistema comprometido, incluyendo Prefetch, Amcache, UserAssist y la MFT (Master File Table). Tu misión como Threat Hunter es analizar estos artefactos para reconstruir la línea de tiempo del ataque, identificar las herramientas utilizadas por el adversario y descubrir técnicas de evasión de defensas como el timestomping.

## Objetivos de Aprendizaje
- Analizar archivos Prefetch para identificar ejecuciones de programas, sus rutas y tiempos de ejecución.
- Examinar entradas de Amcache para descubrir programas ejecutados, sus hashes y firmas digitales.
- Construir y analizar una línea de tiempo a partir de la MFT para detectar anomalías temporales (timestomping).
- Correlacionar múltiples artefactos forenses para reconstruir la cadena de ataque completa.

## Requisitos Previos
- **Docker y Docker Compose** instalados en el sistema host.
- **Memoria RAM:** Mínimo 2 GB disponibles para el contenedor.
- **Puertos:** No se requieren puertos expuestos para este laboratorio.
- Conocimientos básicos de línea de comandos en Linux y uso de `jq` para parseo de JSON.

## Despliegue Paso a Paso

1. **Iniciar el entorno del laboratorio:**
   Navega al directorio del laboratorio y levanta el contenedor en segundo plano.
   ```bash
   docker-compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y asegúrate de que el contenedor `forensic-analyst` esté en estado "Up".

2. **Acceder al contenedor de análisis:**
   Ingresa al contenedor para comenzar la investigación.
   ```bash
   docker exec -it forensic-analyst bash
   ```
   *Verificación:* El prompt debería cambiar, indicando que estás dentro del contenedor (ej. `root@forensic-analyst:/#`).

3. **Verificar las herramientas y evidencias:**
   Comprueba que el script de análisis y los datos estén disponibles.
   ```bash
   ls -la /evidence/
   python3 artifact_analyzer.py -h
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Análisis de Ejecución de Programas (Prefetch)
**Hipótesis de Hunting:** El atacante descargó y ejecutó herramientas maliciosas desde rutas no estándar en el sistema comprometido.

**Comandos:**
```bash
# Ejecutar el analizador enfocado en artefactos Prefetch
python3 artifact_analyzer.py --prefetch

# Ver los datos crudos en formato JSON para mayor detalle
cat /evidence/prefetch/prefetch_analysis.json | jq .
```
*Explicación de flags:* `--prefetch` filtra la salida del script para mostrar únicamente el análisis de los archivos Prefetch recolectados. `jq .` formatea la salida JSON para que sea legible.

**Qué buscar en la salida:**
Busca nombres de ejecutables sospechosos (ej. `certutil.exe`, `mimikatz.exe`), ejecuciones desde directorios temporales o públicos (`C:\Windows\Temp`, `C:\Users\Public`), y la cantidad de veces que se ejecutaron.

**Preguntas de análisis:**
1. ¿Qué herramienta nativa de Windows fue utilizada para descargar archivos y desde qué ruta se ejecutó?
2. ¿Se identifica alguna herramienta conocida de robo de credenciales?
3. ¿Existe algún proceso legítimo de Windows ejecutándose desde una ubicación inusual?

**Respuestas esperadas:**
1. *Se utilizó `certutil.exe` para descargar archivos, posiblemente ejecutado desde una ruta no estándar o con argumentos sospechosos.*
2. *Sí, se debe observar la ejecución de `mimikatz.exe`.*
3. *Sí, un falso `svchost.exe` ejecutándose desde una ruta distinta a `C:\Windows\System32`.*

---

### Ejercicio 2: Identificación de Binarios y Firmas (Amcache)
**Hipótesis de Hunting:** El adversario introdujo binarios sin firmar o con firmas inválidas en el sistema para evadir la detección basada en reputación.

**Comandos:**
```bash
# Ejecutar el analizador enfocado en entradas de Amcache
python3 artifact_analyzer.py --amcache

# Filtrar los datos crudos para ver detalles específicos
cat /evidence/amcache/amcache_entries.json | jq '.[] | select(.publisher == null or .publisher == "")'
```
*Explicación de flags:* `--amcache` muestra el análisis de la colmena Amcache. El comando `jq` filtra las entradas donde el campo `publisher` está vacío o es nulo, indicando binarios sin firmar.

**Qué buscar en la salida:**
Identifica archivos ejecutables que no tengan un "Publisher" (editor) asociado o cuyos hashes (SHA1/SHA256) correspondan a malware conocido.

**Preguntas de análisis:**
1. ¿Cuántos archivos ejecutables registrados en Amcache carecen de información de Publisher?
2. ¿Cuáles son los nombres y rutas de estos archivos sin firmar?
3. ¿Coinciden estos archivos con los encontrados en el análisis de Prefetch?

**Respuestas esperadas:**
1. *Deberían encontrarse al menos 3 entradas sin publisher (correspondientes a las herramientas maliciosas).*
2. *Los archivos incluyen el falso `svchost.exe`, la herramienta de descarga (si fue renombrada) y `mimikatz.exe`.*
3. *Sí, existe una correlación directa entre los binarios sin firmar en Amcache y las ejecuciones anómalas en Prefetch.*

---

### Ejercicio 3: Detección de Manipulación de Tiempos (MFT Timeline)
**Hipótesis de Hunting:** El atacante modificó las marcas de tiempo (timestomping) de sus herramientas maliciosas para ocultarlas en la línea de tiempo del sistema y evadir el análisis forense.

**Comandos:**
```bash
# Ejecutar el analizador enfocado en la línea de tiempo de la MFT
python3 artifact_analyzer.py --mft

# Ver los datos crudos de la MFT
cat /evidence/mft/mft_timeline.json | jq .
```
*Explicación de flags:* `--mft` procesa y muestra la línea de tiempo extraída de la Master File Table, destacando anomalías en los atributos de tiempo (Standard Information vs File Name).

**Qué buscar en la salida:**
Busca archivos donde la fecha de Creación (Created) sea igual a la fecha de Modificación (Modified), lo cual es típico de archivos recién "droppeados". Más importante aún, busca archivos donde la fecha de Creación sea posterior a la fecha de Modificación (Created > Modified), lo cual es un fuerte indicador de timestomping.

**Preguntas de análisis:**
1. ¿Qué archivos muestran signos evidentes de timestomping (Created > Modified)?
2. ¿Qué archivos parecen haber sido creados y modificados en el mismo instante exacto?
3. Basado en la línea de tiempo, ¿cuál fue el orden cronológico real de las acciones del atacante?

**Respuestas esperadas:**
1. *El falso `svchost.exe` y posiblemente `mimikatz.exe` mostrarán fechas de modificación antiguas (ej. años atrás) pero fechas de creación recientes.*
2. *Los archivos descargados o resultados de comandos (ej. volcados de memoria) tendrán Created == Modified.*
3. *1. Descarga con certutil. 2. Ejecución del falso svchost (persistencia/C2). 3. Ejecución de mimikatz. 4. Timestomping de los binarios.*

## Mapeo MITRE ATT&CK

| Táctica | Técnica ID | Nombre de la Técnica | Evidencia en el Laboratorio |
|---------|------------|----------------------|-----------------------------|
| Command and Control | T1105 | Ingress Tool Transfer | Uso de `certutil` para descargar archivos (Prefetch). |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Ejecución de `mimikatz` (Prefetch, Amcache). |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Falso `svchost.exe` en ruta no estándar (Prefetch, Amcache). |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | Anomalías en timestamps de la MFT (Created > Modified). |

## Cadena de Ataque Completa

```text
[Ingress Tool Transfer]      [Masquerading]               [Credential Access]          [Defense Evasion]
      T1105                    T1036.005                      T1003.001                   T1070.006
        |                          |                              |                           |
+-------v-------+          +-------v-------+              +-------v-------+           +-------v-------+
| certutil.exe  | -------> | svchost.exe   | -----------> | mimikatz.exe  | --------> | Timestomping  |
| (Descarga)    |          | (Falso/C2)    |              | (Robo creds)  |           | (MFT Alterada)|
+---------------+          +---------------+              +---------------+           +---------------+
        |                          |                              |                           |
   (Prefetch)             (Prefetch/Amcache)             (Prefetch/Amcache)             (MFT Timeline)
```

## Limpieza
Una vez finalizado el laboratorio, sal del contenedor y detén el entorno para liberar recursos.
```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores
docker-compose down
```

## Troubleshooting

1. **Error: `docker-compose: command not found`**
   *Solución:* Asegúrate de tener Docker Compose instalado. En versiones recientes de Docker, el comando puede ser `docker compose` (sin guion).

2. **Error: `No such container: forensic-analyst` al ejecutar `docker exec`**
   *Solución:* El contenedor no se inició correctamente. Ejecuta `docker-compose ps` para verificar el estado. Si está detenido, revisa los logs con `docker-compose logs`.

3. **Error: `python3: can't open file 'artifact_analyzer.py'`**
   *Solución:* Asegúrate de estar en el directorio correcto dentro del contenedor. El script debería estar en el directorio de trabajo por defecto (usualmente `/` o `/app`). Usa `ls` para verificar su ubicación.

4. **Error: `jq: command not found`**
   *Solución:* Si `jq` no está instalado en el contenedor, puedes instalarlo ejecutando `apt-get update && apt-get install -y jq` dentro del contenedor, o simplemente omitir el pipe a `jq` y leer el JSON crudo.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
