# Lab 21: Simulación APT Guiada (Warm-up)
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 11
**Institución:** Universidad Mayor 2026

## Descripción del Escenario
El equipo de monitoreo de seguridad (SOC) ha detectado un comportamiento anómalo en una de las estaciones de trabajo del departamento de finanzas. Se sospecha que la organización ha sido víctima de un ataque dirigido por un actor de amenazas avanzado, posiblemente asociado a APT29 (Cozy Bear). El ataque parece haber comenzado con un correo de spearphishing que contenía un documento con macros maliciosas, lo que desencadenó una serie de eventos que incluyen ejecución de código, establecimiento de persistencia y posible exfiltración de datos hacia un servidor de Comando y Control (C2). Como Threat Hunter, tu misión es analizar la evidencia recolectada del endpoint comprometido para reconstruir la cadena de ataque y confirmar la intrusión.

## Objetivos de Aprendizaje
* Analizar eventos de procesos en memoria para identificar ejecuciones anómalas de herramientas nativas del sistema (Living off the Land).
* Correlacionar conexiones de red sospechosas con procesos específicos para detectar comunicaciones de Comando y Control (C2).
* Identificar mecanismos de persistencia creados por el atacante mediante el análisis de artefactos del sistema de archivos.
* Mapear los hallazgos técnicos con las tácticas y técnicas del framework MITRE ATT&CK.

## Requisitos Previos
* **Docker y Docker Compose:** Instalados y configurados en el sistema host.
* **Memoria RAM:** Mínimo 2 GB de RAM disponibles para el contenedor.
* **Puertos:** No se requieren puertos expuestos adicionales para este laboratorio.
* **Herramientas:** Conocimientos básicos de línea de comandos de Linux y uso de la herramienta `jq` para parsear JSON.

## Despliegue Paso a Paso
1. **Clonar o acceder al directorio del laboratorio:**
   Asegúrate de estar en el directorio correcto donde se encuentra el archivo `docker-compose.yml`.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-11/docker/lab21-apt-simulation/
   ```

2. **Levantar el entorno de simulación:**
   Ejecuta el siguiente comando para iniciar el contenedor en segundo plano.
   ```bash
   docker-compose up -d
   ```

3. **Verificar el estado del contenedor:**
   Asegúrate de que el contenedor `apt-hunter` esté en ejecución.
   ```bash
   docker ps | grep apt-hunter
   ```

4. **Acceder al contenedor de análisis:**
   Ingresa al contenedor para comenzar la cacería de amenazas.
   ```bash
   docker exec -it apt-hunter bash
   ```

5. **Verificar la evidencia disponible:**
   Comprueba que los archivos de evidencia estén presentes en el directorio `/evidence/`.
   ```bash
   ls -la /evidence/
   ls -la /evidence/network/
   ls -la /evidence/memory/
   ls -la /evidence/filesystem/
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Identificación del Acceso Inicial y Ejecución
**Hipótesis de Hunting:** El atacante utilizó un documento ofimático con macros para ejecutar código malicioso a través de utilidades nativas del sistema como `mshta.exe` o `powershell.exe`.

**Comandos a ejecutar:**
Vamos a buscar procesos sospechosos que hayan sido lanzados por aplicaciones de Office o que involucren `mshta`.
```bash
# Buscar ejecuciones de mshta en los eventos de procesos
cat /evidence/memory/process_events.json | jq '.[] | select(.process_name == "mshta.exe" or .parent_process == "WINWORD.EXE")'
```
*Explicación de flags:* `cat` lee el archivo JSON, `|` pasa la salida a `jq`, el cual filtra los objetos (`.[]`) donde el nombre del proceso es `mshta.exe` o el proceso padre es `WINWORD.EXE`.

**Qué buscar en la salida:**
Busca la línea de comandos exacta (`command_line`) utilizada para ejecutar `mshta.exe` y cualquier URL o archivo HTA referenciado.

**Preguntas de análisis:**
1. ¿Cuál es el proceso padre que inició la cadena de ejecución maliciosa?
2. ¿Qué URL o archivo se pasó como argumento a `mshta.exe`?
3. ¿Qué proceso hijo fue generado por `mshta.exe`?

**Respuestas esperadas:**
1. El proceso padre es `WINWORD.EXE`, lo que confirma el vector de spearphishing.
2. Se espera encontrar una URL externa o un archivo local `.hta` en la línea de comandos de `mshta.exe`.
3. `mshta.exe` probablemente generó un proceso `powershell.exe` para continuar la ejecución.

### Ejercicio 2: Descubrimiento de Persistencia y Descarga de Herramientas
**Hipótesis de Hunting:** El atacante descargó herramientas adicionales utilizando utilidades del sistema (Living off the Land Binaries - LOLBins) y estableció persistencia mediante tareas programadas.

**Comandos a ejecutar:**
Buscaremos el uso de `certutil.exe` para descargas y `schtasks.exe` para persistencia.
```bash
# Buscar uso de certutil o schtasks en los eventos de procesos
cat /evidence/memory/process_events.json | jq '.[] | select(.process_name == "certutil.exe" or .process_name == "schtasks.exe")'

# Revisar artefactos del sistema de archivos relacionados con tareas programadas
cat /evidence/filesystem/artifacts.json | jq '.[] | select(.type == "ScheduledTask")'
```
*Explicación de flags:* Filtramos los eventos de procesos buscando específicamente los binarios `certutil.exe` y `schtasks.exe`. Luego, buscamos en los artefactos del sistema de archivos aquellos clasificados como tareas programadas.

**Qué buscar en la salida:**
En los eventos de procesos, observa las URLs de donde `certutil.exe` descarga archivos y los comandos exactos de `schtasks.exe`. En los artefactos, verifica el nombre de la tarea programada y la acción que ejecuta.

**Preguntas de análisis:**
1. ¿Qué archivo fue descargado usando `certutil.exe` y desde qué dominio/IP?
2. ¿Cuál es el nombre de la tarea programada creada por el atacante?
3. ¿Con qué frecuencia o bajo qué condición se ejecuta la tarea programada?

**Respuestas esperadas:**
1. `certutil.exe` se usó con los flags `-urlcache -split -f` para descargar un payload (ej. un binario o script) desde una IP externa.
2. El nombre de la tarea programada suele intentar camuflarse como un proceso legítimo del sistema (ej. `WindowsUpdateCheck`).
3. La tarea programada probablemente esté configurada para ejecutarse al inicio del sistema (`/sc onlogon` o similar) o a intervalos regulares.

### Ejercicio 3: Análisis de Exfiltración y Comando y Control (C2)
**Hipótesis de Hunting:** El malware establecido se comunica con un servidor C2 a través de HTTPS (puerto 443) enviando beacons periódicos y posiblemente exfiltrando datos.

**Comandos a ejecutar:**
Analizaremos los logs de tráfico de red buscando conexiones salientes sospechosas, especialmente aquellas asociadas a los procesos maliciosos identificados.
```bash
# Buscar conexiones de red salientes en el puerto 443
cat /evidence/network/traffic_log.json | jq '.[] | select(.destination_port == 443)'

# Correlacionar conexiones de red con el proceso malicioso (ej. powershell.exe o el payload descargado)
cat /evidence/network/traffic_log.json | jq '.[] | select(.process_name == "powershell.exe")'
```
*Explicación de flags:* Filtramos el tráfico de red para mostrar solo las conexiones al puerto 443 (HTTPS) y luego buscamos conexiones originadas por procesos sospechosos como `powershell.exe`.

**Qué buscar en la salida:**
Identifica las direcciones IP de destino, la cantidad de bytes transferidos (bytes enviados vs. recibidos) y la regularidad de las conexiones (beacons).

**Preguntas de análisis:**
1. ¿Cuál es la dirección IP del servidor de Comando y Control (C2)?
2. ¿Existe evidencia de exfiltración de datos basada en el volumen de bytes enviados?
3. ¿Qué proceso del sistema está realizando las conexiones de red hacia el C2?

**Respuestas esperadas:**
1. La IP del C2 será la dirección de destino recurrente en los logs de red asociados al proceso malicioso.
2. Sí, si se observa una conexión o un conjunto de conexiones donde los `bytes_sent` son significativamente mayores que los `bytes_received`, indica exfiltración de datos.
3. El proceso realizando las conexiones debería coincidir con el payload descargado en el Ejercicio 2 o con una instancia inyectada de `powershell.exe`.

## Mapeo MITRE ATT&CK

| Táctica | Técnica ID | Nombre de la Técnica | Evidencia en el Laboratorio |
| :--- | :--- | :--- | :--- |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Documento de Word con macros maliciosas (`WINWORD.EXE`). |
| Execution | T1218.005 | System Binary Proxy Execution: Mshta | Uso de `mshta.exe` para ejecutar el callback HTA. |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Ejecución de comandos a través de `powershell.exe`. |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Creación de tarea programada con `schtasks.exe`. |
| Defense Evasion | T1105 | Ingress Tool Transfer | Descarga de payload usando `certutil.exe`. |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Beacons HTTPS (puerto 443) hacia el servidor C2. |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Subida de datos (data upload) a través de la conexión HTTPS. |

## Cadena de Ataque Completa

```text
[Spearphishing Email]
         |
         v
[WINWORD.EXE (Macro)] ---> (T1566.001)
         |
         v
[mshta.exe (HTA Callback)] ---> (T1218.005)
         |
         v
[powershell.exe] ---> (T1059.001)
         |
         +---> [certutil.exe (Download Payload)] ---> (T1105)
         |
         +---> [schtasks.exe (Persistence)] ---> (T1053.005)
         |
         v
[C2 Beaconing (HTTPS/443)] ---> (T1071.001)
         |
         v
[Data Exfiltration] ---> (T1041)
```

## Limpieza
Una vez finalizado el laboratorio, es importante detener y eliminar los contenedores para liberar recursos en el sistema host.
```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores, redes y volúmenes asociados
docker-compose down -v
```

## Troubleshooting
* **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  * **Solución:** Aunque este laboratorio no expone puertos, si hay conflictos, verifica qué contenedores están corriendo con `docker ps` y detén los que no necesites con `docker stop <container_id>`.
* **Problema:** No se encuentra el comando `jq` dentro del contenedor.
  * **Solución:** El contenedor debería tener `jq` preinstalado. Si no es así, puedes instalarlo ejecutando `apt-get update && apt-get install -y jq` dentro del contenedor (requiere permisos de root).
* **Problema:** Los archivos JSON en `/evidence/` están vacíos o no existen.
  * **Solución:** Verifica que el mapeo de volúmenes en el archivo `docker-compose.yml` sea correcto y que los archivos existan en el directorio host antes de levantar el contenedor. Reinicia el laboratorio con `docker-compose down -v` y `docker-compose up -d`.
* **Problema:** Error de permisos al intentar leer los archivos de evidencia.
  * **Solución:** Asegúrate de estar ejecutando los comandos como el usuario correcto dentro del contenedor, o utiliza `sudo` si es necesario y está disponible.
