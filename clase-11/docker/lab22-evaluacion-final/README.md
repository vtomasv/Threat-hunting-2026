# Lab 22: EVALUACIÓN FINAL - Hunting Mission
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** Clase 11

---

## Descripción del Escenario
**Operation Dark Seoul** — Simulación de ataque Lazarus Group contra el sistema SWIFT de un banco.

El Centro de Operaciones de Seguridad (SOC) de la institución financiera ha estado monitoreando la red interna tras recibir alertas de inteligencia de amenazas sobre una nueva campaña dirigida a infraestructuras bancarias. Durante el turno de madrugada, el sistema de Detección de Intrusos (IDS) detectó tráfico HTTPS inusual y persistente desde el servidor crítico `SWIFT-SRV01` hacia una dirección IP externa sospechosa (`185.220.101.50`). 

Este servidor está altamente restringido y no debería tener comunicación directa con Internet, lo que eleva la severidad del incidente a nivel crítico. Como Threat Hunter principal del equipo de respuesta a incidentes, tu misión es investigar este incidente a fondo. Debes reconstruir la cadena de ataque completa, identificar el alcance del compromiso, descubrir qué datos (si los hay) han sido exfiltrados, y proponer medidas de contención inmediatas antes de que los atacantes logren realizar transferencias fraudulentas.

---

## Objetivos de Aprendizaje
- Analizar tráfico de red para identificar patrones de Comando y Control (C2) y beaconing.
- Correlacionar eventos de memoria y procesos para descubrir técnicas avanzadas de evasión de defensas.
- Investigar artefactos del sistema de archivos y logs de eventos de Windows para rastrear el movimiento lateral.
- Mapear los hallazgos a la matriz MITRE ATT&CK para comprender las tácticas y técnicas del adversario.
- Elaborar un reporte ejecutivo y técnico con indicadores de compromiso (IOCs) accionables para el equipo de contención.

---

## Requisitos Previos
- **Software:** Docker y Docker Compose instalados y configurados en el sistema host.
- **Hardware:** Mínimo 2 GB de RAM disponible y 5 GB de espacio en disco.
- **Puertos:** No se requieren puertos expuestos hacia el host para este laboratorio, todo ocurre internamente.
- **Conocimientos:** Familiaridad con comandos básicos de Linux (`cat`, `grep`, `jq`, `awk`), análisis de logs estructurados en JSON y conceptos de respuesta a incidentes.

---

## Despliegue Paso a Paso

Sigue estas instrucciones cuidadosamente para inicializar el entorno de simulación.

1. **Clonar o acceder al directorio del laboratorio:**
   Navega al directorio donde se encuentran los archivos de configuración del laboratorio.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-11/docker/lab22-evaluacion-final/
   ```

2. **Levantar el entorno Docker:**
   Inicia los contenedores en modo detached (segundo plano).
   ```bash
   docker-compose up -d
   ```

3. **Verificar que el contenedor esté en ejecución:**
   Asegúrate de que el contenedor se haya levantado correctamente sin errores.
   ```bash
   docker ps | grep hunting-mission
   ```
   *Salida esperada:* Deberías ver un contenedor llamado `hunting-mission` en estado "Up".

4. **Acceder al contenedor:**
   Abre una sesión interactiva de bash dentro del contenedor para comenzar la investigación.
   ```bash
   docker exec -it hunting-mission bash
   ```

5. **Verificar el acceso a la evidencia:**
   Comprueba que todos los archivos de evidencia simulada estén disponibles.
   ```bash
   ls -la /mission/
   ```
   *Salida esperada:* Deberías ver los directorios `network`, `memory`, `filesystem`, `logs` y el archivo `MISSION_BRIEFING.json`.

---

## Ejercicios Paso a Paso

### Ejercicio 1: Análisis de Tráfico de Red y C2
**Hipótesis de Hunting:** El atacante está utilizando un canal de Comando y Control (C2) cifrado hacia la IP externa detectada para mantener persistencia, recibir comandos y exfiltrar datos críticos del sistema SWIFT.

**Comandos a ejecutar:**
```bash
# Extraer las conexiones hacia la IP sospechosa usando jq
cat /mission/network/traffic.json | jq '.[] | select(.destination_ip == "185.220.101.50")'

# Contar el número de conexiones por puerto de destino para identificar el servicio
cat /mission/network/traffic.json | jq -r '.[] | select(.destination_ip == "185.220.101.50") | .destination_port' | sort | uniq -c

# Analizar el tamaño de los payloads para detectar posible exfiltración
cat /mission/network/traffic.json | jq -r '.[] | select(.destination_ip == "185.220.101.50") | .bytes_sent' | sort -nr | head -n 5
```
*Explicación de flags:* `jq` procesa JSON; `-r` devuelve texto sin comillas; `sort` ordena los resultados; `uniq -c` cuenta las ocurrencias únicas; `sort -nr` ordena numéricamente en orden inverso; `head -n 5` muestra los 5 valores más altos.

**Qué buscar en la salida:**
Busca patrones de conexiones repetitivas (beaconing), puertos inusuales o volúmenes de datos transferidos significativamente altos que indiquen exfiltración de información.

**Preguntas de análisis:**
1. ¿Qué puerto(s) se están utilizando para la comunicación con la IP 185.220.101.50?
2. ¿Existe un patrón de tiempo (beaconing) en las conexiones?
3. ¿Cuál es el volumen máximo de datos enviados en una sola conexión?

**Respuestas esperadas:**
1. Se utiliza el puerto 443 (HTTPS) para ocultar el tráfico C2 dentro del tráfico web normal.
2. Sí, se observan conexiones regulares cada 5 minutos con un jitter del 10%, indicativo de un beacon de Cobalt Strike.
3. Se observa un pico de 50MB transferidos en una sola sesión, sugiriendo exfiltración de bases de datos o archivos de configuración.

### Ejercicio 2: Análisis de Procesos y Memoria
**Hipótesis de Hunting:** El atacante ha inyectado código malicioso en un proceso legítimo del sistema operativo para evadir la detección del software antivirus y EDR.

**Comandos a ejecutar:**
```bash
# Buscar procesos con inyección de memoria o hilos inusuales
cat /mission/memory/processes.json | jq '.[] | select(.injected_threads == true or .suspicious_modules == true)'

# Identificar el proceso padre del proceso sospechoso para rastrear el origen
cat /mission/memory/processes.json | jq -r '.[] | select(.process_name == "svchost.exe" and .injected_threads == true) | "PID: \(.pid), Parent PID: \(.parent_pid), Command Line: \(.command_line)"'
```
*Explicación de flags:* Filtramos por atributos booleanos que indican inyección de hilos o módulos sospechosos, y extraemos el PID, PPID y la línea de comandos exacta utilizada para lanzar el proceso.

**Qué buscar en la salida:**
Identifica procesos legítimos de Windows (como `svchost.exe`, `explorer.exe`, `lsass.exe`) que tengan hilos inyectados, módulos no firmados cargados en memoria, o que hayan sido lanzados desde ubicaciones inusuales.

**Preguntas de análisis:**
1. ¿Qué proceso legítimo está siendo utilizado para ocultar el malware?
2. ¿Cuál es el PID del proceso comprometido y quién es su proceso padre?
3. ¿Qué técnica de evasión sugiere este comportamiento específico?

**Respuestas esperadas:**
1. El proceso `svchost.exe` está siendo utilizado maliciosamente.
2. PID: 4520, Parent PID: 1024 (un proceso de PowerShell que ya terminó).
3. Sugiere Process Injection (T1055), específicamente Process Hollowing, comúnmente usado por APTs para evadir defensas.

### Ejercicio 3: Rastreo de Movimiento Lateral y Persistencia
**Hipótesis de Hunting:** El atacante ha creado tareas programadas para mantener persistencia en el servidor y se ha movido lateralmente desde otra máquina usando credenciales administrativas comprometidas.

**Comandos a ejecutar:**
```bash
# Buscar creación de tareas programadas en los logs de eventos de Windows
cat /mission/logs/events.json | jq '.[] | select(.event_id == 4698)'

# Buscar artefactos de ejecución remota en el sistema de archivos
cat /mission/filesystem/artifacts.json | jq '.[] | select(.file_name | test("PSEXESVC.exe|wmic.exe"; "i"))'

# Extraer el usuario que creó la tarea programada
cat /mission/logs/events.json | jq -r '.[] | select(.event_id == 4698) | .user_account'
```
*Explicación de flags:* `event_id == 4698` corresponde a la creación de tareas programadas. `test("...", "i")` realiza una búsqueda regex insensible a mayúsculas para encontrar herramientas comunes de movimiento lateral.

**Qué buscar en la salida:**
Busca nombres de tareas programadas sospechosas (ej. actualizaciones falsas, nombres aleatorios) y la presencia de herramientas de administración legítimas usadas con fines maliciosos (Living off the Land).

**Preguntas de análisis:**
1. ¿Qué tarea programada fue creada por el atacante y qué comando ejecuta exactamente?
2. ¿Se encontró evidencia de herramientas de movimiento lateral en el disco?
3. ¿Qué cuenta de usuario fue utilizada para realizar estas acciones administrativas?

**Respuestas esperadas:**
1. Se creó una tarea llamada "WindowsUpdateSync" que ejecuta un script de PowerShell ofuscado en Base64.
2. Sí, se encontró el artefacto `PSEXESVC.exe` en `C:\Windows\`, indicando el uso de PsExec para movimiento lateral.
3. Se utilizó la cuenta de administrador de dominio comprometida "svc_swift_admin".

### Ejercicio 4: Análisis de Artefactos de Exfiltración
**Hipótesis de Hunting:** El atacante ha comprimido y cifrado datos sensibles antes de exfiltrarlos a través del canal C2.

**Comandos a ejecutar:**
```bash
# Buscar archivos comprimidos creados recientemente en directorios temporales
cat /mission/filesystem/artifacts.json | jq '.[] | select(.file_path | test("Temp|ProgramData"; "i")) | select(.file_extension | test("zip|rar|7z|tmp"; "i"))'

# Correlacionar la hora de creación del archivo con el pico de tráfico de red
cat /mission/filesystem/artifacts.json | jq -r '.[] | select(.file_name == "sys_backup.tmp") | .creation_time'
```
*Explicación de flags:* Filtramos por rutas comunes de staging (Temp, ProgramData) y extensiones de archivos comprimidos o temporales.

**Qué buscar en la salida:**
Archivos con nombres engañosos (ej. `backup.tmp`, `dump.zip`) creados en directorios temporales justo antes de los picos de tráfico de red detectados en el Ejercicio 1.

**Preguntas de análisis:**
1. ¿Qué archivo sospechoso fue creado en un directorio temporal?
2. ¿Coincide la hora de creación del archivo con el pico de tráfico de red?
3. ¿Qué sugiere el nombre y la ubicación del archivo?

**Respuestas esperadas:**
1. Se encontró un archivo llamado `sys_backup.tmp` (que en realidad es un archivo ZIP cifrado) en `C:\ProgramData\`.
2. Sí, el archivo fue creado a las 03:14 AM, justo dos minutos antes del pico de transferencia de 50MB.
3. Sugiere que el atacante realizó "Data Staging" (T1074), agrupando y comprimiendo los datos antes de la exfiltración.

---

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Táctica | Evidencia Encontrada |
|------------|----------------------|---------|----------------------|
| T1055 | Process Injection | Defense Evasion | Hilos inyectados en `svchost.exe` (processes.json) |
| T1071.001 | Web Protocols | Command and Control | Tráfico C2 sobre HTTPS puerto 443 hacia 185.220.101.50 |
| T1053.005 | Scheduled Task | Persistence | Creación de tarea "WindowsUpdateSync" (Event ID 4698) |
| T1569.002 | Service Execution | Lateral Movement | Uso de PsExec (`PSEXESVC.exe`) en C:\Windows\ |
| T1074.001 | Local Data Staging | Collection | Archivo `sys_backup.tmp` creado en C:\ProgramData\ |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Transferencia inusual de 50MB hacia IP externa |

---

## Cadena de Ataque Completa

```text
[Compromiso Inicial] ---> [Ejecución] ---> [Persistencia] ---> [Evasión de Defensas] ---> [Movimiento Lateral] ---> [Colección] ---> [Exfiltración]
         |                     |                 |                      |                         |                      |                 |
  Phishing/Exploit     PowerShell Script   Scheduled Task       Process Injection           PsExec (SMB)           Data Staging      C2 HTTPS (443)
         |                     |                 |                      |                         |                      |                 |
   (No en logs)       (WindowsUpdateSync) (Event ID 4698)         (svchost.exe)             (PSEXESVC.exe)       (sys_backup.tmp)  (185.220.101.50)
```

---

## Limpieza

Una vez finalizado el laboratorio y completado el reporte, asegúrate de detener y eliminar los contenedores para liberar recursos del sistema host.

```bash
# 1. Salir de la sesión interactiva del contenedor
exit

# 2. Detener y eliminar el entorno Docker (contenedores, redes)
docker-compose down -v

# 3. Opcional: Eliminar imágenes huérfanas para ahorrar espacio en disco
docker image prune -f
```

---

## Troubleshooting

Si encuentras problemas durante la ejecución del laboratorio, revisa estas soluciones comunes:

1. **Problema:** `docker-compose: command not found`
   **Solución:** Asegúrate de tener Docker Compose instalado. Puedes instalarlo con `sudo apt install docker-compose` o usar el plugin moderno `docker compose` (sin guion).

2. **Problema:** El contenedor se detiene inmediatamente después de iniciar (CrashLoop).
   **Solución:** Verifica los logs del contenedor con `docker logs hunting-mission`. Es posible que el comando de entrada (entrypoint) en el Dockerfile esté fallando o que falten dependencias.

3. **Problema:** Error `jq: command not found` dentro del contenedor.
   **Solución:** El contenedor debería tener `jq` preinstalado según el Dockerfile. Si por alguna razón no está, ejecuta `apt-get update && apt-get install -y jq` dentro del contenedor como usuario root.

4. **Problema:** No se encuentran los archivos JSON en el directorio `/mission/`.
   **Solución:** Verifica que el mapeo de volúmenes en el archivo `docker-compose.yml` sea correcto y que los archivos de evidencia existan realmente en el directorio del host antes de levantar el contenedor.

5. **Problema:** Permiso denegado al intentar leer los archivos de evidencia.
   **Solución:** Asegúrate de que tu usuario dentro del contenedor tenga los permisos adecuados. Puedes cambiar los permisos desde el host con `chmod -R 755 ./mission/` antes de montar el volumen.
