# Lab 14 — Caso Integrador de Memoria (Evaluación Parcial 2)
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 07

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha detectado actividad anómala proveniente de la estación de trabajo de un ejecutivo de finanzas. El usuario reportó que su equipo se volvió lento después de abrir un documento adjunto en un correo electrónico que parecía ser una factura urgente. Se ha capturado un volcado de memoria (memory dump) del equipo comprometido. Como Threat Hunter, tu misión es analizar este volcado para reconstruir la cadena de ataque completa, identificar el malware utilizado, descubrir las credenciales comprometidas y determinar si hubo movimiento lateral.

## Objetivos de Aprendizaje
* Identificar procesos anómalos y técnicas de inyección de código (Process Hollowing) en volcados de memoria.
* Extraer y analizar artefactos de ejecución de PowerShell y comandos codificados.
* Detectar intentos de robo de credenciales mediante el volcado del proceso LSASS.
* Reconstruir la línea de tiempo del incidente y mapear las acciones del atacante al framework MITRE ATT&CK.

## Requisitos Previos
* **Software:** Docker y Docker Compose instalados en el sistema host.
* **Hardware:** Mínimo 4 GB de RAM disponibles para el contenedor.
* **Puertos:** No se requieren puertos expuestos para este laboratorio.

## Despliegue Paso a Paso
1. **Clonar o acceder al directorio del laboratorio:**
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-07/docker/lab14-caso-integrador-memoria/
   ```
2. **Levantar el contenedor en segundo plano:**
   ```bash
   docker-compose up -d
   ```
3. **Verificar que el contenedor esté en ejecución:**
   ```bash
   docker ps | grep memory-forensics
   ```
   *Deberías ver el contenedor `memory-forensics` en estado "Up".*
4. **Acceder a la terminal del contenedor:**
   ```bash
   docker exec -it memory-forensics bash
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Identificación del Acceso Inicial y Ejecución
**Hipótesis de Hunting:** El atacante obtuvo acceso inicial mediante un documento malicioso que ejecutó comandos de PowerShell codificados para establecer persistencia o descargar payloads adicionales.

**Comandos a ejecutar:**
```bash
# Buscar procesos sospechosos y sus relaciones padre-hijo
memory_hunter --processes

# Extraer comandos de PowerShell ejecutados
memory_hunter --summary | grep -i powershell
```
*Explicación de flags:*
* `--processes`: Muestra un árbol de procesos para identificar relaciones inusuales (ej. Word abriendo PowerShell).
* `--summary`: Proporciona un resumen general del volcado de memoria.

**Qué buscar en la salida:**
Busca un proceso de Microsoft Word (`WINWORD.EXE`) que tenga como proceso hijo a `powershell.exe`. Además, revisa si el comando de PowerShell incluye el flag `-enc` o `-EncodedCommand`.

**Preguntas de análisis:**
1. ¿Cuál es el PID del proceso de Microsoft Word y de PowerShell?
2. ¿Qué comando codificado en Base64 se ejecutó?
3. ¿Cuál es el propósito del script de PowerShell decodificado?

**Respuestas esperadas:**
* **R1:** WINWORD.EXE (PID: 4512) -> powershell.exe (PID: 5104).
* **R2:** Se ejecutó un comando con `-enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...`
* **R3:** El script decodificado descarga y ejecuta un payload en memoria (posiblemente un stager de Cobalt Strike).

---

### Ejercicio 2: Detección de Evasión de Defensas (Process Hollowing)
**Hipótesis de Hunting:** El atacante inyectó código malicioso en un proceso legítimo del sistema para evadir la detección de los antivirus y mantener el acceso.

**Comandos a ejecutar:**
```bash
# Buscar regiones de memoria inyectadas o anómalas
memory_hunter --malfind

# Extraer IOCs de los procesos sospechosos
ioc_extractor --pid 2048
```
*Explicación de flags:*
* `--malfind`: Busca regiones de memoria con permisos de ejecución, lectura y escritura (PAGE_EXECUTE_READWRITE) que no están respaldadas por un archivo en disco.
* `--pid`: Especifica el ID del proceso del cual extraer Indicadores de Compromiso.

**Qué buscar en la salida:**
Identifica procesos legítimos de Windows (como `svchost.exe`, `explorer.exe` o `notepad.exe`) que aparezcan en los resultados de `malfind` con cabeceras MZ/PE inyectadas.

**Preguntas de análisis:**
1. ¿Qué proceso legítimo fue víctima de Process Hollowing?
2. ¿Cuáles son las direcciones de memoria donde se encontró el código inyectado?
3. ¿Qué direcciones IP o dominios de C2 se extrajeron del proceso inyectado?

**Respuestas esperadas:**
* **R1:** svchost.exe (PID: 2048).
* **R2:** Direcciones como `0x00000000023A0000` con permisos `PAGE_EXECUTE_READWRITE`.
* **R3:** Se extrajo la IP `192.168.100.55` y el dominio `update.microsoft-updater.com` (C2 de Cobalt Strike).

---

### Ejercicio 3: Robo de Credenciales y Movimiento Lateral
**Hipótesis de Hunting:** Tras establecerse en el equipo, el atacante intentó volcar la memoria del proceso LSASS para obtener credenciales en texto claro y luego se movió lateralmente a otros equipos del dominio.

**Comandos a ejecutar:**
```bash
# Buscar comandos ejecutados relacionados con LSASS
memory_hunter --summary | grep -i lsass

# Reconstruir la línea de tiempo de los eventos
timeline_builder --output timeline.csv
cat timeline.csv | grep -i psexec
```
*Explicación de flags:*
* `--output`: Define el archivo de salida para la línea de tiempo generada.

**Qué buscar en la salida:**
Busca el uso de herramientas como `rundll32.exe` o `procdump.exe` apuntando a `lsass.exe`. En la línea de tiempo, busca la ejecución de `PsExec.exe` o conexiones de red inusuales por el puerto 445.

**Preguntas de análisis:**
1. ¿Qué comando exacto se utilizó para volcar la memoria de LSASS?
2. ¿A qué hora se ejecutó el volcado de credenciales?
3. ¿Hacia qué dirección IP interna se intentó el movimiento lateral usando PsExec?

**Respuestas esperadas:**
* **R1:** `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 652 C:\temp\lsass.dmp full` (donde 652 es el PID de lsass.exe).
* **R2:** A las 14:35:22 UTC según la línea de tiempo.
* **R3:** Se detectó ejecución de PsExec hacia la IP `10.0.5.20` (Controlador de Dominio).

## Mapeo MITRE ATT&CK

| ID | Técnica | Evidencia |
|----|---------|-----------|
| T1566.001 | Spearphishing Attachment | Proceso WINWORD.EXE abriendo un documento malicioso. |
| T1059.001 | PowerShell | Ejecución de `powershell.exe -enc ...` como hijo de Word. |
| T1055.012 | Process Hollowing | `svchost.exe` con regiones de memoria inyectadas (malfind). |
| T1003.001 | LSASS Memory | Uso de `rundll32.exe` con `comsvcs.dll` para volcar LSASS. |
| T1570 | Lateral Tool Transfer | Transferencia y ejecución de `PsExec.exe` en la red. |
| T1018 | Remote System Discovery | Comandos de enumeración de dominio (`nltest`, `net group`). |
| T1074.001 | Local Data Staging | Archivos `.dmp` y `.zip` encontrados en `C:\temp\`. |
| T1560.001 | Archive via Utility | Uso de utilidades de compresión con contraseña para exfiltración. |

## Cadena de Ataque Completa

```text
[Phishing Email]
       |
       v
[WINWORD.EXE] (T1566.001)
       |
       +---> [powershell.exe -enc] (T1059.001)
                    |
                    v
             [Descarga de Payload]
                    |
                    v
             [svchost.exe] (Process Hollowing - T1055.012) <---> [C2 Server]
                    |
                    +---> [rundll32.exe comsvcs.dll] (LSASS Dump - T1003.001)
                    |
                    +---> [Enumeración de Red] (T1018)
                    |
                    +---> [PsExec.exe] (Movimiento Lateral - T1570)
                    |
                    +---> [Compresión de Datos] (T1560.001)
```

## Limpieza
Una vez finalizado el laboratorio, asegúrate de detener y eliminar los contenedores para liberar recursos:
```bash
# Salir del contenedor
exit

# Detener y eliminar el contenedor
docker-compose down
```

## Troubleshooting
* **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  * **Solución:** Aunque este laboratorio no expone puertos, si modificaste el `docker-compose.yml`, asegúrate de detener otros laboratorios con `docker-compose down` en sus respectivos directorios.
* **Problema:** El contenedor se detiene inmediatamente después de iniciarse.
  * **Solución:** Verifica los logs con `docker logs memory-forensics`. Asegúrate de tener suficiente memoria RAM disponible en el sistema host.
* **Problema:** Las herramientas como `memory_hunter` indican "Command not found".
  * **Solución:** Asegúrate de estar ejecutando los comandos dentro del contenedor (`docker exec -it memory-forensics bash`) y no en tu máquina host.
* **Problema:** La salida de `malfind` es demasiado extensa.
  * **Solución:** Utiliza `grep` para filtrar por PIDs específicos o redirige la salida a un archivo de texto (`memory_hunter --malfind > malfind_output.txt`) para analizarlo con `less` o `cat`.
