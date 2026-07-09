# Lab 11 — Detección de Process Injection
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 06
**Universidad:** Universidad Mayor 2026

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha detectado un comportamiento anómalo en una estación de trabajo crítica del departamento de finanzas. Las alertas iniciales indican la ejecución de un archivo sospechoso llamado `update.exe` que fue descargado desde un correo electrónico de phishing. Este ejecutable actuó como un *dropper*, realizando múltiples técnicas de inyección de procesos en binarios legítimos del sistema operativo para evadir la detección y establecer persistencia. Como Threat Hunter, tu misión es analizar la memoria del sistema comprometido para identificar, clasificar y documentar las tres técnicas de inyección de procesos utilizadas por el atacante.

## Objetivos de Aprendizaje
* Comprender las diferencias fundamentales a nivel de memoria entre Classic DLL Injection, Process Hollowing y APC Injection.
* Identificar anomalías en los Virtual Address Descriptors (VAD) que indican la presencia de código inyectado.
* Detectar hilos de ejecución (threads) anómalos y analizar sus puntos de inicio.
* Mapear los hallazgos técnicos con las tácticas y técnicas del framework MITRE ATT&CK.

## Requisitos Previos
* **Software:** Docker y Docker Compose instalados en el sistema host.
* **Hardware:** Mínimo 4 GB de RAM disponibles para el contenedor.
* **Puertos:** No se requieren puertos expuestos para este laboratorio.
* **Conocimientos:** Familiaridad básica con la línea de comandos de Linux y conceptos de memoria en Windows.

## Despliegue Paso a Paso

1. **Clonar o acceder al directorio del laboratorio:**
   Asegúrate de estar en el directorio correcto donde se encuentra el archivo `docker-compose.yml`.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-06/docker/lab11-process-injection/
   ```

2. **Levantar el entorno:**
   Inicia el contenedor en modo *detached* (segundo plano).
   ```bash
   docker-compose up -d
   ```

3. **Verificar el estado del contenedor:**
   Asegúrate de que el contenedor `injection-analyst` esté en ejecución.
   ```bash
   docker ps | grep injection-analyst
   ```

4. **Acceder al contenedor:**
   Abre una sesión interactiva de bash dentro del contenedor para comenzar el análisis.
   ```bash
   docker exec -it injection-analyst bash
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Detección de Classic DLL Injection
**Hipótesis de Hunting:** Los atacantes a menudo inyectan DLLs maliciosas en procesos legítimos (como `explorer.exe`) para ocultar su actividad de red (C2). Estas DLLs suelen tener permisos RWX (Read, Write, Execute) y estar ubicadas en directorios temporales.

**Comandos a ejecutar:**
```bash
# 1. Ejecutar el analizador general para identificar procesos sospechosos
injection_analyzer

# 2. Inspeccionar los VADs del proceso explorer.exe (asumiendo PID 1452 según la salida anterior)
vad_inspector --pid 1452

# 3. Verificar los hilos del proceso para encontrar el punto de inicio anómalo
thread_checker --pid 1452
```
*Explicación de flags:*
* `--pid 1452`: Especifica el Process ID del proceso a analizar.

**Qué buscar en la salida:**
* En `vad_inspector`: Busca regiones de memoria con protección `PAGE_EXECUTE_READWRITE` (RWX) que estén mapeadas a un archivo en un directorio inusual (ej. `C:\Users\Admin\AppData\Local\Temp\msvcrt_ext.dll`).
* En `thread_checker`: Busca un hilo cuyo `StartAddress` apunte directamente a la DLL inyectada en lugar de a una función legítima del sistema.

**Preguntas de análisis:**
1. ¿Cuál es el nombre y la ruta de la DLL inyectada en `explorer.exe`?
2. ¿Qué permisos de memoria tiene la región donde se cargó la DLL?
3. ¿Por qué el atacante elegiría `explorer.exe` para esta técnica?

**Respuestas esperadas:**
1. La DLL es `msvcrt_ext.dll` y se encuentra en un directorio temporal.
2. La región tiene permisos RWX (Read, Write, Execute), lo cual es anómalo para una DLL legítima que normalmente se carga como RX.
3. `explorer.exe` es un proceso que siempre está en ejecución en una sesión de usuario y tiene acceso a la red, lo que lo hace ideal para ocultar comunicaciones de Command and Control (C2).

---

### Ejercicio 2: Identificación de Process Hollowing
**Hipótesis de Hunting:** El malware puede crear un proceso legítimo en estado suspendido, vaciar su memoria (unmap) y reemplazarla con un ejecutable malicioso. Esto se evidencia por regiones de memoria RWX privadas sin un archivo asociado, pero que contienen un encabezado PE (MZ).

**Comandos a ejecutar:**
```bash
# 1. Inspeccionar los VADs del proceso svchost.exe (asumiendo PID 2890)
vad_inspector --pid 2890

# 2. Analizar los hilos del proceso
thread_checker --pid 2890
```
*Explicación de flags:*
* `--pid 2890`: Especifica el Process ID del proceso a analizar.

**Qué buscar en la salida:**
* En `vad_inspector`: Identifica una región de memoria con protección RWX que sea `Private` (no mapeada a un archivo en disco) y que comience con los *magic bytes* `MZ` (indicador de un ejecutable de Windows).
* En `thread_checker`: El hilo principal comenzará en la imagen base original, pero el código ejecutado corresponderá al PE inyectado.

**Preguntas de análisis:**
1. ¿Qué características en el VAD confirman que se trata de Process Hollowing y no de una inyección de DLL?
2. ¿Qué proceso legítimo fue utilizado como "cáscara" (hollowed process)?
3. ¿Por qué no hay un archivo asociado a la región de memoria maliciosa?

**Respuestas esperadas:**
1. La región de memoria es `Private` (sin archivo respaldado en disco), tiene permisos RWX y contiene un encabezado PE completo (`MZ`), a diferencia de una DLL que estaría mapeada a un archivo.
2. El proceso utilizado fue `svchost.exe`.
3. Porque el ejecutable malicioso fue inyectado directamente en la memoria del proceso desde otro proceso (el dropper), sin tocar el disco en esa ubicación.

---

### Ejercicio 3: Análisis de APC Injection
**Hipótesis de Hunting:** Los atacantes pueden encolar Asynchronous Procedure Calls (APCs) en hilos legítimos para ejecutar shellcode. Esto se observa como regiones de memoria RWX privadas que contienen shellcode (sin encabezado MZ) y hilos con APCs encoladas.

**Comandos a ejecutar:**
```bash
# 1. Inspeccionar los VADs del proceso notepad.exe (asumiendo PID 4120)
vad_inspector --pid 4120

# 2. Verificar el estado de los hilos y las APCs
thread_checker --pid 4120
```
*Explicación de flags:*
* `--pid 4120`: Especifica el Process ID del proceso a analizar.

**Qué buscar en la salida:**
* En `vad_inspector`: Busca una región RWX `Private` que NO contenga un encabezado `MZ`, sino instrucciones en ensamblador (ej. `fc 48...` típico de shellcode x64).
* En `thread_checker`: Identifica hilos que tengan APCs encoladas apuntando a la región de memoria RWX descubierta.

**Preguntas de análisis:**
1. ¿Qué tipo de payload se inyectó en `notepad.exe`?
2. ¿Cómo difiere la región de memoria de esta técnica comparada con Process Hollowing?
3. ¿Qué mecanismo utiliza el sistema operativo que el atacante abusó para ejecutar el código?

**Respuestas esperadas:**
1. Se inyectó un shellcode x64 diseñado para establecer una reverse shell.
2. A diferencia del Process Hollowing, esta región de memoria no contiene un ejecutable completo (no hay encabezado `MZ`), solo contiene el shellcode puro.
3. El atacante abusó de las Asynchronous Procedure Calls (APCs), que son funciones que se ejecutan asíncronamente en el contexto de un hilo particular cuando este entra en un estado alterable (alertable state).

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| T1055.001  | Dynamic-link Library Injection | DLL `msvcrt_ext.dll` cargada en `explorer.exe` con permisos RWX. |
| T1055.012  | Process Hollowing | Región RWX privada con encabezado MZ en `svchost.exe`. |
| T1055.004  | Asynchronous Procedure Call | Shellcode inyectado en `notepad.exe` ejecutado vía APC queue. |

## Cadena de Ataque Completa

```text
[ Phishing Email ]
        |
        v
[ Descarga update.exe ] ---> (Dropper)
        |
        +---> Inyecta DLL (T1055.001) ---> [ explorer.exe ] ---> (Beacon C2)
        |
        +---> Crea proceso suspendido ---> [ svchost.exe ] ---> (Process Hollowing T1055.012)
        |
        +---> Encola APC (T1055.004) ----> [ notepad.exe ] ---> (Reverse Shell x64)
```

## Limpieza

Una vez finalizado el análisis, sal del contenedor y detén el entorno para liberar recursos.

```bash
# 1. Salir del contenedor
exit

# 2. Detener y eliminar los contenedores
docker-compose down

# 3. (Opcional) Eliminar la imagen si no se volverá a usar
docker rmi lab11-process-injection_analyst
```

## Troubleshooting

1. **Error: `docker-compose: command not found`**
   * *Solución:* Asegúrate de tener instalado Docker Compose. En sistemas modernos, el comando puede ser `docker compose` (sin guion).

2. **Error: `injection_analyzer: command not found` dentro del contenedor**
   * *Solución:* Verifica que estás ejecutando los comandos dentro del contenedor correcto (`injection-analyst`). Si el problema persiste, reconstruye la imagen con `docker-compose build --no-cache`.

3. **Los PIDs de los procesos no coinciden con los de la guía**
   * *Solución:* Los PIDs son dinámicos y cambian en cada ejecución. Utiliza la salida del comando `injection_analyzer` para identificar los PIDs correctos de `explorer.exe`, `svchost.exe` y `notepad.exe` en tu sesión actual.

4. **El contenedor se detiene inmediatamente después de iniciarlo**
   * *Solución:* Revisa los logs del contenedor con `docker logs injection-analyst`. Es posible que haya un error en el entrypoint o falta de memoria en el sistema host.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
