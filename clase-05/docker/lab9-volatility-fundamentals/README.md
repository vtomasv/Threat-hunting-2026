# Lab 9 — Análisis de Procesos con Volatility 3
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 05

## Descripción del Escenario

El equipo de SOC ha detectado actividad anómala en una estación de trabajo Windows 10 de un usuario del departamento de finanzas. Se sospecha que el equipo ha sido comprometido mediante un ataque de phishing, lo que permitió a un atacante ejecutar código malicioso y establecer persistencia. El equipo de respuesta a incidentes ha capturado un volcado de memoria (memory dump) del equipo afectado. Este laboratorio presenta un entorno simulado que emula la salida de Volatility 3 para este volcado de memoria. El dataset contiene procesos legítimos del sistema operativo mezclados con **4 procesos maliciosos** que utilizan diferentes técnicas de evasión. Tu misión como Threat Hunter es analizar la información de los procesos, identificar las anomalías y descubrir las técnicas utilizadas por el atacante.

## Objetivos de Aprendizaje

*   Comprender la estructura normal de los procesos en un sistema operativo Windows.
*   Identificar técnicas de evasión comunes como Masquerading (T1036.005) y Credential Dumping (T1003.001).
*   Analizar relaciones padre-hijo (Parent-Child relationships) para detectar ejecuciones anómalas.
*   Examinar los argumentos de línea de comandos (cmdline) en busca de comandos ofuscados o sospechosos.
*   Correlacionar información de procesos con conexiones de red para identificar posibles canales de Comando y Control (C2).

## Requisitos Previos

*   **Docker y Docker Compose:** Instalados y configurados en el sistema host.
*   **Memoria RAM:** Al menos 2 GB de RAM disponibles para el contenedor.
*   **Puertos:** No se requieren puertos expuestos para este laboratorio, ya que la interacción es a través de la terminal del contenedor.

## Despliegue Paso a Paso

1.  **Clonar o navegar al directorio del laboratorio:**
    Asegúrate de estar en el directorio correcto donde se encuentra el archivo `docker-compose.yml`.
    ```bash
    cd /home/ubuntu/MAR404-threat-hunting-2026/clase-05/docker/lab9-volatility-fundamentals/
    ```

2.  **Levantar el entorno:**
    Ejecuta el siguiente comando para construir e iniciar el contenedor en segundo plano.
    ```bash
    docker-compose up -d
    ```

3.  **Verificar el estado del contenedor:**
    Asegúrate de que el contenedor `vol3-analyst` esté en ejecución.
    ```bash
    docker ps | grep vol3-analyst
    ```
    *Deberías ver el contenedor listado con el estado "Up".*

4.  **Acceder al contenedor:**
    Inicia una sesión interactiva de bash dentro del contenedor para comenzar el análisis.
    ```bash
    docker exec -it vol3-analyst bash
    ```

## Ejercicios Paso a Paso

### Ejercicio 1: Análisis de Procesos y Masquerading

**Hipótesis de hunting:** Los atacantes a menudo ocultan sus procesos maliciosos dándoles nombres similares a los procesos legítimos del sistema operativo (Masquerading) o ejecutándolos desde rutas inusuales.

**Comandos EXACTOS a ejecutar:**
```bash
# Ejecutar el script que simula la salida de pslist y filtrar por procesos comunes
hunt_processes | grep -iE "svchost|scvhost"
```
*Explicación de flags:* `|` redirige la salida del primer comando al segundo. `grep` busca patrones de texto. `-i` ignora mayúsculas y minúsculas. `-E` permite el uso de expresiones regulares extendidas.

**Qué buscar en la salida:**
Busca nombres de procesos que estén mal escritos intencionalmente (ej. `scvhost.exe` en lugar de `svchost.exe`). También presta atención a las rutas de ejecución si están disponibles, buscando procesos del sistema ejecutándose desde directorios temporales o de usuario.

**Preguntas de análisis:**
1.  ¿Encontraste algún proceso con un nombre que intente imitar a un proceso legítimo de Windows?
2.  ¿Cuál es el PID de este proceso sospechoso?
3.  ¿Por qué un atacante utilizaría esta técnica?

**Respuestas esperadas:**
1.  Sí, se observa un proceso llamado `scvhost.exe` que intenta imitar a `svchost.exe`.
2.  El PID del proceso `scvhost.exe` es 6672.
3.  Para evadir la detección visual por parte de administradores o analistas de seguridad que revisan la lista de procesos, ya que a simple vista parece un proceso normal del sistema.

### Ejercicio 2: Análisis de Relaciones Padre-Hijo y Credential Dumping

**Hipótesis de hunting:** Ciertos procesos críticos de Windows, como `lsass.exe`, tienen relaciones padre-hijo muy específicas y predecibles. Desviaciones en estas relaciones, como múltiples instancias o padres incorrectos, son fuertes indicadores de compromiso, como intentos de volcado de credenciales.

**Comandos EXACTOS a ejecutar:**
```bash
# Ejecutar el script que simula la salida de pstree y buscar lsass.exe
hunt_processes | grep -i -B 2 -A 2 "lsass.exe"
```
*Explicación de flags:* `-B 2` muestra 2 líneas antes de la coincidencia (Before). `-A 2` muestra 2 líneas después de la coincidencia (After). Esto ayuda a ver el contexto y el proceso padre.

**Qué buscar en la salida:**
Busca cuántas instancias de `lsass.exe` se están ejecutando. En un sistema normal, generalmente solo hay una instancia de `lsass.exe` y su proceso padre suele ser `wininit.exe`. Identifica si hay instancias adicionales y cuál es su proceso padre (PPID).

**Preguntas de análisis:**
1.  ¿Cuántas instancias de `lsass.exe` encontraste en ejecución?
2.  ¿Cuál es el PID y el PPID de la instancia anómala de `lsass.exe`?
3.  ¿Qué proceso inició esta instancia anómala y por qué es sospechoso?

**Respuestas esperadas:**
1.  Se encuentran dos instancias de `lsass.exe`.
2.  La instancia anómala tiene el PID 7788.
3.  El proceso padre (PPID) de la instancia anómala es `cmd.exe`. Esto es altamente sospechoso porque `lsass.exe` nunca debería ser iniciado por una consola de comandos; esto indica un probable intento de volcado de credenciales (Credential Dumping).

### Ejercicio 3: Análisis de Línea de Comandos y Ejecución Ofuscada

**Hipótesis de hunting:** Los atacantes utilizan la línea de comandos para ejecutar scripts maliciosos, a menudo utilizando técnicas de ofuscación como la codificación en Base64 en PowerShell para ocultar sus intenciones a los sistemas de monitoreo.

**Comandos EXACTOS a ejecutar:**
```bash
# Ejecutar el script que simula la salida de cmdline y buscar ejecuciones de PowerShell o cmd
hunt_processes | grep -iE "powershell|cmd.exe"
```

**Qué buscar en la salida:**
Revisa los argumentos pasados a `cmd.exe` o `powershell.exe`. Busca flags sospechosos como `-enc`, `-EncodedCommand`, `-w hidden`, o cadenas largas de texto aparentemente aleatorio que podrían ser código codificado en Base64.

**Preguntas de análisis:**
1.  ¿Identificaste alguna ejecución de `cmd.exe` o `powershell.exe` con argumentos sospechosos?
2.  ¿Cuál es el PID del proceso que ejecuta el comando sospechoso?
3.  ¿Qué técnica específica se está utilizando en la línea de comandos encontrada?

**Respuestas esperadas:**
1.  Sí, se observa una ejecución de `cmd.exe` que incluye un comando de PowerShell codificado.
2.  El PID del proceso `cmd.exe` malicioso es 4500.
3.  Se está utilizando la técnica de Encoded PowerShell (T1059.001), evidenciada por el uso del flag `-enc` seguido de una cadena codificada, lo que permite ejecutar comandos ocultando su contenido en texto plano.

### Ejercicio 4: Validación Automática con Find Evil

**Hipótesis de hunting:** Las herramientas automatizadas pueden ayudar a identificar rápidamente anomalías conocidas basándose en reglas predefinidas, acelerando el proceso de triaje inicial.

**Comandos EXACTOS a ejecutar:**
```bash
# Ejecutar la herramienta de validación automática
find_evil_checker
```

**Qué buscar en la salida:**
Revisa la salida de la herramienta para ver qué procesos ha marcado como sospechosos o maliciosos. Compara estos resultados con los hallazgos de tus análisis manuales en los ejercicios anteriores.

**Preguntas de análisis:**
1.  ¿Qué procesos identificó la herramienta `find_evil_checker` como maliciosos?
2.  ¿Coinciden los resultados de la herramienta con tus hallazgos manuales?
3.  ¿Identificó la herramienta algún proceso malicioso adicional que no habías encontrado? (Ej. un `svchost.exe` anómalo).

**Respuestas esperadas:**
1.  La herramienta debería identificar `scvhost.exe` (PID 6672), `lsass.exe` anómalo (PID 7788), `cmd.exe` con PowerShell codificado (PID 4500) y un `svchost.exe` anómalo (PID 8890).
2.  Sí, deberían coincidir con los hallazgos de los ejercicios 1, 2 y 3.
3.  Sí, la herramienta también identifica un `svchost.exe` (PID 8890) ejecutándose desde `C:\Temp\` y sin el flag `-k`, lo cual es un comportamiento anómalo para este proceso del sistema (Wrong Path / Masquerading).

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
| :--- | :--- | :--- |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Proceso `scvhost.exe` (PID 6672) imitando a `svchost.exe`. Proceso `svchost.exe` (PID 8890) ejecutándose desde `C:\Temp\`. |
| T1003.001 | OS Credential Dumping: LSASS Memory | Segunda instancia de `lsass.exe` (PID 7788) iniciada por `cmd.exe`. |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Ejecución de `cmd.exe` (PID 4500) lanzando PowerShell con el flag `-enc` (EncodedCommand). |

## Cadena de Ataque Completa

```text
[Phishing Email] --> [User Execution]
                           |
                           v
                  [cmd.exe (PID 4500)] --(T1059.001: Encoded PowerShell)--> Descarga y Ejecución de Payload
                           |
                           +--> [scvhost.exe (PID 6672)] --(T1036.005: Masquerading)--> Persistencia/C2
                           |
                           +--> [svchost.exe (PID 8890)] --(T1036.005: Wrong Path)--> Ejecución Oculta en C:\Temp\
                           |
                           +--> [lsass.exe (PID 7788)] --(T1003.001: Credential Dumping)--> Robo de Credenciales
```

## Limpieza

Una vez finalizado el laboratorio, es importante limpiar el entorno para liberar recursos.

1.  **Salir del contenedor:**
    ```bash
    exit
    ```
2.  **Detener y eliminar el contenedor:**
    Asegúrate de estar en el directorio del laboratorio.
    ```bash
    docker-compose down
    ```

## Troubleshooting

*   **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
    *   **Solución:** Aunque este laboratorio no expone puertos, si modificaste el `docker-compose.yml`, asegúrate de que no haya conflictos. Revisa con `docker ps` si hay otros contenedores usando los mismos recursos.
*   **Problema:** No se encuentra el comando `hunt_processes` o `find_evil_checker` dentro del contenedor.
    *   **Solución:** Asegúrate de haber accedido al contenedor correcto (`vol3-analyst`). Verifica que la construcción de la imagen Docker se haya completado sin errores.
*   **Problema:** El contenedor se detiene inmediatamente después de iniciarlo.
    *   **Solución:** Revisa los logs del contenedor con `docker logs vol3-analyst` para identificar posibles errores durante el inicio o la ejecución del entrypoint.
*   **Problema:** Permisos denegados al ejecutar docker.
    *   **Solución:** Asegúrate de que tu usuario pertenezca al grupo `docker` o ejecuta los comandos con `sudo` (ej. `sudo docker-compose up -d`).
