# Lab 13 - DLL Side-Loading + Trojan Analysis - MAR404 Cacería de Amenazas - Clase 07

## Descripción del Escenario
El equipo de SOC ha detectado actividad anómala proveniente de un endpoint de un usuario del departamento de finanzas. La alerta inicial indica una posible ejecución sospechosa relacionada con `OneDriveUpdater.exe`. Tras una investigación preliminar, se sospecha que un actor de amenazas ha utilizado la técnica de DLL Side-Loading para ejecutar un troyano personalizado denominado "SilentDrop RAT". Este troyano parece tener capacidades avanzadas de espionaje, incluyendo keylogger, captura de pantalla (screenshot), monitorización del portapapeles (clipboard monitor) y exfiltración de datos hacia un servidor de Comando y Control (C2). Como Threat Hunter, tu misión es analizar los artefactos proporcionados en este entorno aislado para confirmar la técnica de inyección, perfilar las capacidades del troyano y descubrir sus mecanismos de persistencia.

## Objetivos de Aprendizaje
* Comprender y detectar la técnica de DLL Side-Loading (T1574.002) mediante el análisis de dependencias y ejecuciones anómalas.
* Perfilar las capacidades de un troyano (SilentDrop RAT) identificando funciones de keylogging, captura de pantalla y exfiltración.
* Identificar mecanismos de persistencia en sistemas comprometidos, específicamente a través de tareas programadas.
* Mapear los hallazgos técnicos con el framework MITRE ATT&CK para estructurar el reporte del incidente.

## Requisitos Previos
* **Docker y Docker Compose:** Instalados y configurados en el sistema host.
* **Memoria RAM:** Mínimo 2 GB de RAM disponibles para el contenedor.
* **Puertos:** No se requieren puertos expuestos para este laboratorio, el análisis es local dentro del contenedor.
* **Conocimientos:** Familiaridad básica con la línea de comandos de Linux y conceptos de análisis de malware.

## Despliegue Paso a Paso
1. **Clonar o acceder al directorio del laboratorio:**
   Asegúrate de estar en el directorio correcto del laboratorio.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-07/docker/lab13-dll-injection/
   ```
2. **Levantar el entorno con Docker Compose:**
   Ejecuta el siguiente comando para construir e iniciar el contenedor en segundo plano.
   ```bash
   docker-compose up -d
   ```
3. **Verificar el estado del contenedor:**
   Asegúrate de que el contenedor `dll-analyst` esté en ejecución.
   ```bash
   docker ps | grep dll-analyst
   ```
4. **Acceder al contenedor:**
   Inicia una sesión interactiva de bash dentro del contenedor para comenzar el análisis.
   ```bash
   docker exec -it dll-analyst bash
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Detección de DLL Side-Loading
**Hipótesis de Hunting:** El adversario ha colocado una DLL maliciosa en el mismo directorio que un ejecutable legítimo (`OneDriveUpdater.exe`) para forzar su carga en lugar de la DLL legítima del sistema.

**Comandos Exactos:**
```bash
# Ejecutar el analizador de DLLs para buscar dependencias anómalas en el directorio de OneDrive
dll_analyzer --scan /opt/artifacts/OneDrive/ --detect-sideloading
```
*Explicación de flags:*
* `--scan /opt/artifacts/OneDrive/`: Indica el directorio donde se encuentran los artefactos recolectados del endpoint.
* `--detect-sideloading`: Activa el módulo heurístico para comparar las DLLs cargadas con las firmas de DLLs legítimas del sistema operativo.

**Qué buscar en la salida:**
Busca advertencias sobre firmas inválidas, hashes que no coinciden con bases de datos conocidas, o DLLs cargadas desde el directorio de la aplicación en lugar de `C:\Windows\System32`.

**Preguntas de Análisis:**
1. ¿Cuál es el nombre de la DLL que fue cargada mediante Side-Loading?
2. ¿Qué funciones exportadas (exports) anómalas presenta esta DLL en comparación con la legítima?
3. ¿Cuál es el hash SHA256 de la DLL maliciosa?

**Respuestas Esperadas:**
1. La DLL cargada es `version.dll`.
2. Presenta exports adicionales no estándar como `StartSilentDrop` y `InitHook`.
3. El hash SHA256 es `a1b2c3d4e5f6...` (el hash específico mostrado en la salida de la herramienta).

### Ejercicio 2: Perfilado de Capacidades del Troyano "SilentDrop RAT"
**Hipótesis de Hunting:** La DLL maliciosa inyectada actúa como un cargador (loader) para el troyano "SilentDrop RAT", el cual posee módulos de espionaje activos en la memoria del proceso.

**Comandos Exactos:**
```bash
# Analizar el volcado de memoria del proceso OneDriveUpdater.exe
trojan_profiler --memory-dump /opt/artifacts/memory/onedrive_mem.dmp --extract-modules
```
*Explicación de flags:*
* `--memory-dump /opt/artifacts/memory/onedrive_mem.dmp`: Especifica el archivo de volcado de memoria a analizar.
* `--extract-modules`: Extrae e identifica los módulos inyectados o cargados dinámicamente en la memoria del proceso.

**Qué buscar en la salida:**
Identifica cadenas de texto (strings), llamadas a APIs de Windows relacionadas con hooks de teclado (ej. `SetWindowsHookEx`), captura de pantalla (ej. `BitBlt`) y acceso al portapapeles (ej. `GetClipboardData`).

**Preguntas de Análisis:**
1. ¿Qué APIs de Windows indican la presencia de un keylogger?
2. ¿Se encontraron evidencias de monitorización del portapapeles? ¿Cuáles?
3. ¿Hacia qué dirección IP o dominio intenta exfiltrar los datos el troyano?

**Respuestas Esperadas:**
1. Se observan llamadas a `SetWindowsHookExA` y `GetAsyncKeyState`.
2. Sí, se detectaron llamadas a `OpenClipboard` y `GetClipboardData`.
3. El troyano intenta conectarse a `c2.malicious-domain.com` en el puerto 443.

### Ejercicio 3: Identificación de Mecanismos de Persistencia
**Hipótesis de Hunting:** Para asegurar que el troyano se ejecute tras un reinicio del sistema, el atacante ha creado un mecanismo de persistencia, probablemente abusando de las tareas programadas de Windows.

**Comandos Exactos:**
```bash
# Verificar los artefactos de persistencia recolectados del sistema
persistence_checker --analyze-tasks /opt/artifacts/tasks/ --check-registry /opt/artifacts/registry/SOFTWARE
```
*Explicación de flags:*
* `--analyze-tasks /opt/artifacts/tasks/`: Analiza los archivos XML de las tareas programadas exportadas.
* `--check-registry /opt/artifacts/registry/SOFTWARE`: Revisa la colmena del registro en busca de llaves de auto-inicio (Run/RunOnce).

**Qué buscar en la salida:**
Busca tareas programadas que ejecuten `OneDriveUpdater.exe` desde una ubicación inusual o con parámetros sospechosos, o entradas en el registro que apunten al ejecutable comprometido.

**Preguntas de Análisis:**
1. ¿Qué mecanismo de persistencia fue utilizado por el atacante?
2. ¿Cuál es el nombre de la tarea programada maliciosa?
3. ¿Con qué frecuencia o bajo qué condiciones se ejecuta esta tarea?

**Respuestas Esperadas:**
1. El atacante utilizó una Tarea Programada (Scheduled Task).
2. La tarea se llama `OneDrive Sync Update`.
3. Se ejecuta al iniciar sesión cualquier usuario (Logon Trigger).

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| T1574.002 | DLL Side-Loading | Ejecución de `version.dll` maliciosa por `OneDriveUpdater.exe`. |
| T1056.001 | Keylogging | Llamadas a `SetWindowsHookEx` detectadas en memoria. |
| T1113 | Screen Capture | Llamadas a APIs gráficas como `BitBlt` en el volcado de memoria. |
| T1115 | Clipboard Data | Uso de `GetClipboardData` por el proceso comprometido. |
| T1041 | Exfiltration Over C2 Channel | Conexiones de red salientes hacia `c2.malicious-domain.com`. |
| T1053.005 | Scheduled Task | Tarea `OneDrive Sync Update` configurada para persistencia. |

## Cadena de Ataque Completa

```text
[Ejecución Inicial]
        |
        v
+-----------------------+
| Tarea Programada      | (T1053.005)
| "OneDrive Sync Update"|
+-----------------------+
        |
        v
[Ejecución de Binario Legítimo]
        |
        v
+-----------------------+
| OneDriveUpdater.exe   |
+-----------------------+
        |
        v
[Carga de DLL Maliciosa]
        |
        v
+-----------------------+
| version.dll           | (T1574.002 - DLL Side-Loading)
+-----------------------+
        |
        v
[Inyección/Ejecución de Payload]
        |
        v
+-----------------------+
| SilentDrop RAT        |
+-----------------------+
        |
        +---> [Keylogging] (T1056.001)
        |
        +---> [Screen Capture] (T1113)
        |
        +---> [Clipboard Data] (T1115)
        |
        v
[Exfiltración]
        |
        v
+-----------------------+
| Servidor C2           | (T1041)
+-----------------------+
```

## Limpieza
Una vez finalizado el análisis, es importante detener y eliminar los contenedores para liberar recursos del sistema.
```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores, redes y volúmenes asociados
docker-compose down -v
```

## Troubleshooting
* **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  * **Solución:** Aunque este laboratorio no expone puertos, si modificaste el `docker-compose.yml`, asegúrate de que los puertos mapeados no estén siendo utilizados por otro servicio en tu host. Usa `netstat -tuln` para verificar.
* **Problema:** No se encuentra el comando `dll_analyzer` dentro del contenedor.
  * **Solución:** Verifica que estás ejecutando los comandos dentro del contenedor correcto (`dll-analyst`). Si el problema persiste, revisa los logs de construcción con `docker-compose logs` para asegurar que la instalación de las herramientas fue exitosa.
* **Problema:** Los archivos de artefactos en `/opt/artifacts/` no existen.
  * **Solución:** Es posible que el volumen no se haya montado correctamente. Reinicia el entorno ejecutando `docker-compose down -v` seguido de `docker-compose up -d`.
* **Problema:** Permiso denegado al intentar ejecutar las herramientas de análisis.
  * **Solución:** Asegúrate de tener los permisos de ejecución correctos. Puedes intentar ejecutarlas con `sudo` si está disponible, o verificar los permisos con `ls -l /usr/local/bin/`.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
