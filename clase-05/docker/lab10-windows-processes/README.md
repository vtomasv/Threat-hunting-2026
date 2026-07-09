# Lab 10 — Find Evil: Identificar Procesos Maliciosos (Avanzado)
Curso: MAR404 — Cacería de Amenazas
Clase: 05

## Descripción del Escenario

El equipo del Centro de Operaciones de Seguridad (SOC) ha detectado un comportamiento anómalo en una estación de trabajo crítica de la red corporativa. Tras una alerta inicial de conexión a una IP de reputación dudosa, se ha capturado un volcado de memoria del equipo afectado. El atacante parece haber utilizado técnicas sofisticadas de evasión para ocultar su presencia en el sistema. Como analista de Threat Hunting, tu misión es analizar los artefactos extraídos de la memoria para identificar los procesos maliciosos, comprender las técnicas de evasión empleadas y reconstruir la cadena de ataque.

## Objetivos de Aprendizaje

- Identificar técnicas avanzadas de inyección de código como Process Hollowing mediante el análisis de regiones de memoria (VAD).
- Detectar la carga lateral de bibliotecas dinámicas (DLL Side-Loading) analizando procesos legítimos.
- Reconocer técnicas de falsificación de procesos padre (Parent PID Spoofing) y manipulación de tokens de acceso.
- Correlacionar conexiones de red anómalas con procesos específicos para identificar la infraestructura de Comando y Control (C2).

## Requisitos Previos

- **Docker y Docker Compose**: Instalados y configurados en el sistema anfitrión.
- **Memoria RAM**: Mínimo 2 GB de RAM disponibles para el contenedor.
- **Puertos**: No se requieren puertos expuestos para este laboratorio, ya que el análisis se realiza internamente en el contenedor.

## Despliegue Paso a Paso

1. **Iniciar el entorno del laboratorio**:
   Ejecuta el siguiente comando en el directorio del laboratorio para levantar el contenedor en segundo plano.
   ```bash
   docker-compose up -d
   ```
   *Verificación*: Deberías ver un mensaje indicando que el contenedor `findevil-analyst` se ha iniciado correctamente.

2. **Acceder al contenedor de análisis**:
   Ingresa al contenedor interactivo para comenzar el análisis.
   ```bash
   docker exec -it findevil-analyst bash
   ```
   *Verificación*: El prompt de tu terminal debería cambiar, indicando que ahora estás dentro del contenedor (por ejemplo, `root@findevil-analyst:/#`).

3. **Verificar los archivos de datos**:
   Asegúrate de que los artefactos de memoria estén disponibles en el directorio `/data`.
   ```bash
   ls -la /data/
   ```
   *Verificación*: Debes ver archivos como `vol3_pslist.txt`, `vol3_cmdline.txt`, `vol3_netscan.txt`, `vol3_malfind.txt`, `processes.json` y `connections.json`.

## Ejercicios Paso a Paso

### Ejercicio 1: Detección de Process Hollowing

**Hipótesis de Hunting**: Los atacantes frecuentemente inyectan código malicioso en procesos legítimos de Windows (como `notepad.exe`) para evadir la detección. Esto suele dejar rastros en las regiones de memoria (VAD) con permisos de lectura, escritura y ejecución (RWX), y a menudo se asocia con conexiones de red anómalas.

**Comandos a ejecutar**:
1. Buscar procesos `notepad.exe` y sus PIDs:
   ```bash
   cat /data/vol3_pslist.txt | grep -i "notepad.exe"
   ```
   *Explicación*: `cat` lee el archivo de lista de procesos y `grep -i` filtra las líneas que contienen "notepad.exe" sin distinguir mayúsculas de minúsculas.

2. Verificar inyecciones de código en el PID encontrado usando los resultados de malfind:
   ```bash
   cat /data/vol3_malfind.txt | grep "5544"
   ```
   *Explicación*: Filtra el archivo de resultados de malfind para buscar el PID específico (5544), buscando regiones de memoria inyectadas.

3. Correlacionar el PID con conexiones de red:
   ```bash
   cat /data/vol3_netscan.txt | grep "5544"
   ```
   *Explicación*: Busca el PID en el archivo de conexiones de red para identificar si el proceso inyectado se está comunicando con el exterior.

**Qué buscar en la salida**:
- En el primer comando, identifica el PID de `notepad.exe`.
- En el segundo comando, busca indicaciones de regiones de memoria con protección `PAGE_EXECUTE_READWRITE` (RWX).
- En el tercer comando, observa si hay conexiones establecidas (ESTABLISHED) hacia IPs externas.

**Preguntas de Análisis**:
1. ¿Cuál es el PID del proceso `notepad.exe` sospechoso?
2. ¿Qué permisos de memoria inusuales se observan en el proceso según la salida de malfind?
3. ¿A qué dirección IP y puerto se está conectando este proceso?

**Deberias haber logrado este resultado**:
- *Respuesta 1*: El PID es 5544.
- *Respuesta 2*: Se observan regiones de memoria con permisos RWX (Read-Write-Execute), lo cual es un fuerte indicador de inyección de código (Process Hollowing).
- *Respuesta 3*: El proceso tiene una conexión establecida hacia una IP externa (C2), evidenciando la comunicación maliciosa.

---

### Ejercicio 2: Identificación de DLL Side-Loading

**Hipótesis de Hunting**: Los adversarios pueden colocar una DLL maliciosa con el mismo nombre que una DLL legítima en el directorio de una aplicación confiable (como `OneDrive.exe`). Cuando la aplicación se ejecuta, carga la DLL maliciosa en lugar de la legítima.

**Comandos a ejecutar**:
1. Buscar procesos relacionados con OneDrive:
   ```bash
   cat /data/vol3_pslist.txt | grep -i "OneDrive.exe"
   ```
   *Explicación*: Filtra la lista de procesos para encontrar instancias de OneDrive.exe.

2. Analizar los datos estructurados para buscar módulos no firmados o sospechosos cargados por el PID de OneDrive:
   ```bash
   jq '.[] | select(.pid == 3300) | .modules[] | select(.signed == false)' /data/processes.json
   ```
   *Explicación*: Usa `jq` para parsear el archivo JSON de procesos, selecciona el proceso con PID 3300 (OneDrive.exe), itera sobre sus módulos cargados y filtra aquellos que no están firmados digitalmente.

**Qué buscar en la salida**:
- Identifica el PID de `OneDrive.exe`.
- En la salida de `jq`, busca el nombre de la DLL que no está firmada y su ruta de carga.

**Preguntas de Análisis**:
1. ¿Cuál es el PID del proceso `OneDrive.exe`?
2. ¿Qué DLL específica se ha cargado que carece de firma digital?
3. ¿Por qué la carga de esta DLL específica por parte de OneDrive.exe es considerada sospechosa?

**Deberias haber logrado este resultado**:
- *Respuesta 1*: El PID es 3300.
- *Respuesta 2*: La DLL no firmada es `version.dll`.
- *Respuesta 3*: `version.dll` es una biblioteca estándar de Windows que normalmente debería estar firmada por Microsoft y cargarse desde `C:\Windows\System32`. Si se carga desde el directorio de la aplicación y no está firmada, es un claro caso de DLL Side-Loading.

---

### Ejercicio 3: Detección de Parent PID Spoofing y Token Manipulation

**Hipótesis de Hunting**: Para ocultar la ejecución de comandos maliciosos, los atacantes pueden falsificar el proceso padre de un ejecutable (Parent PID Spoofing) y manipular los tokens de acceso para escalar privilegios a SYSTEM (Token Manipulation).

**Comandos a ejecutar**:
1. Buscar procesos `svchost.exe` anómalos (por ejemplo, creados mucho después del inicio del sistema):
   ```bash
   cat /data/vol3_pslist.txt | grep -i "svchost.exe"
   ```
   *Explicación*: Lista todos los procesos svchost.exe para analizar sus tiempos de creación y PIDs padre (PPID).

2. Analizar la línea de comandos de procesos sospechosos:
   ```bash
   cat /data/vol3_cmdline.txt | grep "4420"
   ```
   *Explicación*: Busca la línea de comandos exacta utilizada para lanzar el svchost.exe sospechoso (PID 4420).

3. Buscar procesos `cmd.exe` ejecutándose con privilegios elevados de forma anómala:
   ```bash
   jq '.[] | select(.name == "cmd.exe" and .user == "NT AUTHORITY\\SYSTEM")' /data/processes.json
   ```
   *Explicación*: Usa `jq` para encontrar procesos cmd.exe que se estén ejecutando bajo el usuario SYSTEM.

**Qué buscar en la salida**:
- Un `svchost.exe` que no tenga como padre a `services.exe` o que haya sido creado significativamente más tarde que los demás.
- Un `cmd.exe` ejecutándose como SYSTEM pero cuyo proceso padre pertenece a un usuario estándar.

**Preguntas de Análisis**:
1. ¿Qué anomalías presenta el proceso `svchost.exe` con PID 4420 en comparación con otros procesos svchost?
2. ¿Cuál es el PID del proceso `cmd.exe` que se ejecuta como SYSTEM?
3. ¿Qué técnica sugiere el hecho de que un `cmd.exe` tenga privilegios SYSTEM pero un proceso padre de un usuario normal?

**Deberias haber logrado este resultado**:
- *Respuesta 1*: El `svchost.exe` (PID 4420) fue creado horas después del inicio del sistema y tiene muy pocos hilos (threads) en comparación con un svchost legítimo, indicando PPID Spoofing.
- *Respuesta 2*: El PID del `cmd.exe` es 6100.
- *Respuesta 3*: Sugiere Token Manipulation (Robo de Tokens), donde el atacante ha duplicado un token de SYSTEM y lo ha aplicado a un proceso iniciado por un usuario estándar para escalar privilegios.

## Mapeo MITRE ATT&CK

| Táctica | Técnica ID | Nombre de la Técnica | Evidencia en el Laboratorio |
|---------|------------|----------------------|-----------------------------|
| Defense Evasion | T1055.012 | Process Hollowing | `notepad.exe` (PID 5544) con regiones de memoria RWX y conexión de red activa. |
| Defense Evasion | T1574.002 | DLL Side-Loading | `OneDrive.exe` (PID 3300) cargando `version.dll` no firmada. |
| Defense Evasion | T1134.004 | Parent PID Spoofing | `svchost.exe` (PID 4420) creado tardíamente con PPID falsificado. |
| Privilege Escalation | T1134.001 | Token Manipulation | `cmd.exe` (PID 6100) ejecutándose como SYSTEM con un proceso padre de usuario estándar. |

## Cadena de Ataque Completa

```text
[Ejecución Inicial]
        |
        v
+-------------------+
| OneDrive.exe      |  <-- DLL Side-Loading (T1574.002)
| (PID: 3300)       |      Carga version.dll maliciosa
+-------------------+
        |
        v
[Evasión de Defensas]
        |
        v
+-------------------+
| svchost.exe       |  <-- Parent PID Spoofing (T1134.004)
| (PID: 4420)       |      Falsifica proceso padre para ocultarse
+-------------------+
        |
        v
[Escalada de Privilegios]
        |
        v
+-------------------+
| cmd.exe           |  <-- Token Manipulation (T1134.001)
| (PID: 6100)       |      Obtiene privilegios SYSTEM
+-------------------+
        |
        v
[Comando y Control]
        |
        v
+-------------------+
| notepad.exe       |  <-- Process Hollowing (T1055.012)
| (PID: 5544)       |      Inyectado, establece conexión C2
+-------------------+
```

## Limpieza

Una vez finalizado el análisis, sal del contenedor y detén el entorno de Docker para liberar recursos.

```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores del laboratorio
docker-compose down
```

## Troubleshooting

- **Problema**: El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  **Solución**: Aunque este laboratorio no expone puertos, si hay conflictos, verifica qué contenedores están corriendo con `docker ps` y detén los innecesarios con `docker stop <container_id>`.

- **Problema**: No se encuentra el comando `jq` dentro del contenedor.
  **Solución**: El contenedor debería tener `jq` preinstalado. Si no es así, puedes instalarlo ejecutando `apt-get update && apt-get install -y jq` dentro del contenedor.

- **Problema**: Los archivos en `/data/` aparecen vacíos o no existen.
  **Solución**: Asegúrate de haber ejecutado `docker-compose up -d` desde el directorio correcto (`lab10-windows-processes`). Si el problema persiste, reinicia el entorno con `docker-compose down` seguido de `docker-compose up -d`.

- **Problema**: Los comandos `grep` no devuelven ninguna salida.
  **Solución**: Verifica que estás escribiendo correctamente los PIDs o nombres de procesos. Recuerda que Linux distingue entre mayúsculas y minúsculas; usa el flag `-i` con `grep` si no estás seguro de la capitalización.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
