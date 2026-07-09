# Lab 18 — Sigma Rules: Escritura y Conversión
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 09

## Descripción del Escenario
El equipo de Threat Intelligence ha recibido un reporte sobre una nueva campaña de malware que utiliza técnicas de evasión de defensas y robo de credenciales. Se han recolectado varios eventos de logs de sistemas comprometidos, pero el equipo de SOC no tiene reglas de detección para estos comportamientos. Tu misión como Threat Hunter es analizar los eventos de prueba, escribir reglas Sigma para detectar estas tácticas y convertirlas a consultas específicas para los SIEMs de la organización (Elasticsearch y Splunk).

## Objetivos de Aprendizaje
- Comprender la estructura y sintaxis de las reglas Sigma.
- Escribir reglas Sigma personalizadas para detectar comportamientos maliciosos específicos.
- Utilizar `sigma-cli` para validar y convertir reglas Sigma a diferentes lenguajes de consulta (Elasticsearch, Splunk).
- Analizar eventos de logs (JSON) para identificar indicadores de compromiso (IoCs) y comportamientos anómalos.

## Requisitos Previos
- **Docker y Docker Compose:** Instalados y configurados en el sistema host.
- **RAM:** Mínimo 1 GB de RAM disponible.
- **Puertos:** No se requieren puertos expuestos, todo el trabajo se realiza dentro del contenedor.

## Despliegue Paso a Paso

1. **Iniciar el entorno:**
   Navega al directorio del laboratorio y levanta el contenedor en segundo plano.
   ```bash
   docker-compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y asegúrate de que el contenedor `sigma-analyst` esté en estado "Up".

2. **Acceder al contenedor:**
   Abre una sesión interactiva en el contenedor para comenzar a trabajar.
   ```bash
   docker exec -it sigma-analyst bash
   ```
   *Verificación:* El prompt de tu terminal debería cambiar, indicando que estás dentro del contenedor (ej. `root@sigma-analyst:/app#`).

3. **Verificar herramientas:**
   Comprueba que `sigma-cli` y `jq` estén instalados correctamente.
   ```bash
   sigma version
   jq --version
   ```
   *Verificación:* Ambos comandos deben devolver la versión de la herramienta sin errores.

## Ejercicios Paso a Paso

### Ejercicio 1: Análisis de Eventos y Detección de Mimikatz

**Hipótesis de Hunting:**
Los atacantes frecuentemente utilizan herramientas como Mimikatz para extraer credenciales de la memoria. Si un atacante ejecuta Mimikatz, deberíamos ver eventos de creación de procesos o acceso a memoria asociados a este ejecutable.

**Comandos a ejecutar:**
1. Inspeccionar los eventos de prueba para identificar la ejecución de Mimikatz:
   ```bash
   cat /app/test_events.json | jq '.[] | select(.EventID == 1 and (.Image | test("mimikatz"; "i")))'
   ```
   *Explicación:* `cat` lee el archivo JSON, `jq` filtra los eventos donde el `EventID` es 1 (Creación de proceso) y el campo `Image` contiene la palabra "mimikatz" (ignorando mayúsculas/minúsculas).

2. Validar la regla de ejemplo proporcionada:
   ```bash
   sigma check rules/example_mimikatz.yml
   ```
   *Explicación:* `sigma check` valida la sintaxis y estructura de la regla Sigma.

3. Convertir la regla a una consulta de Splunk:
   ```bash
   sigma convert -t splunk -p sysmon rules/example_mimikatz.yml
   ```
   *Explicación:* `sigma convert` transforma la regla. `-t splunk` define el backend de destino (Splunk) y `-p sysmon` aplica el pipeline de Sysmon para mapear los campos correctamente.

**Qué buscar en la salida:**
- En el paso 1, busca los detalles del proceso, como la ruta del ejecutable y los argumentos de línea de comandos.
- En el paso 2, busca un mensaje que indique que la regla es válida.
- En el paso 3, busca la consulta SPL generada (ej. `EventID="1" Image="*\\mimikatz.exe"`).

**Preguntas de análisis:**
1. ¿Qué línea de comandos exacta se utilizó para ejecutar Mimikatz según los eventos de prueba?
2. ¿Por qué es importante utilizar el pipeline (`-p sysmon`) al convertir la regla?
3. ¿Qué otros campos además de `Image` podrían usarse para detectar Mimikatz de forma más robusta?

**Respuestas esperadas:**
1. *Depende del JSON, pero típicamente algo como `mimikatz.exe privilege::debug sekurlsa::logonpasswords exit`.*
2. *El pipeline mapea los campos genéricos de Sigma a los campos específicos que utiliza el origen de datos (en este caso, Sysmon), asegurando que la consulta generada funcione en el SIEM.*
3. *Se podrían usar hashes (SHA256, MD5), el campo `OriginalFileName`, o patrones específicos en `CommandLine`.*

### Ejercicio 2: Creación de Regla para Evasión de Defensas (Borrado de Logs)

**Hipótesis de Hunting:**
Para ocultar sus rastros, los atacantes suelen borrar los registros de eventos de Windows utilizando utilidades nativas como `wevtutil.exe`. Si esto ocurre, deberíamos detectar la ejecución de este comando con los parámetros específicos de borrado.

**Comandos a ejecutar:**
1. Crear un archivo para la nueva regla:
   ```bash
   nano rules/clear_logs.yml
   ```
   *Explicación:* Abre el editor de texto para escribir la regla.

2. Escribir la regla Sigma (copia y pega esto en el editor, luego guarda):
   ```yaml
   title: Borrado de Logs de Eventos via Wevtutil
   id: a1b2c3d4-e5f6-7890-1234-567890abcdef
   status: experimental
   description: Detecta la ejecución de wevtutil para borrar logs de eventos.
   logsource:
       category: process_creation
       product: windows
   detection:
       selection:
           Image|endswith: '\wevtutil.exe'
           CommandLine|contains|all:
               - 'cl'
               - 'System'
       condition: selection
   falsepositives:
       - Scripts de mantenimiento legítimos del administrador.
   level: high
   ```

3. Convertir la regla a Elasticsearch:
   ```bash
   sigma convert -t elasticsearch -p sysmon rules/clear_logs.yml
   ```
   *Explicación:* Convierte la regla recién creada a una consulta compatible con Elasticsearch.

**Qué buscar en la salida:**
- La consulta generada para Elasticsearch, que debería verse similar a `(Image.keyword:*\\wevtutil.exe AND CommandLine:*cl* AND CommandLine:*System*)`.

**Preguntas de análisis:**
1. ¿Qué significa el modificador `|contains|all` en la sección de detección?
2. ¿Cómo modificarías la regla para detectar también el borrado del log de "Security"?
3. ¿Qué nivel de severidad (`level`) le asignarías a esta alerta y por qué?

**Respuestas esperadas:**
1. *Significa que todos los elementos de la lista (en este caso 'cl' y 'System') deben estar presentes en el campo `CommandLine`, sin importar el orden.*
2. *Añadiendo otra condición o modificando la existente para incluir 'Security' en lugar de o además de 'System', por ejemplo usando una lista bajo un nuevo identificador de selección.*
3. *Nivel `high` o `critical`, ya que el borrado de logs es un fuerte indicador de compromiso y un intento activo de evasión de defensas, raramente realizado por usuarios normales.*

### Ejercicio 3: Detección de Persistencia (Tareas Programadas)

**Hipótesis de Hunting:**
Los atacantes crean tareas programadas maliciosas para mantener el acceso al sistema tras un reinicio. La creación de tareas mediante `schtasks.exe` con parámetros sospechosos es un indicador clave de esta técnica.

**Comandos a ejecutar:**
1. Buscar eventos relacionados con `schtasks` en los datos de prueba:
   ```bash
   cat /app/test_events.json | jq '.[] | select(.CommandLine | test("schtasks.*create"; "i"))'
   ```
   *Explicación:* Filtra los eventos donde la línea de comandos contiene "schtasks" seguido de "create".

2. Crear una regla Sigma para detectar esto (`nano rules/schtasks_persistence.yml`):
   ```yaml
   title: Creación de Tarea Programada Sospechosa
   id: b2c3d4e5-f6a7-8901-2345-678901abcdef
   status: experimental
   description: Detecta la creación de tareas programadas que podrían indicar persistencia.
   logsource:
       category: process_creation
       product: windows
   detection:
       selection:
           Image|endswith: '\schtasks.exe'
           CommandLine|contains|all:
               - '/create'
               - '/sc'
               - 'onlogon'
       condition: selection
   falsepositives:
       - Despliegue de software legítimo.
   level: medium
   ```

3. Listar los backends disponibles y convertir a uno diferente (ej. QRadar):
   ```bash
   sigma list backends
   sigma convert -t qradar -p sysmon rules/schtasks_persistence.yml
   ```
   *Explicación:* Muestra todos los formatos de destino soportados y convierte la regla al formato de IBM QRadar.

**Qué buscar en la salida:**
- En el paso 1, los detalles de la tarea programada creada por el atacante.
- En el paso 3, la consulta AQL (Ariel Query Language) generada para QRadar.

**Preguntas de análisis:**
1. ¿Qué indica el parámetro `/sc onlogon` en la línea de comandos de `schtasks`?
2. ¿Por qué esta regla podría generar falsos positivos?
3. ¿Qué otros eventos de Windows (EventIDs) podrían usarse para detectar la creación de tareas programadas además de la creación de procesos (EventID 1)?

**Respuestas esperadas:**
1. *Indica que la tarea programada se ejecutará cada vez que un usuario inicie sesión en el sistema.*
2. *Porque los administradores de sistemas o el software de gestión de TI legítimo también pueden crear tareas programadas que se ejecutan al iniciar sesión.*
3. *EventID 4698 (A scheduled task was created) en el log de Seguridad de Windows.*

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
| :--- | :--- | :--- |
| T1003.001 | OS Credential Dumping: LSASS Memory | Ejecución de `mimikatz.exe` detectada en los logs. |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Uso de `wevtutil.exe cl` para borrar logs. |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Creación de tareas con `schtasks.exe /create`. |

## Cadena de Ataque Completa

```text
[Compromiso Inicial]
        |
        v
[Ejecución de Malware]
        |
        +-----------------------------------+
        |                                   |
        v                                   v
[Robo de Credenciales]             [Persistencia]
(T1003.001 - Mimikatz)       (T1053.005 - Schtasks)
        |                                   |
        +-----------------------------------+
        |
        v
[Evasión de Defensas]
(T1070.001 - Wevtutil)
```

## Limpieza
Una vez finalizado el laboratorio, sal del contenedor y detén los servicios para liberar recursos.
```bash
# Salir del contenedor
exit

# Detener y eliminar el contenedor
docker-compose down
```

## Troubleshooting

- **Problema:** `sigma: command not found` dentro del contenedor.
  **Solución:** Asegúrate de estar ejecutando los comandos dentro del contenedor `sigma-analyst` y no en tu máquina host. Verifica que la instalación en el Dockerfile se completó correctamente.
- **Problema:** Error al convertir la regla: `Pipeline sysmon is not supported`.
  **Solución:** Verifica que estás escribiendo correctamente el nombre del pipeline (`-p sysmon`). Puedes listar los pipelines disponibles con `sigma list pipelines`.
- **Problema:** `jq` devuelve un error de parseo.
  **Solución:** Asegúrate de que el archivo `/app/test_events.json` tenga un formato JSON válido. Si lo editaste, revisa la sintaxis.
- **Problema:** La regla Sigma falla la validación con `sigma check`.
  **Solución:** Revisa la indentación de tu archivo YAML. YAML es muy estricto con los espacios (no uses tabulaciones). Asegúrate de que todos los campos requeridos (`title`, `logsource`, `detection`, `condition`) estén presentes.
