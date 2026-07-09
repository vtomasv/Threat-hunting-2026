# Lab 17 — Hunting con Osquery
## Curso: MAR404 — Cacería de Amenazas
## Clase: 09

---

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha recibido una alerta de comportamiento anómalo proveniente de un endpoint crítico de la organización. Se sospecha que un actor de amenazas ha logrado comprometer el sistema, estableciendo persistencia y abriendo canales de comunicación hacia el exterior. Como Threat Hunter, tu misión es utilizar Osquery para interrogar el sistema operativo, identificar los procesos maliciosos, descubrir las tareas programadas ocultas y rastrear las conexiones de red sospechosas para reconstruir la cadena de ataque.

## Objetivos de Aprendizaje
* Comprender el uso de Osquery como herramienta de interrogación de endpoints mediante sintaxis SQL.
* Identificar técnicas de persistencia comunes, como tareas programadas ocultas y elementos de inicio maliciosos.
* Detectar procesos ejecutándose desde rutas inusuales y conexiones de red anómalas.
* Mapear los hallazgos técnicos con las tácticas y técnicas del framework MITRE ATT&CK.

## Requisitos Previos
* **Docker y Docker Compose:** Instalados y configurados en el sistema host.
* **Memoria RAM:** Mínimo 2 GB de RAM disponibles para el contenedor.
* **Puertos:** No se requieren puertos expuestos hacia el host, la interacción es mediante consola interactiva.

## Despliegue Paso a Paso

1. **Clonar o acceder al directorio del laboratorio:**
   Asegúrate de estar en el directorio correcto donde se encuentra el archivo `docker-compose.yml`.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-09/docker/lab17-osquery-hunting/
   ```

2. **Levantar el entorno:**
   Ejecuta el siguiente comando para iniciar el contenedor en segundo plano.
   ```bash
   docker-compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y confirma que el contenedor `osquery-hunter` está en estado "Up".

3. **Acceder al contenedor:**
   Ingresa a la terminal interactiva del contenedor.
   ```bash
   docker exec -it osquery-hunter bash
   ```
   *Verificación:* El prompt de tu terminal debería cambiar, indicando que estás dentro del contenedor (ej. `root@osquery-hunter:/#`).

4. **Iniciar Osquery:**
   Lanza la interfaz interactiva de Osquery.
   ```bash
   osqueryi
   ```
   *Verificación:* Verás el prompt de Osquery (`osquery>`), listo para recibir consultas SQL.

---

## Ejercicios Paso a Paso

### Ejercicio 1: Detección de Procesos en Rutas Inusuales
**Hipótesis de Hunting:** Los atacantes suelen ejecutar malware desde directorios temporales o públicos para evadir restricciones de ejecución. Buscaremos procesos que no se estén ejecutando desde los directorios estándar del sistema.

**Comandos Exactos:**
```sql
SELECT pid, name, path FROM processes WHERE path NOT LIKE 'C:\Windows%' AND path NOT LIKE 'C:\Program Files%' AND path != '';
```
*Explicación:* 
* `SELECT pid, name, path`: Selecciona el ID del proceso, su nombre y la ruta del ejecutable.
* `FROM processes`: Consulta la tabla de procesos activos.
* `WHERE path NOT LIKE ...`: Filtra los resultados excluyendo las rutas legítimas comunes de Windows.

**Qué buscar en la salida:**
Busca procesos ejecutándose desde rutas como `C:\Users\Public`, `C:\Temp` o directorios de datos de aplicaciones.

**Preguntas de Análisis:**
1. ¿Qué proceso sospechoso encontraste y desde qué ruta se está ejecutando?
2. ¿Por qué un atacante elegiría esa ruta específica?
3. ¿Qué implicaciones tiene que un proceso se ejecute desde un directorio público?

**Respuestas Esperadas:**
1. Se espera encontrar un proceso malicioso (ej. `svchost.exe` o un nombre aleatorio) ejecutándose desde `C:\Users\Public`.
2. Los directorios públicos suelen tener permisos de escritura para cualquier usuario, facilitando la descarga y ejecución de payloads sin privilegios de administrador.
3. Indica una posible evasión de controles de seguridad básicos y un compromiso inicial del sistema.

---

### Ejercicio 2: Identificación de Conexiones de Red Sospechosas
**Hipótesis de Hunting:** El malware instalado probablemente esté comunicándose con un servidor de Comando y Control (C2). Buscaremos conexiones de red establecidas hacia direcciones IP externas.

**Comandos Exactos:**
```sql
SELECT p.pid, p.name, s.remote_address, s.remote_port FROM processes p JOIN process_open_sockets s ON p.pid = s.pid WHERE s.remote_address NOT LIKE '10.%' AND s.remote_address != '127.0.0.1' AND s.remote_address != '0.0.0.0' AND s.remote_address != '::';
```
*Explicación:*
* `JOIN process_open_sockets`: Une la tabla de procesos con la de sockets abiertos usando el PID.
* `WHERE s.remote_address NOT LIKE '10.%' ...`: Filtra las conexiones locales o internas para centrarse en IPs externas.

**Qué buscar en la salida:**
Identifica procesos que tengan conexiones activas hacia IPs públicas, especialmente en puertos no estándar o puertos comunes usados para C2 (ej. 4444, 8080).

**Preguntas de Análisis:**
1. ¿Qué proceso está realizando la conexión externa?
2. ¿A qué dirección IP y puerto se está conectando?
3. ¿El proceso identificado en este ejercicio coincide con el encontrado en el Ejercicio 1?

**Respuestas Esperadas:**
1. El proceso malicioso identificado anteriormente (ej. el que corre desde `C:\Users\Public`).
2. Una IP externa sospechosa y un puerto inusual, como el 4444.
3. Sí, esto confirma que el proceso anómalo es el responsable de la comunicación C2.

---

### Ejercicio 3: Descubrimiento de Persistencia Oculta
**Hipótesis de Hunting:** Para mantener el acceso tras un reinicio, el atacante ha creado un mecanismo de persistencia. Buscaremos tareas programadas que hayan sido configuradas para ocultarse del usuario.

**Comandos Exactos:**
```sql
SELECT name, action, path, hidden FROM scheduled_tasks WHERE hidden = 1;
```
*Explicación:*
* `SELECT name, action, path, hidden`: Muestra el nombre de la tarea, la acción que realiza, la ruta del ejecutable y su estado de ocultación.
* `FROM scheduled_tasks`: Consulta la tabla de tareas programadas.
* `WHERE hidden = 1`: Filtra específicamente aquellas tareas que tienen el flag de oculto activado.

**Qué buscar en la salida:**
Busca tareas programadas que ejecuten binarios sospechosos o scripts desde rutas no estándar.

**Preguntas de Análisis:**
1. ¿Cuál es el nombre de la tarea programada oculta?
2. ¿Qué acción o ejecutable está configurada para lanzar?
3. ¿Cómo se relaciona esta tarea con los hallazgos de los ejercicios anteriores?

**Respuestas Esperadas:**
1. Un nombre engañoso diseñado para parecer legítimo (ej. `WindowsUpdateSync`).
2. El ejecutable malicioso encontrado en `C:\Users\Public`.
3. Esta tarea garantiza que el proceso malicioso (que realiza la conexión C2) se vuelva a ejecutar automáticamente si el sistema se reinicia.

---

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
| :--- | :--- | :--- |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Proceso malicioso usando un nombre legítimo o ejecutándose desde `C:\Users\Public`. |
| T1071.001 | Application Layer Protocol: Web Protocols | Conexión de red hacia una IP externa en un puerto sospechoso (ej. 4444). |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Creación de una tarea programada oculta (`hidden = 1`) para persistencia. |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Posibles elementos de inicio maliciosos adicionales (startup items). |

---

## Cadena de Ataque Completa

```text
[Compromiso Inicial] ---> [Ejecución] ---> [Persistencia] ---> [Comando y Control]
         |                     |                 |                     |
   (Phishing/Exploit)   (Proceso en path)  (Scheduled Task)    (Conexión a IP externa)
         |                     |                 |                     |
         v                     v                 v                     v
    Acceso al host      C:\Users\Public\...   hidden = 1        Puerto 4444 / IP Externa
```

---

## Limpieza

Una vez finalizado el laboratorio, es importante limpiar el entorno para liberar recursos.

1. Salir de la interfaz de Osquery:
   ```sql
   .exit
   ```
2. Salir del contenedor:
   ```bash
   exit
   ```
3. Detener y eliminar el contenedor:
   ```bash
   docker-compose down
   ```

---

## Troubleshooting

* **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  * **Solución:** Aunque este laboratorio no expone puertos, si hay conflictos con otros contenedores, detén los contenedores conflictivos con `docker stop <container_id>`.
* **Problema:** Al ejecutar `osqueryi`, aparece un error de permisos o comando no encontrado.
  * **Solución:** Asegúrate de haber ingresado al contenedor correcto (`docker exec -it osquery-hunter bash`) y de tener privilegios suficientes (deberías ser root por defecto).
* **Problema:** Las consultas SQL no devuelven resultados.
  * **Solución:** Verifica la sintaxis de la consulta. Osquery requiere que las sentencias SQL terminen con un punto y coma (`;`). Asegúrate de no haber omitido este carácter.
* **Problema:** No se encuentra el archivo `docker-compose.yml`.
  * **Solución:** Verifica que estás en el directorio correcto (`/home/ubuntu/MAR404-threat-hunting-2026/clase-09/docker/lab17-osquery-hunting/`) antes de ejecutar los comandos de Docker.
