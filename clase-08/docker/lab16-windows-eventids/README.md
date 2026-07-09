# Lab 16 — Correlación de Windows Event IDs
## Curso: MAR404 — Cacería de Amenazas
## Clase: 08

## Descripción del Escenario
El equipo de SOC ha detectado actividad anómala en la red interna durante el fin de semana. Se sospecha que un actor de amenazas ha logrado comprometer un servidor Windows expuesto, realizando movimientos laterales y estableciendo persistencia. Se ha capturado un conjunto de eventos de seguridad de Windows (Windows Security Events) que han sido ingeridos en un entorno ELK (Elasticsearch, Logstash, Kibana). Tu misión como Threat Hunter es analizar estos logs, correlacionar los Event IDs clave y reconstruir la cadena de ataque completa para entender el alcance del compromiso.

## Objetivos de Aprendizaje
* Comprender y correlacionar los principales Windows Event IDs relacionados con autenticación, creación de servicios y manipulación de cuentas.
* Desarrollar consultas efectivas en Kibana (KQL/Lucene) para identificar patrones de ataque como Brute Force y Pass-the-Hash.
* Identificar técnicas de evasión de defensas, específicamente el borrado de logs de auditoría.
* Mapear los hallazgos a las tácticas y técnicas del framework MITRE ATT&CK.

## Requisitos Previos
* **Docker y Docker Compose** instalados en el sistema host.
* **Memoria RAM:** Mínimo 4GB de RAM disponibles para el stack ELK.
* **Puertos requeridos:** 
  * `5601` (Kibana)
  * `9200` (Elasticsearch)

## Despliegue Paso a Paso
1. Clona el repositorio y navega al directorio del laboratorio:
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-08/docker/lab16-windows-eventids/
   ```
2. Inicia el entorno utilizando Docker Compose:
   ```bash
   docker-compose up -d
   ```
3. Verifica que los contenedores estén en ejecución:
   ```bash
   docker ps
   ```
   *Deberías ver los contenedores de Elasticsearch y Kibana en estado "Up".*
4. Accede a la interfaz de Kibana abriendo tu navegador web en:
   `http://localhost:5601`
5. Ve a la sección **Discover** y asegúrate de seleccionar el índice de eventos de Windows (por ejemplo, `winlogbeat-*` o el configurado en el lab) y ajusta el rango de tiempo para abarcar los últimos 7 días.

## Ejercicios Paso a Paso

### Ejercicio 1: Detección de Fuerza Bruta y Compromiso Inicial
**Hipótesis de Hunting:** El atacante intentó adivinar contraseñas repetidamente antes de lograr un acceso exitoso.
**Comandos/Consultas (KQL en Kibana):**
```kql
event.code: 4625 OR event.code: 4624
```
*Para ver el volumen, agrupa por `user.name` y `event.code`.*
**Qué buscar en la salida:** Un alto volumen de eventos `4625` (Logon Failed) seguido de un evento `4624` (Logon Success) para la misma cuenta de usuario en un corto período de tiempo.
**Preguntas de Análisis:**
1. ¿Qué cuenta de usuario fue el objetivo del ataque de fuerza bruta?
2. ¿Cuántos intentos fallidos ocurrieron antes del inicio de sesión exitoso?
3. ¿Cuál es la dirección IP de origen del ataque?
**Respuestas Esperadas:**
1. La cuenta objetivo suele ser `Administrator` o un usuario estándar específico del dataset.
2. Se observan 50 eventos `4625` antes del `4624`.
3. La IP de origen se encuentra en el campo `source.ip` o `winlog.event_data.IpAddress`.

### Ejercicio 2: Identificación de Movimiento Lateral (Pass-the-Hash)
**Hipótesis de Hunting:** Tras el compromiso inicial, el atacante utilizó credenciales extraídas (hashes) para moverse lateralmente en la red.
**Comandos/Consultas (KQL en Kibana):**
```kql
event.code: 4624 AND winlog.event_data.LogonType: 9
```
*También puedes buscar:*
```kql
event.code: 4648
```
**Qué buscar en la salida:** Inicios de sesión exitosos con Logon Type 9 (NewCredentials), lo cual es un fuerte indicador de Pass-the-Hash cuando se combina con procesos inusuales. El evento 4648 indica un inicio de sesión usando credenciales explícitas.
**Preguntas de Análisis:**
1. ¿Qué proceso originó el inicio de sesión con Logon Type 9?
2. ¿A qué recurso de red intentaba acceder el atacante?
3. ¿Qué usuario fue suplantado en este movimiento lateral?
**Respuestas Esperadas:**
1. Generalmente, procesos como `cmd.exe`, `powershell.exe` o herramientas de ataque específicas.
2. El campo `winlog.event_data.TargetServerName` mostrará el destino.
3. El usuario suplantado aparecerá en `winlog.event_data.TargetUserName`.

### Ejercicio 3: Persistencia y Evasión de Defensas
**Hipótesis de Hunting:** El atacante instaló un servicio malicioso para mantener el acceso y luego borró los logs para ocultar sus huellas.
**Comandos/Consultas (KQL en Kibana):**
```kql
event.code: 7045 OR event.code: 4697 OR event.code: 1102
```
**Qué buscar en la salida:** Eventos `7045` o `4697` que indican la instalación de un nuevo servicio, prestando especial atención a rutas sospechosas (ej. `C:\Windows\Temp`). El evento `1102` indica que el log de auditoría fue limpiado.
**Preguntas de Análisis:**
1. ¿Cuál es el nombre y la ruta del ejecutable del servicio malicioso instalado?
2. ¿Qué cuenta de usuario instaló el servicio?
3. ¿A qué hora exacta se borraron los logs de seguridad (Evento 1102)?
**Respuestas Esperadas:**
1. El servicio suele apuntar a un binario en una carpeta temporal, ej. `*Temp*`.
2. La cuenta comprometida con privilegios administrativos.
3. El timestamp del evento `1102` marcará el momento de la evasión.

### Ejercicio 4: Manipulación de Cuentas
**Hipótesis de Hunting:** El atacante creó una cuenta oculta y la añadió al grupo de administradores locales para asegurar acceso futuro.
**Comandos/Consultas (KQL en Kibana):**
```kql
event.code: 4720 OR event.code: 4732
```
**Qué buscar en la salida:** Evento `4720` (Creación de cuenta de usuario) seguido de un evento `4732` (Miembro añadido a un grupo local con privilegios de seguridad).
**Preguntas de Análisis:**
1. ¿Cuál es el nombre de la cuenta recién creada? ¿Tiene algún patrón sospechoso?
2. ¿A qué grupo fue añadida la nueva cuenta?
**Respuestas Esperadas:**
1. La cuenta suele terminar en `$` para intentar ocultarse (ej. `admin$`).
2. Fue añadida al grupo de Administradores Locales (SID terminando en `-544`).

## Mapeo MITRE ATT&CK

| Táctica | Técnica ID | Nombre de la Técnica | Evidencia (Event ID) |
| :--- | :--- | :--- | :--- |
| Credential Access | T1110 | Brute Force | Múltiples 4625 seguidos de 4624 |
| Lateral Movement | T1550.002 | Pass the Hash | 4624 (Logon Type 9), 4648 |
| Persistence | T1543.003 | Windows Service | 7045, 4697 con binario en Temp |
| Defense Evasion | T1070.001 | Clear Windows Event Logs | 1102 (Audit log cleared) |
| Persistence | T1136.001 | Local Account | 4720 (Cuenta oculta), 4732 (Grupo Admin) |

## Cadena de Ataque Completa

```text
[Brute Force] ---> [Initial Access] ---> [Lateral Movement] ---> [Persistence] ---> [Defense Evasion]
 (ID: 4625)         (ID: 4624)            (Pass-the-Hash)      (Malicious Svc)     (Clear Logs)
    |                  |                  (ID: 4624 LT9)       (ID: 7045/4697)     (ID: 1102)
    v                  v                        |                    |                  |
 50 Fallos          1 Éxito                     v                    v                  v
                                          Acceso a Server      Binario en Temp     Ocultar Rastros
                                                                     |
                                                                     v
                                                               [Account Manip.]
                                                               (ID: 4720/4732)
```

## Limpieza
Una vez finalizado el laboratorio, detén y elimina los contenedores para liberar recursos:
```bash
cd /home/ubuntu/MAR404-threat-hunting-2026/clase-08/docker/lab16-windows-eventids/
docker-compose down -v
```
*(El flag `-v` elimina los volúmenes asociados, borrando los datos de Elasticsearch).*

## Troubleshooting
* **Kibana no carga (Connection Refused):** Elasticsearch puede tardar unos minutos en iniciar completamente. Espera 2-3 minutos y recarga la página. Verifica los logs con `docker-compose logs -f kibana`.
* **Contenedor Elasticsearch se detiene (Exit 137 o 78):** Esto suele indicar falta de memoria RAM. Asegúrate de tener al menos 4GB libres o ajusta el parámetro `ES_JAVA_OPTS` en el `docker-compose.yml`.
* **No se ven eventos en Kibana:** Asegúrate de haber seleccionado el patrón de índice correcto en **Stack Management > Index Patterns** y de haber ajustado el rango de tiempo en la esquina superior derecha (ej. "Last 7 days" o "Last 1 year" dependiendo de la fecha de los logs).
* **Puertos en uso:** Si el puerto 5601 o 9200 ya están en uso, detén el servicio conflictivo o cambia el mapeo de puertos en el archivo `docker-compose.yml` (ej. `8080:5601`).
