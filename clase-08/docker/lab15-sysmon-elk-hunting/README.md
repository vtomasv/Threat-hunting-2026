# Lab 15 — Hunting con Sysmon + ELK Stack

**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 08

## Descripción del Escenario

El equipo de Centro de Operaciones de Seguridad (SOC) ha detectado anomalías significativas en un endpoint crítico de la red corporativa. Se sospecha fuertemente que un actor de amenazas avanzado ha logrado comprometer el equipo, ejecutando movimientos laterales, estableciendo mecanismos de persistencia y preparando la exfiltración de datos. 

Afortunadamente, el equipo de respuesta a incidentes logró capturar la telemetría completa de Sysmon del equipo comprometido antes de aislarlo. Estos logs han sido ingestados en un entorno ELK (Elasticsearch, Logstash, Kibana) pre-configurado. Tu misión como Threat Hunter es analizar los más de 450 eventos capturados, reconstruir la cadena de ataque completa y responder a las preguntas de investigación para entender el alcance del compromiso.

## Objetivos de Aprendizaje

* Comprender y analizar eventos críticos de Sysmon (Event IDs 1, 3, 8, 10, 13, 22) en un entorno de incidentes real.
* Desarrollar y ejecutar consultas efectivas utilizando la API de Elasticsearch para identificar comportamientos anómalos.
* Mapear los hallazgos técnicos a las tácticas y técnicas del framework MITRE ATT&CK.
* Reconstruir la cadena de ataque completa a partir de eventos aislados de telemetría.

## Requisitos Previos

* **Motor de Contenedores:** Docker y Docker Compose instalados y actualizados en el sistema host.
* **Recursos del Sistema:** Al menos 4GB de memoria RAM disponibles exclusivamente para el stack ELK.
* **Configuración de Red:** Puertos locales disponibles: `9200` (Elasticsearch) y `5601` (Kibana).
* **Sistema Operativo:** Configuración de `vm.max_map_count` ajustada para Elasticsearch.

## Despliegue Paso a Paso

Sigue estos pasos para inicializar el entorno del laboratorio:

1. **Preparar el host:** Ajusta el límite de memoria virtual requerido por Elasticsearch.
   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```
2. **Levantar los contenedores:** Ejecuta Docker Compose en modo detached.
   ```bash
   docker-compose up -d
   ```
3. **Verificar el estado:** Confirma que los contenedores estén en ejecución.
   ```bash
   docker ps
   ```
4. **Esperar inicialización:** Espera aproximadamente 60 segundos para la carga de datos.
5. **Verificar Elasticsearch:** Comprueba que la API esté respondiendo correctamente.
   ```bash
   curl -s http://localhost:9200/_cluster/health | grep -o '"status":"[a-z]*"'
   ```
   *La salida debería indicar "status":"green" o "yellow".*
6. **Acceder a Kibana:** Abre tu navegador web y dirígete a `http://localhost:5601`.

## Ejercicios Paso a Paso

### Ejercicio 1: Detección de volcado de credenciales (Mimikatz)

**Hipótesis de hunting:** Los atacantes frecuentemente intentan acceder a la memoria del proceso LSASS (Local Security Authority Subsystem Service) para extraer credenciales en texto claro o hashes, lo cual genera un evento de acceso a procesos.

**Comandos EXACTOS a ejecutar:**
```bash
curl -X GET "http://localhost:9200/sysmon-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 5,
  "query": {
    "bool": {
      "must": [
        { "match": { "event_id": 10 } },
        { "wildcard": { "target_image": "*lsass*" } }
      ]
    }
  }
}'
```

*Explicación de flags:*
* `-X GET`: Especifica el método HTTP GET para realizar la consulta a la API.
* `?pretty`: Formatea la respuesta JSON para que sea legible por humanos.
* `-H 'Content-Type: application/json'`: Indica que el cuerpo de la petición está en formato JSON.
* `-d'...'`: Define el cuerpo de la consulta, buscando el Event ID 10 y el proceso objetivo `lsass`.

**Qué buscar en la salida:**
Busca en los resultados (dentro del arreglo `hits.hits`) los eventos donde el campo `SourceImage` sea un proceso inusual accediendo a `TargetImage: C:\Windows\System32\lsass.exe` con un `GrantedAccess` sospechoso (ej. 0x1010 o 0x1410).

**Preguntas de análisis:**
1. ¿Qué proceso (SourceImage) intentó acceder a lsass.exe?
2. ¿Cuál fue el nivel de acceso concedido (GrantedAccess)?
3. ¿A qué hora exacta ocurrió este evento?

**Respuestas esperadas:**
1. El proceso malicioso suele ser un ejecutable temporal o una herramienta renombrada (ej. `mimikatz.exe` o un binario en `C:\Users\Public\`).
2. El acceso concedido típicamente es `0x1010` o `0x1410`, que permite leer la memoria del proceso.
3. La hora dependerá del timestamp del evento en el índice, pero debe coincidir con el inicio de la actividad post-compromiso.

---

### Ejercicio 2: Identificación de persistencia en el registro

**Hipótesis de hunting:** Los adversarios modifican las llaves de registro de inicio (Run keys) para asegurar que su malware se ejecute automáticamente cada vez que el usuario inicie sesión o se reinicie el sistema.

**Comandos EXACTOS a ejecutar:**
```bash
curl -X GET "http://localhost:9200/sysmon-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 5,
  "query": {
    "bool": {
      "must": [
        { "match": { "event_id": 13 } },
        { "wildcard": { "target_object": "*CurrentVersion\\\\Run*" } }
      ]
    }
  }
}'
```

*Explicación de flags:*
* `-X GET`: Método HTTP para la consulta de búsqueda.
* `?pretty`: Retorna el JSON de forma estructurada y tabulada.
* `-H`: Envía el encabezado HTTP indicando el tipo de contenido JSON.
* `-d`: Envía la consulta buscando el Event ID 13 (Registry Event) y modificaciones en la llave `Run`.

**Qué buscar en la salida:**
Revisa el campo `Details` para identificar qué ejecutable o script se está configurando para inicio automático y el campo `Image` para saber qué proceso realizó la modificación.

**Preguntas de análisis:**
1. ¿Qué llave de registro exacta fue modificada?
2. ¿Cuál es la ruta del archivo que se configuró para persistencia?
3. ¿Qué proceso realizó esta modificación en el registro?

**Respuestas esperadas:**
1. Típicamente `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` o similar.
2. La ruta suele apuntar a un archivo en un directorio de usuario, como `C:\Users\Public\payload.exe`.
3. El proceso que realiza la modificación suele ser el payload inicial o un script de PowerShell.

---

### Ejercicio 3: Análisis de inyección de procesos y conexiones C2

**Hipótesis de hunting:** El malware avanzado inyecta código en procesos legítimos del sistema (como explorer.exe o svchost.exe) para evadir detección, y desde allí establece conexiones de red hacia servidores de Comando y Control (C2).

**Comandos EXACTOS a ejecutar:**
```bash
curl -X GET "http://localhost:9200/sysmon-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 5,
  "query": {
    "bool": {
      "must": [
        { "match": { "event_id": 8 } }
      ]
    }
  }
}'
```

*Explicación de flags:*
* `-X GET`: Método HTTP para obtener datos de Elasticsearch.
* `-H 'Content-Type: application/json'`: Define el tipo de contenido de la petición.
* `-d`: Cuerpo de la petición buscando el Event ID 8 (CreateRemoteThread), indicativo de inyección de procesos.

**Qué buscar en la salida:**
Identifica el `SourceImage` (proceso inyector) y el `TargetImage` (proceso inyectado). Luego, en Kibana, correlaciona el `TargetImage` con eventos de red (Event ID 3) hacia IPs externas.

**Preguntas de análisis:**
1. ¿Qué proceso inyectó código y en qué proceso objetivo (TargetImage)?
2. ¿Qué dirección IP externa y puerto se contactó posteriormente desde el proceso inyectado?
3. ¿Por qué el atacante eligió ese proceso objetivo específico?

**Respuestas esperadas:**
1. Un proceso sospechoso inyectó un hilo en un proceso legítimo como `svchost.exe` o `explorer.exe`.
2. El proceso inyectado generó un Event ID 3 conectándose a una IP pública (ej. en el puerto 443 o 80).
3. Se elige `svchost.exe` o `explorer.exe` porque son procesos comunes que normalmente tienen acceso a la red, ayudando a evadir firewalls y analistas.

## Mapeo MITRE ATT&CK

| Técnica ID | Nombre de la Técnica | Evidencia en Sysmon |
|------------|----------------------|---------------------|
| T1003.001  | OS Credential Dumping: LSASS Memory | Event ID 10 (Process Access) hacia lsass.exe |
| T1059.001  | Command and Scripting Interpreter: PowerShell | Event ID 1 (Process Creation) con flags `-enc` |
| T1047      | Windows Management Instrumentation | Event ID 1 (Process Creation) involucrando wmiprvse.exe |
| T1547.001  | Boot or Logon Autostart Execution: Registry Run Keys | Event ID 13 (Registry Event) en `CurrentVersion\Run` |
| T1055.001  | Process Injection: Dynamic-link Library Injection | Event ID 8 (CreateRemoteThread) |
| T1568.002  | Dynamic Resolution: Domain Generation Algorithms | Event ID 22 (DNSEvent) con dominios anómalos |
| T1071.001  | Application Layer Protocol: Web Protocols | Event ID 3 (Network Connection) hacia IPs externas |

## Cadena de Ataque Completa

```text
+--------------------+      +--------------------+      +--------------------+
| Ejecución Inicial  | ---> |    Persistencia    | ---> | Evasión/Inyección  |
| PowerShell Encoded |      |  Registry Run Key  |      | CreateRemoteThread |
|    (Event ID 1)    |      |   (Event ID 13)    |      |    (Event ID 8)    |
+--------------------+      +--------------------+      +--------------------+
                                                                 |
                                                                 v
+--------------------+      +--------------------+      +--------------------+
| Comando y Control  | <--- |  Movimiento Lat.   | <--- | Acceso Credenciales|
| Conexión a C2 / DGA|      |        WMI         |      |   Acceso a LSASS   |
|  (Event ID 3, 22)  |      |    (Event ID 1)    |      |   (Event ID 10)    |
+--------------------+      +--------------------+      +--------------------+
```

## Limpieza

Para detener y eliminar los recursos del laboratorio una vez finalizados los ejercicios, ejecuta el siguiente comando en el directorio del laboratorio:

```bash
docker-compose down -v
```

*Nota: El flag `-v` asegura que se eliminen los volúmenes asociados, borrando los datos de Elasticsearch y liberando espacio en disco.*

## Troubleshooting

1. **Error "vm.max_map_count is too low" al iniciar Elasticsearch:**
   *Solución:* El sistema host no tiene suficiente memoria virtual asignada. Ejecuta `sudo sysctl -w vm.max_map_count=262144` en el host antes de levantar los contenedores.

2. **Kibana no carga o muestra "Kibana server is not ready yet":**
   *Solución:* Elasticsearch puede tardar en iniciar y Kibana depende de él. Espera 1-2 minutos adicionales y verifica los logs con `docker-compose logs -f kibana`.

3. **No hay datos en los índices de Sysmon:**
   *Solución:* Verifica que el contenedor de ingesta de datos haya finalizado correctamente. Puedes reiniciar la ingesta con `docker-compose restart logstash` (o el servicio correspondiente en el archivo compose).

4. **Error de puertos en uso (Bind for 0.0.0.0:9200 failed):**
   *Solución:* Asegúrate de no tener otra instancia de Elasticsearch corriendo localmente. Detenla con `sudo systemctl stop elasticsearch` o cambia el puerto mapeado en el archivo `docker-compose.yml`.
