# Lab 4 — Análisis de Tráfico HTTP y User-Agents Anómalos
**Curso:** MAR404 - Threat Hunting 2026  
**Clase:** 02  

## Descripción del Escenario

El equipo de SOC ha detectado un incremento inusual en el tráfico HTTP saliente desde la red corporativa hacia dominios desconocidos. Se sospecha que un host interno (10.0.1.50) ha sido comprometido y está utilizando un canal de Comando y Control (C2) encubierto en tráfico HTTP estándar. El malware parece estar mezclando sus comunicaciones con la navegación web legítima de los usuarios, pero se cree que utiliza un User-Agent anómalo. Tu misión como Threat Hunter es analizar la captura de tráfico, identificar el User-Agent malicioso, confirmar el comportamiento de beaconing y extraer los comandos exfiltrados.

## Objetivos de Aprendizaje

* Extraer y clasificar User-Agents desde capturas de tráfico HTTP.
* Identificar anomalías en User-Agents mediante análisis de frecuencia y longitud.
* Detectar patrones temporales de comunicación (beaconing) indicativos de malware.
* Extraer y decodificar payloads ofuscados en comunicaciones C2.
* Mapear los hallazgos a tácticas y técnicas del framework MITRE ATT&CK.

## Requisitos Previos

* **Docker y Docker Compose** instalados en el sistema anfitrión.
* **Memoria RAM:** Mínimo 2 GB disponibles para el contenedor.
* **Puertos:** Ningún puerto específico requerido en el host (análisis offline).

## Despliegue Paso a Paso

1. Navega al directorio del laboratorio:
   ```bash
   cd lab4-http-anomalies
   ```
2. Levanta el entorno utilizando Docker Compose:
   ```bash
   docker-compose up -d
   ```
3. Verifica que el contenedor esté en ejecución:
   ```bash
   docker ps | grep http-analyst
   ```
4. Accede a la terminal del contenedor:
   ```bash
   docker exec -it http-analyst bash
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Identificación de User-Agents Anómalos

**Hipótesis de Hunting:** "El malware se comunica utilizando un User-Agent HTTP no estándar o poco frecuente para evadir detecciones basadas en firmas, lo que resultará en una baja frecuencia de aparición en comparación con los navegadores legítimos."

**Comandos a ejecutar:**
```bash
# Listar y contar la frecuencia de todos los User-Agents en el tráfico
hunt_http ua

# Ejecutar el script de análisis de anomalías para destacar UAs sospechosos
analyze_ua --input traffic.pcap --mode frequency
```
*Explicación de flags:*
* `ua`: Subcomando de `hunt_http` para extraer y resumir User-Agents.
* `--input traffic.pcap`: Especifica el archivo de captura a analizar.
* `--mode frequency`: Indica al script que busque anomalías basadas en la rareza del User-Agent.

**Qué buscar en la salida:**
Busca User-Agents que aparezcan muy pocas veces (frecuencia baja) o que tengan un formato inusual (por ejemplo, muy cortos, sin versión de sistema operativo, o que indiquen herramientas de línea de comandos).

**Preguntas de análisis:**
1. ¿Cuál es el User-Agent más frecuente en la red?
2. ¿Qué User-Agent destaca por su baja frecuencia y formato inusual?
3. ¿Por qué un atacante elegiría este User-Agent específico?

**Respuestas esperadas:**
1. Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
2. `WinHTTP/1.0`
3. Es la biblioteca por defecto utilizada por muchas APIs de Windows y malware escrito en C/C++ o PowerShell, a menudo los atacantes olvidan o no se molestan en cambiarlo.

---

### Ejercicio 2: Análisis de Patrones Temporales (Beaconing)

**Hipótesis de Hunting:** "El host comprometido (10.0.1.50) realiza conexiones periódicas (beaconing) hacia un servidor externo para solicitar instrucciones, lo que generará un patrón de tiempo predecible entre las peticiones HTTP."

**Comandos a ejecutar:**
```bash
# Analizar el patrón temporal de las conexiones HTTP del host sospechoso
hunt_http timing --ip 10.0.1.50

# Verificar específicamente el comportamiento de beaconing hacia IPs de destino
hunt_http c2check --source 10.0.1.50 --threshold 0.8
```
*Explicación de flags:*
* `timing`: Subcomando para calcular los deltas de tiempo entre peticiones.
* `--ip 10.0.1.50`: Filtra el análisis solo para el host sospechoso.
* `c2check`: Subcomando para evaluar la regularidad de las conexiones.
* `--source 10.0.1.50`: Define la IP de origen a evaluar.
* `--threshold 0.8`: Establece el umbral de regularidad (80%) para considerar una conexión como beaconing.

**Qué buscar en la salida:**
Observa los intervalos de tiempo (deltas) entre las peticiones hacia IPs específicas. Busca conexiones que ocurran a intervalos regulares (ej. cada 30, 45 o 60 segundos) con poca variación (jitter).

**Preguntas de análisis:**
1. ¿Hacia qué dirección IP se observa el patrón de beaconing más claro?
2. ¿Cuál es el intervalo de tiempo promedio entre los beacons?
3. ¿Qué dominio (Host header) se está utilizando para estas comunicaciones?

**Respuestas esperadas:**
1. `203.0.113.100`
2. Aproximadamente 45 segundos.
3. `cdn-update-service.com`

---

### Ejercicio 3: Extracción y Decodificación de Payloads

**Hipótesis de Hunting:** "El canal C2 utiliza codificación estándar (como Base64) dentro del cuerpo de las peticiones o respuestas HTTP para ocultar los comandos enviados al implant y los datos exfiltrados."

**Comandos a ejecutar:**
```bash
# Extraer el contenido de las peticiones HTTP hacia el C2
hunt_http extract --ip 203.0.113.100 --method POST

# Decodificar el payload sospechoso encontrado en formato JSON
echo "eyBjbWQ6ICJ3aG9hbWkiIH0=" | base64 -d
```
*Explicación de flags:*
* `extract`: Subcomando para volcar el payload de las transacciones HTTP.
* `--ip 203.0.113.100`: Filtra por la IP del servidor C2 identificado.
* `--method POST`: Se enfoca en las peticiones POST, que comúnmente llevan datos exfiltrados.
* `base64 -d`: Comando estándar de Linux para decodificar cadenas en Base64.

**Qué buscar en la salida:**
Revisa los cuerpos de las peticiones POST y las respuestas del servidor. Busca cadenas de texto largas que parezcan Base64 (caracteres alfanuméricos terminados en `=` o `==`). Al decodificarlas, busca comandos del sistema o información de la máquina.

**Preguntas de análisis:**
1. ¿Qué URIs se están utilizando para la comunicación C2?
2. ¿En qué formato están estructurados los datos antes de ser codificados?
3. ¿Qué comando del sistema intentó ejecutar el atacante según el payload decodificado?

**Respuestas esperadas:**
1. `/api/status`, `/api/tasks`, `/api/config`, `/api/results`
2. JSON.
3. `whoami` (y posiblemente otros comandos de descubrimiento del sistema).

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| T1071.001 | Application Layer Protocol: Web Protocols | Uso de HTTP (puerto 80) para las comunicaciones de Comando y Control. |
| T1132.001 | Data Encoding: Standard Encoding | Payloads de C2 codificados en Base64 dentro de estructuras JSON. |
| T1036 | Masquerading | Uso de un dominio aparentemente legítimo (`cdn-update-service.com`) y el UA `WinHTTP/1.0`. |
| T1082 | System Information Discovery | Comandos exfiltrados en los payloads decodificados (ej. `whoami`). |

## Cadena de Ataque Completa

```text
[Host Comprometido]                               [Servidor C2]
   10.0.1.50                                      203.0.113.100
       |                                                |
       | --- HTTP GET /api/status (UA: WinHTTP/1.0) --> | [Beaconing ~45s]
       | <------ HTTP 200 OK (Payload: Base64) -------- | [Envío de Tareas]
       |                                                |
       | --- HTTP POST /api/results (Data: Base64) ---> | [Exfiltración/Resultados]
       | <------ HTTP 200 OK -------------------------- |
```

## Limpieza

Una vez finalizado el laboratorio, asegúrate de detener y eliminar los contenedores para liberar recursos:

```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores, redes y volúmenes asociados
docker-compose down -v
```

## Troubleshooting

* **Problema:** El comando `hunt_http` no se encuentra.
  * **Solución:** Asegúrate de estar dentro del contenedor `http-analyst` y no en tu máquina host. Verifica que el contenedor se construyó correctamente.
* **Problema:** No se detecta el beaconing en el Ejercicio 2.
  * **Solución:** Verifica que estás utilizando la IP correcta (`10.0.1.50`). Si el umbral es muy estricto, intenta reducirlo a `--threshold 0.7`.
* **Problema:** Error al decodificar Base64 ("invalid input").
  * **Solución:** Asegúrate de copiar la cadena exacta sin espacios adicionales ni comillas al pasarla al comando `echo`.
* **Problema:** El contenedor no inicia por falta de memoria.
  * **Solución:** Cierra otras aplicaciones en tu host o ajusta la configuración de Docker Desktop para asignar al menos 2 GB de RAM.
