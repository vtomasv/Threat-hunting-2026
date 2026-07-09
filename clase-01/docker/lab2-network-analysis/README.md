# Lab 2: Threat Hunt — Análisis de Tráfico de Red (Detección de Beaconing C2)

## Curso MAR404 — Cacería de Amenazas (Threat Hunter) — Clase 1
### Universidad Mayor 2026

---

## Descripción

Este laboratorio despliega un entorno de análisis de red con herramientas profesionales (tshark, tcpdump, ngrep) y un PCAP pre-generado que contiene tráfico normal mezclado con comunicaciones C2 (Command & Control) tipo beaconing. Los estudiantes deben identificar el patrón de beaconing, extraer IOCs y documentar sus hallazgos.

## Requisitos Previos

- Docker Engine 24.0+ y Docker Compose v2
- Mínimo 2 GB de RAM disponible
- Puerto 8080 libre (para el C2 simulator de la demo)

## Despliegue

```bash
cd lab2-network-analysis

# Levantar el entorno (genera el PCAP automáticamente)
docker-compose up -d

# Esperar ~30 segundos para la generación del PCAP
docker-compose logs pcap-generator

# Acceder al contenedor de análisis
docker exec -it hunt-network-analyst /bin/bash
```

## Acceso

| Servicio | Acceso | Descripción |
|----------|--------|-------------|
| Analyst Workstation | `docker exec -it hunt-network-analyst bash` | Entorno de análisis |
| C2 Simulator | http://localhost:8080/stats | Panel de control del C2 (demo) |
| PCAP | `/pcap/c2_beaconing.pcap` (dentro del contenedor) | Archivo de captura |

## Ejercicio Principal: Detección de Beaconing

### Contexto del Escenario

El equipo de seguridad ha capturado 30 minutos de tráfico de red de un host (192.168.1.105) que fue reportado como sospechoso por el equipo de IT. La inteligencia de amenazas indica que un grupo APT utiliza beaconing HTTP con intervalos regulares hacia dominios recién registrados.

### Objetivos

1. Identificar comunicaciones periódicas (beaconing) en el PCAP
2. Determinar la IP y dominio del servidor C2
3. Extraer el User-Agent utilizado por el implante
4. Calcular el intervalo de beaconing y su jitter
5. Documentar todos los IOCs encontrados

### Metodología Sugerida

**Paso 1: Reconocimiento general**
```bash
# Estadísticas generales del PCAP
tshark -r /pcap/c2_beaconing.pcap -q -z io,stat,60

# Conversaciones IP (identificar IPs con más tráfico)
tshark -r /pcap/c2_beaconing.pcap -q -z conv,ip
```

**Paso 2: Análisis de tráfico HTTP**
```bash
# Listar todas las solicitudes HTTP
tshark -r /pcap/c2_beaconing.pcap -Y 'http.request' \
  -T fields -e frame.time -e ip.dst -e http.host -e http.request.uri -e http.user_agent

# Extraer User-Agents únicos
tshark -r /pcap/c2_beaconing.pcap -Y 'http.user_agent' \
  -T fields -e http.user_agent | sort -u
```

**Paso 3: Detección de patrones temporales**
```bash
# Tiempos relativos de conexiones a IP sospechosa
tshark -r /pcap/c2_beaconing.pcap -Y 'ip.dst==203.0.113.42 && tcp.flags.syn==1' \
  -T fields -e frame.time_relative

# Calcular deltas entre conexiones (con Python)
python3 -c "
import subprocess
result = subprocess.run(['tshark', '-r', '/pcap/c2_beaconing.pcap', 
    '-Y', 'ip.dst==203.0.113.42 && http.request',
    '-T', 'fields', '-e', 'frame.time_relative'], 
    capture_output=True, text=True)
times = [float(t) for t in result.stdout.strip().split('\n') if t]
deltas = [times[i+1]-times[i] for i in range(len(times)-1)]
print(f'Conexiones: {len(times)}')
print(f'Intervalo promedio: {sum(deltas)/len(deltas):.1f}s')
print(f'Min: {min(deltas):.1f}s | Max: {max(deltas):.1f}s')
"
```

**Paso 4: Análisis de contenido**
```bash
# Ver payload HTTP de las conexiones C2
tcpdump -r /pcap/c2_beaconing.pcap -nn 'dst host 203.0.113.42 and tcp port 80' -A | head -100
```

### Preguntas de Análisis

1. ¿Cuántas IPs destino únicas hay en el PCAP? ¿Cuál tiene el patrón más regular?
2. ¿Qué User-Agent se diferencia del resto? ¿Por qué es sospechoso?
3. ¿Cuál es el intervalo promedio entre beacons? ¿Hay jitter?
4. ¿Qué endpoint (URI) utiliza el implante para el check-in?
5. ¿Qué información devuelve el servidor C2 en la respuesta?
6. ¿Cómo mapearía esta actividad a MITRE ATT&CK?

### Respuestas Esperadas 

| IOC | Valor |
|-----|-------|
| C2 IP | 203.0.113.42 |
| C2 Domain | update-service-cdn.com |
| User-Agent | Mozilla/5.0 (compatible; UpdateAgent/1.0) |
| Beacon URI | /api/v1/check |
| Intervalo | ~60 segundos (±2s jitter) |
| Protocolo | HTTP/1.1 (puerto 80) |
| MITRE ATT&CK | T1071.001 (Application Layer Protocol: Web) |
| MITRE ATT&CK | T1573 (Encrypted Channel) - NO aplica (HTTP plano) |
| MITRE ATT&CK | T1029 (Scheduled Transfer) |

## Demo en Vivo 

El contenedor `c2-simulator` permite demostrar en vivo cómo funciona un C2:

```bash
# Desde otra terminal, simular un beacon
curl -H "User-Agent: Mozilla/5.0 (compatible; UpdateAgent/1.0)" \
     http://localhost:8080/api/v1/check

# Ver estadísticas de conexiones
curl http://localhost:8080/stats | jq .
```

## Limpieza

```bash
docker-compose down -v
```
