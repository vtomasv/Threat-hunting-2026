# Lab 5 — Detección de Túneles DNS y Exfiltración (Curso MAR404, Clase 03)

## Descripción del Escenario
En este laboratorio, nos enfrentamos a un incidente crítico. Un insider malicioso o un malware avanzado ha logrado comprometer un equipo interno y está exfiltrando datos sensibles (un archivo de credenciales). Para evadir los controles perimetrales, el atacante está utilizando DNS tunneling. Los datos robados se codifican en Base32 y se envían como subdominios anormalmente largos en consultas DNS hacia un servidor autoritativo controlado por el atacante, mezclándose con el tráfico DNS legítimo de navegación normal. Tu misión es detectar esta actividad anómala, identificar el dominio malicioso y recuperar los datos exfiltrados.

## Objetivos de Aprendizaje
- Identificar dominios con un volumen anómalo de consultas DNS en un entorno de red.
- Detectar subdominios anormalmente largos que actúan como indicadores de tunneling.
- Calcular y analizar la entropía de Shannon para confirmar la presencia de datos codificados.
- Extraer y decodificar los datos exfiltrados para comprender el impacto del incidente.
- Documentar los hallazgos de manera estructurada utilizando la plantilla PEAK.

## Requisitos Previos
- **Docker y Docker Compose:** Instalados y configurados en el sistema host.
- **Memoria RAM:** Mínimo 2 GB disponibles para el contenedor.
- **Puertos:** Ningún puerto específico expuesto, pero se requiere acceso a la red de Docker.

## Despliegue Paso a Paso
1. Navega al directorio del laboratorio:
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-03/docker/lab5-tunnels-detection
   ```
2. Levanta el entorno utilizando Docker Compose:
   ```bash
   docker-compose up -d
   ```
3. Verifica que el contenedor esté en ejecución:
   ```bash
   docker ps | grep dns-tunnel-analyst
   ```
4. Accede al contenedor de análisis:
   ```bash
   docker exec -it dns-tunnel-analyst bash
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Identificación de Dominios Anómalos
**Hipótesis de Hunting:** "Un atacante está utilizando un dominio específico para exfiltrar datos, lo que generará un volumen inusualmente alto de consultas DNS hacia ese dominio en comparación con el tráfico normal."

**Comandos a Ejecutar:**
```bash
# Mostrar estadísticas generales de DNS
hunt_dns stats

# Listar los dominios ordenados por frecuencia de consultas
hunt_dns domains
```
*Explicación de flags:* `stats` muestra un resumen del tráfico DNS capturado. `domains` agrupa y cuenta las consultas por dominio, ordenándolas de mayor a menor frecuencia.

**Qué buscar en la salida:**
Busca un dominio que tenga un número de consultas desproporcionadamente alto en comparación con dominios conocidos (como google.com o microsoft.com).

**Preguntas de Análisis:**
1. ¿Cuál es el dominio con mayor número de consultas DNS?
2. ¿Es este dominio conocido o parece sospechoso?
3. ¿Cuál es la diferencia en volumen entre el dominio más consultado y el segundo?

**Respuestas Esperadas:**
1. El dominio con mayor número de consultas es `data.exfil-tunnel.net`.
2. Es un dominio sospechoso, no asociado a servicios legítimos conocidos.
3. La diferencia debería ser significativa, indicando un uso intensivo (ej. miles de consultas vs cientos).

### Ejercicio 2: Detección de Subdominios Largos y Entropía
**Hipótesis de Hunting:** "Los datos exfiltrados se codifican en los subdominios, lo que resultará en subdominios anormalmente largos y con una alta entropía de Shannon."

**Comandos a Ejecutar:**
```bash
# Buscar subdominios con longitud anormal
hunt_dns long

# Calcular la entropía de los subdominios
hunt_dns entropy
```
*Explicación de flags:* `long` filtra y muestra las consultas DNS cuyos subdominios superan una longitud umbral (ej. >50 caracteres). `entropy` calcula la entropía de Shannon para los subdominios, ayudando a identificar datos codificados o cifrados.

**Qué buscar en la salida:**
Identifica si el dominio sospechoso encontrado en el Ejercicio 1 tiene subdominios muy largos (>50 caracteres) y si su entropía promedio es superior a 3.5.

**Preguntas de Análisis:**
1. ¿Qué dominio presenta los subdominios más largos?
2. ¿Cuál es la longitud promedio de estos subdominios?
3. ¿Cuál es la entropía promedio de los subdominios del dominio sospechoso en comparación con dominios normales?

**Respuestas Esperadas:**
1. `data.exfil-tunnel.net` presenta los subdominios más largos.
2. La longitud promedio es superior a 50 caracteres.
3. La entropía promedio es >3.5, mientras que los dominios normales tienen ~2.5.

### Ejercicio 3: Extracción y Decodificación de Datos
**Hipótesis de Hunting:** "Los subdominios largos del dominio sospechoso contienen datos codificados en Base32 que pueden ser extraídos y decodificados para revelar la información exfiltrada."

**Comandos a Ejecutar:**
```bash
# Extraer los subdominios del dominio sospechoso
hunt_dns extract data.exfil-tunnel.net > exfil_data.txt

# Decodificar los datos extraídos (asumiendo Base32)
cat exfil_data.txt | tr -d '.' | base32 -d > credenciales_recuperadas.txt

# Ver el contenido decodificado
cat credenciales_recuperadas.txt
```
*Explicación de flags:* `extract <dominio>` extrae solo la parte del subdominio de las consultas dirigidas a ese dominio. `tr -d '.'` elimina los puntos que separan las partes del subdominio. `base32 -d` decodifica la cadena resultante.

**Qué buscar en la salida:**
El archivo `credenciales_recuperadas.txt` debería contener texto legible, específicamente un archivo de credenciales.

**Preguntas de Análisis:**
1. ¿Qué tipo de codificación se utilizó para los datos exfiltrados?
2. ¿Qué información sensible se logró recuperar?
3. ¿Cuál es el tamaño aproximado de los datos exfiltrados?

**Respuestas Esperadas:**
1. Se utilizó codificación Base32.
2. Se recuperó un archivo de credenciales.
3. El tamaño aproximado es de ~300 bytes.

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| T1048.001  | Exfiltration Over Alternative Protocol: DNS | Uso de consultas DNS para enviar datos fuera de la red. |
| T1071.004  | Application Layer Protocol: DNS | Tráfico anómalo sobre el puerto 53 (DNS). |
| T1572      | Protocol Tunneling | Encapsulación de datos (credenciales) dentro del protocolo DNS. |

## Cadena de Ataque Completa

```text
[Host Comprometido] 
       |
       | 1. Lee archivo de credenciales
       | 2. Codifica en Base32
       | 3. Genera consultas DNS: <datos_base32>.data.exfil-tunnel.net
       v
[Servidor DNS Local]
       |
       | 4. Resuelve recursivamente
       v
[Internet]
       |
       | 5. Enruta al servidor autoritativo
       v
[Servidor Atacante (198.51.100.50)]
       |
       | 6. Recibe consultas DNS
       | 7. Extrae subdominios
       | 8. Decodifica Base32 -> Obtiene credenciales
```

## Limpieza
Para detener y eliminar el entorno del laboratorio, ejecuta:
```bash
exit # Salir del contenedor
docker-compose down
```

## Troubleshooting
- **Problema:** `docker-compose: command not found`
  **Solución:** Asegúrate de tener instalado Docker Compose. Puedes instalarlo con `sudo apt install docker-compose`.
- **Problema:** El contenedor `dns-tunnel-analyst` no inicia.
  **Solución:** Verifica si hay conflictos de puertos o falta de memoria RAM. Revisa los logs con `docker-compose logs`.
- **Problema:** El comando `hunt_dns` no se reconoce.
  **Solución:** Asegúrate de estar dentro del contenedor correcto (`docker exec -it dns-tunnel-analyst bash`) y que el PATH esté configurado correctamente.
- **Problema:** Error al decodificar Base32 (`invalid input`).
  **Solución:** Verifica que has eliminado todos los puntos (`.`) del subdominio antes de pasarlo a `base32 -d`.
