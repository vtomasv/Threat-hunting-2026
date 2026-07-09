# Lab 7 — Detección de Buffer Overflow y File Upload en Red
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 04

## Descripción del Escenario

Durante el fin de semana, el equipo del SOC recibió múltiples alertas de actividad anómala provenientes de un servidor web expuesto a internet. El servidor aloja una aplicación heredada que se sabe que es vulnerable. El atacante parece haber utilizado una combinación de técnicas para comprometer el sistema, comenzando con un intento de explotación de un desbordamiento de búfer (Buffer Overflow), seguido de la carga de un archivo malicioso (File Upload) y la ejecución de comandos a través de una web shell. 

Este laboratorio presenta un archivo PCAP sintético que contiene tráfico HTTP normal mezclado con la actividad maliciosa. Tu misión como Threat Hunter es analizar el tráfico de red, identificar cada etapa del ataque, extraer los Indicadores de Compromiso (IOCs) y reconstruir la cadena de ataque completa.

## Objetivos de Aprendizaje

- Identificar y analizar intentos de explotación de Buffer Overflow a nivel de red, reconociendo patrones como NOP sleds y shellcodes.
- Detectar la carga de archivos maliciosos (File Upload) utilizando técnicas de evasión como archivos polyglot (GIF + PHP).
- Rastrear la ejecución de comandos a través de web shells y correlacionar eventos para reconstruir la cadena de ataque.
- Mapear las técnicas observadas a la matriz MITRE ATT&CK para documentar el incidente de manera estandarizada.

## Requisitos Previos

- **Docker y Docker Compose:** Instalados y configurados en el sistema anfitrión.
- **Memoria RAM:** Mínimo 2 GB de RAM disponibles para el contenedor.
- **Puertos:** El puerto 8080 no debe estar en uso en el sistema anfitrión.

## Despliegue Paso a Paso

Para iniciar el entorno de laboratorio, sigue estos pasos:

1. Inicia los contenedores en segundo plano:
   ```bash
   docker-compose up -d
   ```
2. Verifica que el contenedor esté en ejecución:
   ```bash
   docker ps | grep bof-analyst
   ```
   *Deberías ver el contenedor `bof-analyst` en estado "Up".*
3. Accede a la terminal del contenedor:
   ```bash
   docker exec -it bof-analyst bash
   ```
   *El prompt cambiará, indicando que estás dentro del entorno de análisis.*

## Ejercicios Paso a Paso

### Ejercicio 1: Detectar el Buffer Overflow

**Hipótesis de Hunting:** Los atacantes a menudo utilizan secuencias de NOPs (No Operation) para aumentar la probabilidad de éxito al explotar vulnerabilidades de desbordamiento de búfer. Podemos buscar estas secuencias en el tráfico de red para identificar intentos de explotación.

**Comandos:**
```bash
# Ejecutar el script de detección de NOP sleds
./detect_nop_sled
```
*Explicación de flags:* El script `detect_nop_sled` está preconfigurado para analizar el archivo PCAP en busca de secuencias largas de bytes `0x90` (NOP) en los payloads TCP.

**Qué buscar en la salida:**
Busca la dirección IP de origen, el puerto de destino y la longitud de la secuencia NOP detectada.

**Preguntas de Análisis:**
1. ¿Cuál es la dirección IP del atacante y qué puerto está atacando?
2. ¿Cuántos bytes componen el NOP sled detectado?
3. ¿Qué técnica de MITRE ATT&CK corresponde a este comportamiento?

**Logras obtener estas respuestas:**
- La IP del atacante es `10.10.14.33` y el puerto atacado es el `8080`.
- El NOP sled detectado tiene una longitud de `512` bytes.
- Corresponde a la técnica T1190 (Exploit Public-Facing Application) y T1203 (Exploitation for Client Execution).

### Ejercicio 2: Detectar el File Upload Malicioso

**Hipótesis de Hunting:** Los atacantes pueden intentar evadir los controles de seguridad subiendo archivos que parecen inofensivos (como imágenes) pero que contienen código ejecutable (archivos polyglot). Podemos buscar firmas de archivos mixtas en las cargas útiles HTTP.

**Comandos:**
```bash
# Ejecutar el script de extracción de payloads
./extract_payloads
```
*Explicación de flags:* El script `extract_payloads` analiza el tráfico HTTP en busca de solicitudes POST que contengan archivos adjuntos y extrae su contenido para su análisis.

**Qué buscar en la salida:**
Identifica el nombre del archivo subido y examina su contenido en busca de firmas de imágenes (como `GIF89a`) seguidas de código PHP (`<?php ... ?>`).

**Preguntas de Análisis:**
1. ¿Cuál es el nombre del archivo malicioso subido al servidor?
2. ¿Qué tipo de archivo polyglot se utilizó para evadir los controles?
3. ¿Qué parámetro se utiliza para ejecutar comandos a través de la web shell?

**Puedes obtener estas respuestas:**
- El archivo malicioso se llama `avatar.php.gif`.
- Se utilizó un archivo polyglot que combina la firma de un archivo GIF con código PHP.
- El parámetro utilizado para ejecutar comandos es `?cmd=`.

### Ejercicio 3: Detectar Intentos de Local File Inclusion (LFI)

**Hipótesis de Hunting:** Después de establecer un punto de apoyo, los atacantes suelen intentar leer archivos sensibles del sistema utilizando técnicas de Local File Inclusion (LFI) o Path Traversal. Podemos buscar patrones como `../` en las URLs solicitadas.

**Comandos:**
```bash
# Buscar patrones de path traversal en el tráfico HTTP usando tshark
tshark -r capture.pcap -Y "http.request.uri contains \"../\"" -T fields -e ip.src -e http.request.uri
```
*Explicación de flags:* 
- `-r capture.pcap`: Especifica el archivo de captura a analizar.
- `-Y "http.request.uri contains \"../\""`: Filtra los paquetes HTTP donde la URI contiene el patrón de path traversal.
- `-T fields -e ip.src -e http.request.uri`: Muestra solo la IP de origen y la URI solicitada.

**Qué buscar en la salida:**
Observa las rutas de los archivos que el atacante intentó acceder.

**Preguntas de Análisis:**
1. ¿Qué archivo sensible del sistema intentó leer el atacante?
2. ¿Tuvo éxito el intento de LFI? (Pista: revisa los códigos de respuesta HTTP).
3. ¿Cómo se relaciona este intento con la ejecución de la web shell?

**Puedes obtener estas respuestas:**
- El atacante intentó leer el archivo `../../etc/passwd`.
- Se debe verificar el código de respuesta HTTP para confirmar si el servidor devolvió el contenido del archivo.
- El atacante probablemente utilizó la web shell previamente subida para ejecutar el comando o explotar una vulnerabilidad de LFI en la aplicación.

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| T1190 | Exploit Public-Facing Application | Tráfico dirigido al puerto 8080 con payload malicioso. |
| T1203 | Exploitation for Client Execution | Presencia de un NOP sled de 512 bytes (0x90) en el payload TCP. |
| T1505.003 | Web Shell | Carga del archivo `avatar.php.gif` y uso del parámetro `?cmd=`. |
| T1059.004 | Unix Shell | Conexión de reverse shell detectada en el puerto 4444. |
| T1083 | File and Directory Discovery | Intentos de acceso a `../../etc/passwd` mediante path traversal. |

## Cadena de Ataque Completa

```text
[Atacante: 10.10.14.33]
       |
       | 1. Intento de Buffer Overflow (Puerto 8080, NOP Sled 512 bytes)
       v
[Servidor Web Vulnerable]
       |
       | 2. Carga de Archivo Polyglot (avatar.php.gif)
       v
[Web Shell Instalada]
       |
       | 3. Ejecución de Comandos (?cmd=) e Intentos de LFI (../../etc/passwd)
       v
[Compromiso del Sistema]
       |
       | 4. Reverse Shell (Puerto 4444)
       v
[Control Total por el Atacante]
```

## Limpieza

Una vez finalizado el laboratorio, asegúrate de limpiar el entorno para liberar recursos:

1. Sal del contenedor:
   ```bash
   exit
   ```
2. Detén y elimina los contenedores:
   ```bash
   docker-compose down
   ```

## Troubleshooting

- **Problema:** El comando `docker-compose up -d` falla indicando que el puerto 8080 ya está en uso.
  - **Solución:** Verifica qué servicio está utilizando el puerto 8080 en tu sistema anfitrión (`sudo lsof -i :8080` o `netstat -tuln | grep 8080`) y detenlo, o modifica el archivo `docker-compose.yml` para mapear un puerto diferente.
- **Problema:** No se encuentran los scripts `detect_nop_sled` o `extract_payloads`.
  - **Solución:** Asegúrate de estar dentro del directorio correcto en el contenedor. Puedes usar el comando `ls` para verificar la presencia de los scripts. Si no están, revisa si hubo errores durante la construcción de la imagen Docker.
- **Problema:** `tshark` muestra un error de permisos al leer el archivo PCAP.
  - **Solución:** Verifica los permisos del archivo `capture.pcap` usando `ls -l`. Si es necesario, cambia los permisos con `chmod +r capture.pcap` o ejecuta el comando con privilegios elevados si estás en un entorno que lo requiere.
- **Problema:** El contenedor se detiene inmediatamente después de iniciarse.
  - **Solución:** Revisa los logs del contenedor usando `docker logs bof-analyst` para identificar posibles errores de configuración o dependencias faltantes.
