# Lab 8 — Caso Integrador: Incidente Multi-Vector en Red
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 04

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha detectado actividad anómala en la red de la organización. Se sospecha que un actor de amenazas avanzado (APT) ha logrado comprometer la infraestructura interna. El incidente involucra múltiples vectores de ataque, comenzando con un escaneo de red, seguido de la explotación de una vulnerabilidad en un servidor web público, establecimiento de un canal de Comando y Control (C2), movimiento lateral hacia un servidor de base de datos, persistencia mediante una web shell, descubrimiento de archivos sensibles y, finalmente, exfiltración de datos a través de túneles DNS. Como Threat Hunter, tu misión es analizar la captura de tráfico de red (`lab8_incident.pcap`) para reconstruir la cadena de ataque completa y documentar los Indicadores de Compromiso (IOCs).

## Objetivos de Aprendizaje
- Analizar tráfico de red complejo para identificar múltiples fases de un ataque APT.
- Extraer y documentar Indicadores de Compromiso (IOCs) a partir de capturas de paquetes.
- Reconstruir la línea de tiempo de un incidente de seguridad utilizando herramientas de análisis de red.
- Mapear las tácticas y técnicas observadas al framework MITRE ATT&CK.

## Requisitos Previos
- **Docker y Docker Compose:** Instalados y configurados en el sistema host.
- **Memoria RAM:** Mínimo 4 GB disponibles para el contenedor de análisis.
- **Puertos:** Ningún puerto específico requerido en el host, el análisis se realiza dentro del contenedor.

## Despliegue Paso a Paso

1. **Iniciar el entorno de laboratorio:**
   Ejecuta el siguiente comando en el directorio del laboratorio para levantar los contenedores en segundo plano.
   ```bash
   docker-compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y asegúrate de que el contenedor `caso-integrador-analyst` esté en estado "Up".

2. **Acceder al contenedor de análisis:**
   Ingresa al contenedor interactivo para comenzar el análisis.
   ```bash
   docker exec -it caso-integrador-analyst bash
   ```
   *Verificación:* El prompt de tu terminal debería cambiar, indicando que estás dentro del contenedor (ej. `root@caso-integrador-analyst:/#`).

3. **Verificar los archivos del laboratorio:**
   Asegúrate de que la captura de red esté disponible.
   ```bash
   ls -la /data/lab8_incident.pcap
   ```
   *Verificación:* El comando debe listar el archivo `.pcap` con un tamaño mayor a 0 bytes.

---

## Ejercicios Paso a Paso

### Ejercicio 1: Identificación del Reconocimiento y Acceso Inicial
**Hipótesis de hunting:** El atacante realizó un escaneo de puertos seguido de la explotación de un servicio web expuesto para obtener acceso inicial.

**Comandos EXACTOS a ejecutar:**
```bash
# 1. Identificar escaneo SYN usando tshark
tshark -r /data/lab8_incident.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr | head -n 10

# 2. Buscar tráfico HTTP sospechoso hacia el puerto 8080 (Buffer Overflow)
tshark -r /data/lab8_incident.pcap -Y "tcp.dstport == 8080 and http.request" -T fields -e ip.src -e http.request.uri -e http.user_agent
```
*Explicación de flags:*
- `-r`: Especifica el archivo de captura a leer.
- `-Y`: Aplica un filtro de visualización (display filter).
- `-T fields`: Indica que la salida será en formato de campos específicos.
- `-e`: Especifica el campo a extraer (ej. `ip.src`, `tcp.dstport`).

**Qué buscar en la salida:**
- En el primer comando, busca una dirección IP origen que intente conectarse a múltiples puertos destino en un corto período de tiempo.
- En el segundo comando, busca URIs inusualmente largas o con caracteres extraños (ej. `\x90\x90...`) que indiquen un intento de Buffer Overflow.

**Preguntas de análisis:**
1. ¿Cuál es la dirección IP del atacante que realizó el escaneo?
2. ¿Qué puerto fue el objetivo del exploit de Buffer Overflow?
3. ¿Qué User-Agent se utilizó en la petición HTTP maliciosa?

**Respuestas esperadas (Para el instructor):**
- *Respuesta 1:* La IP del atacante es (dependerá del pcap, ej. 192.168.1.100).
- *Respuesta 2:* El puerto objetivo fue el 8080.
- *Respuesta 3:* El User-Agent puede ser una herramienta automatizada (ej. Nmap Scripting Engine, curl, o un script de Python) o estar vacío.

---

### Ejercicio 2: Detección del Canal de Comando y Control (C2)
**Hipótesis de hunting:** Tras el compromiso inicial, el atacante estableció una conexión de reverse shell hacia su infraestructura para mantener el control.

**Comandos EXACTOS a ejecutar:**
```bash
# 1. Identificar conexiones salientes hacia puertos inusuales (ej. 4443)
tshark -r /data/lab8_incident.pcap -q -z conv,tcp | grep "4443"

# 2. Seguir el stream TCP completo de la sesión C2 (muestra comandos en ASCII)
tshark -r /data/lab8_incident.pcap -q -z "follow,tcp,ascii,tcp.port==4443"

# 3. Alternativa: usar tcpdump para ver el contenido ASCII directamente
tcpdump -r /data/lab8_incident.pcap -nn 'port 4443' -A

# 4. Extraer solo los payloads en hex (para decodificar manualmente)
tshark -r /data/lab8_incident.pcap -Y "tcp.port == 4443 && data" -T fields -e data
```
*Explicación de flags:*
- `-q`: Modo silencioso, no muestra el resumen de paquetes por defecto.
- `-z conv,tcp`: Genera estadísticas de las conversaciones TCP.
- `-z "follow,tcp,ascii,..."`: Reconstruye y muestra el stream TCP completo en ASCII.
- `-A` (tcpdump): Imprime cada paquete en ASCII, ideal para ver comandos de shell.
- `data`: Campo que contiene los bytes crudos del payload TCP.

**Qué buscar en la salida:**
- Una conversación TCP de larga duración o con un volumen de datos significativo hacia el puerto 4443.
- Comandos típicos de shell de Unix (ej. `whoami`, `id`, `ls`, `pwd`) en el contenido de la sesión.

**Preguntas de análisis:**
1. ¿Qué dirección IP y puerto se utilizaron para el servidor C2?
2. ¿Qué comandos ejecutó el atacante inmediatamente después de obtener la reverse shell?
3. ¿Se descargó alguna herramienta adicional a través de este canal?

**Respuestas esperadas (Para el instructor):**
- *Respuesta 1:* IP del atacante: 203.0.113.77, puerto C2: 4443 (reverse shell desde 192.168.10.20).
- *Respuesta 2:* Comandos ejecutados: `id`, `whoami`, `uname -a`, `cat /etc/passwd`, `cat /var/www/html/config/database.conf` (extracción de credenciales DB).
- *Respuesta 3:* No se descargaron herramientas adicionales; el atacante usó comandos nativos (LOTL) para reconocimiento y extracción de credenciales.

---

### Ejercicio 3: Análisis de Exfiltración de Datos vía DNS
**Hipótesis de hunting:** El atacante exfiltró información sensible utilizando túneles DNS para evadir los controles de seguridad perimetrales.

**Comandos EXACTOS a ejecutar:**
```bash
# 1. Filtrar consultas DNS inusualmente largas (indicador de tunneling)
tshark -r /data/lab8_incident.pcap -Y "dns.qry.name.len > 50" -T fields -e ip.src -e dns.qry.name | sort | uniq -c

# 2. Identificar el dominio C2 usado para exfiltración (buscar patrón de subdominios largos)
tshark -r /data/lab8_incident.pcap -Y "dns.qry.name contains \"evil-corp\"" -T fields -e dns.qry.name

# 3. Extraer los subdominios codificados (primera parte antes del primer punto)
tshark -r /data/lab8_incident.pcap -Y "dns.qry.name contains \"data.cdn-update.evil-corp.net\"" -T fields -e dns.qry.name | awk -F'.' '{print $1}'

# 4. Decodificar los datos exfiltrados (Base32)
tshark -r /data/lab8_incident.pcap -Y "dns.qry.name contains \"data.cdn-update.evil-corp.net\"" -T fields -e dns.qry.name | awk -F'.' '{print $1}' | python3 -c "
import sys, base64
for line in sys.stdin:
    chunk = line.strip()
    # Agregar padding Base32
    padding = '=' * ((8 - len(chunk) % 8) % 8)
    try:
        decoded = base64.b32decode(chunk.upper() + padding).decode()
        print(decoded)
    except: pass
"
```
*Explicación de flags:*
- `dns.qry.name.len > 50`: Filtra consultas DNS donde la longitud del nombre es mayor a 50 caracteres (indicador de tunneling).
- `contains`: Filtra paquetes cuyo campo contiene la cadena especificada.
- `awk -F'.' '{print $1}'`: Extrae la primera parte del FQDN (el subdominio que contiene los datos codificados).
- El script Python decodifica Base32 para revelar los datos exfiltrados.

**Qué buscar en la salida:**
- Múltiples consultas DNS desde `192.168.10.20` hacia el dominio `cdn-update.evil-corp.net` con subdominios que parecen cadenas aleatorias codificadas en Base32.
- Al decodificar, se revelan credenciales de base de datos.

**Preguntas de análisis:**
1. ¿Cuál es el dominio raíz utilizado para la exfiltración DNS?
2. ¿Qué tipo de codificación utiliza el atacante en los subdominios?
3. Al decodificar las cadenas, ¿qué información se estaba exfiltrando?

**Respuestas esperadas (Para el instructor):**
- *Respuesta 1:* `cdn-update.evil-corp.net` (dominio C2 para exfiltración DNS).
- *Respuesta 2:* Base32 (caracteres alfanuméricos en minúscula sin padding).
- *Respuesta 3:* Credenciales de la base de datos: `DB_USER=webapp;DB_PASS=Str0ng!P@ss2024;DB_HOST=192.168.10.30`.

---

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| T1595 | Active Scanning | Múltiples paquetes SYN a diferentes puertos desde una única IP. |
| T1190 | Exploit Public-Facing Application | Petición HTTP maliciosa al puerto 8080 (Buffer Overflow). |
| T1059.004 | Unix Shell | Tráfico de reverse shell en el puerto 4443. |
| T1505.003 | Web Shell | Subida de archivo polyglot (JPEG+PHP) detectada en tráfico HTTP. |
| T1021.002 | SMB/Windows Admin Shares | Conexiones SMB anómalas hacia el servidor de base de datos. |
| T1083 | File and Directory Discovery | Uso de LFI para leer archivos del sistema (`/etc/passwd`). |
| T1003 | OS Credential Dumping | Intentos de acceso a archivos de contraseñas. |
| T1048.001 | Exfiltration Over DNS | Consultas DNS con subdominios largos y codificados. |

---

## Cadena de Ataque Completa

```text
[Atacante] 
   |
   | 1. Reconocimiento (Nmap SYN Scan)
   v
[Servidor Web (Puerto 8080)] 
   |
   | 2. Acceso Inicial (Buffer Overflow)
   | 3. Persistencia (Upload Web Shell JPEG+PHP)
   | 4. Discovery (LFI)
   v
[Canal C2 (Puerto 4443)] <---- Reverse Shell ----> [Atacante]
   |
   | 5. Movimiento Lateral (SMB)
   v
[Servidor de Base de Datos]
   |
   | 6. Exfiltración (DNS Tunneling)
   v
[Servidor DNS Malicioso]
```

---

## Limpieza

Una vez finalizado el análisis, es importante detener y eliminar los contenedores para liberar recursos en el sistema host.

```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores, redes y volúmenes asociados
docker-compose down -v
```

---

## Troubleshooting

1. **El contenedor no inicia o se detiene inmediatamente:**
   - *Solución:* Verifica que los puertos requeridos no estén en uso en el host. Revisa los logs con `docker-compose logs`.
2. **No se encuentra el archivo pcap:**
   - *Solución:* Asegúrate de que el volumen se haya montado correctamente. Verifica el archivo `docker-compose.yml` y confirma que el directorio `./data` local contiene el archivo `lab8_incident.pcap`.
3. **tshark muestra el error "Permission denied":**
   - *Solución:* Asegúrate de estar ejecutando los comandos como el usuario `root` dentro del contenedor, o utiliza `sudo` si es necesario.
4. **La salida de tshark está vacía:**
   - *Solución:* Revisa la sintaxis del filtro de visualización (`-Y`). Un error tipográfico en el filtro hará que no coincida ningún paquete.
5. **No se pueden ejecutar las herramientas automáticas (timeline_builder, ioc_extractor):**
   - *Solución:* Verifica que los scripts tengan permisos de ejecución (`chmod +x /scripts/*`) y que estén en el PATH del sistema.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
