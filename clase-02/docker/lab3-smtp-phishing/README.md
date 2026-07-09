# Lab 3 — Detección de Phishing en Tráfico SMTP
**Curso:** MAR404 - Threat Hunting 2026  
**Clase:** 02 - Análisis de Tráfico de Red y Protocolos  

---

## Descripción del Escenario

El equipo del Centro de Operaciones de Seguridad (SOC) ha recibido múltiples alertas sobre un posible incidente de compromiso de credenciales. Se sospecha que un adversario ha logrado evadir los filtros de correo perimetrales y ha entregado un correo electrónico de phishing a un empleado clave de la organización. Se ha capturado el tráfico de red (PCAP) del servidor SMTP corporativo durante la ventana de tiempo del incidente. Tu misión como Threat Hunter es analizar este tráfico, identificar el correo malicioso, extraer los artefactos asociados y determinar el alcance del ataque.

---

## Objetivos de Aprendizaje

- Identificar y reconstruir sesiones SMTP sospechosas a partir de capturas de tráfico de red.
- Detectar técnicas de suplantación de identidad (spoofing) analizando discrepancias entre el `MAIL FROM` (envelope) y el header `From`.
- Extraer, decodificar y analizar adjuntos codificados en Base64 directamente desde el tráfico de red.
- Correlacionar el tráfico de correo con consultas DNS para identificar infraestructura maliciosa.

---

## Requisitos Previos

- **Software:** Docker y Docker Compose instalados en el sistema host.
- **Recursos:** Mínimo 2 GB de RAM disponibles.
- **Puertos:** No se requieren puertos expuestos al host, todo el análisis se realiza dentro del contenedor.
- **Conocimientos:** Familiaridad básica con la línea de comandos de Linux y el protocolo SMTP.

---

## Despliegue Paso a Paso

1. **Clonar o acceder al directorio del laboratorio:**
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-02/docker/lab3-smtp-phishing
   ```

2. **Levantar el entorno con Docker Compose:**
   ```bash
   docker-compose up -d
   ```

3. **Verificar que el contenedor esté en ejecución:**
   ```bash
   docker ps | grep smtp-analyst
   ```
   *Deberías ver el contenedor `smtp-analyst` en estado "Up".*

4. **Acceder a la terminal del contenedor:**
   ```bash
   docker exec -it smtp-analyst bash
   ```

5. **Verificar las herramientas disponibles:**
   ```bash
   hunt_smtp stats
   ```
   *Este comando debería mostrar un resumen de los paquetes y sesiones en el archivo PCAP.*

---

## Ejercicios Paso a Paso

### Ejercicio 1: Identificación de Sesiones SMTP y Remitentes Sospechosos

**Hipótesis de Hunting:**
"Un atacante está enviando correos electrónicos falsificados (spoofing) hacia nuestra organización, lo cual se evidenciará mediante discrepancias entre el remitente del sobre (Envelope Sender) y el remitente del encabezado (Header From)."

**Comandos Exactos:**
```bash
# 1. Listar todas las sesiones SMTP para obtener una visión general
hunt_smtp sessions

# 2. Extraer los remitentes (MAIL FROM) y compararlos con los headers
hunt_smtp from

# 3. Usar tshark para buscar discrepancias manualmente (explicación de flags:
# -r: lee el archivo pcap
# -Y: aplica un filtro de visualización (tráfico SMTP)
# -T fields: especifica que queremos extraer campos específicos
# -e: define los campos a extraer)
tshark -r capture.pcap -Y "smtp" -T fields -e smtp.req.parameter -e smtp.header.from | grep -i "from"
```

**Qué buscar en la salida:**
Busca direcciones de correo electrónico en el campo `MAIL FROM` que no coincidan con la dirección mostrada en el campo `From:` del encabezado del correo. Presta atención a dominios que intentan imitar a marcas conocidas (typosquatting).

**Preguntas de Análisis:**
1. ¿Cuántas sesiones SMTP únicas se identificaron en la captura?
2. ¿Qué dirección de correo electrónico aparece en el `MAIL FROM` del correo sospechoso?
3. ¿Qué dirección aparece en el encabezado `From:` que vería el usuario final?
4. ¿Qué técnica está utilizando el atacante al mostrar un dominio diferente al real?

**Respuestas Esperadas:**
1. *Dependiendo del PCAP, generalmente se ven entre 5 y 10 sesiones.*
2. *El `MAIL FROM` (envelope) muestra una dirección asociada a la IP atacante o un dominio comprometido, por ejemplo, `attacker@security-update-portal.com`.*
3. *El encabezado `From:` muestra `security@microsoft.com`.*
4. *El atacante está utilizando Email Spoofing combinado con Typosquatting en el dominio de origen para engañar a la víctima.*

---

### Ejercicio 2: Extracción y Análisis del Adjunto Malicioso

**Hipótesis de Hunting:**
"El correo de phishing contiene un archivo adjunto malicioso codificado en Base64 que incluye un formulario HTML diseñado para robar credenciales corporativas."

**Comandos Exactos:**
```bash
# 1. Extraer los objetos y adjuntos del PCAP usando el helper
hunt_smtp extract

# 2. Listar los archivos extraídos en el directorio actual
ls -la extracted_files/

# 3. Buscar cadenas de texto sospechosas en el archivo HTML extraído (explicación de flags:
# -i: ignora mayúsculas/minúsculas
# -n: muestra el número de línea)
grep -in "password" extracted_files/invoice_update.html
grep -in "<form" extracted_files/invoice_update.html

# 4. Decodificar manualmente un fragmento Base64 si es necesario
echo "PGh0bWw+..." | base64 -d
```

**Qué buscar en la salida:**
Revisa los archivos extraídos en busca de extensiones `.html`, `.exe` o `.zip`. Al analizar el archivo HTML, busca etiquetas `<form>`, campos de entrada de tipo `password` y URLs hacia donde se envían los datos (atributo `action` del formulario).

**Preguntas de Análisis:**
1. ¿Cuál es el nombre del archivo adjunto extraído del correo sospechoso?
2. ¿Qué tipo de archivo es y qué contiene en su interior?
3. ¿Hacia qué URL o dirección IP se envían las credenciales robadas cuando la víctima envía el formulario?

**Respuestas Esperadas:**
1. *El archivo se llama `invoice_update.html`.*
2. *Es un documento HTML que contiene un formulario de inicio de sesión falso (Phishing Page) diseñado para robar credenciales.*
3. *El formulario envía los datos mediante un método POST hacia `http://198.51.100.23/login.php` o un dominio malicioso similar.*

---

### Ejercicio 3: Correlación con Consultas DNS

**Hipótesis de Hunting:**
"La ejecución del archivo malicioso o la recepción del correo generó consultas DNS hacia dominios de infraestructura controlada por el atacante, los cuales pueden ser identificados en el tráfico de red."

**Comandos Exactos:**
```bash
# 1. Ver todas las consultas DNS en el tráfico usando el helper
hunt_smtp dns

# 2. Usar tshark para filtrar consultas DNS específicas (explicación de flags:
# -r: lee el archivo pcap
# -Y: filtra por protocolo DNS
# -T fields -e dns.qry.name: extrae solo los nombres de dominio consultados)
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -nr

# 3. Buscar la resolución IP del dominio sospechoso
tshark -r capture.pcap -Y "dns.qry.name contains \"security-update-portal\"" -V | grep -i "address"
```

**Qué buscar en la salida:**
Identifica dominios inusuales, recientemente creados o que utilicen técnicas de typosquatting. Busca la dirección IP asociada a estos dominios para correlacionarla con la IP de origen del correo electrónico.

**Preguntas de Análisis:**
1. ¿Qué dominio sospechoso fue consultado por la máquina víctima?
2. ¿A qué dirección IP resuelve este dominio malicioso?
3. ¿Coincide esta dirección IP con la IP de origen de la sesión SMTP maliciosa?

**Respuestas Esperadas:**
1. *El dominio consultado es `security-update-portal.com`.*
2. *El dominio resuelve a la IP `198.51.100.23`.*
3. *Sí, la IP de resolución DNS coincide con la IP desde la cual se originó la conexión SMTP maliciosa, confirmando la infraestructura del atacante.*

---

## Mapeo MITRE ATT&CK

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| **T1566.001** | Phishing: Spearphishing Attachment | Recepción de un correo con el adjunto `invoice_update.html`. |
| **T1204.002** | User Execution: Malicious File | El usuario debe abrir el archivo HTML para visualizar el formulario. |
| **T1071.003** | Application Layer Protocol: Mail Protocols | Uso del protocolo SMTP para la entrega del payload malicioso. |
| **T1036.004** | Masquerading: Masquerade Task or Service | Falsificación del encabezado `From:` (`security@microsoft.com`). |

---

## Cadena de Ataque Completa

```text
[ Atacante (198.51.100.23) ]
         |
         | 1. Envía email SMTP falsificado (Spoofing)
         v
[ Servidor de Correo Corporativo ]
         |
         | 2. Entrega email con adjunto Base64 (invoice_update.html)
         v
[ Máquina Víctima ]
         |
         | 3. Usuario abre HTML -> Renderiza formulario falso
         | 4. Consulta DNS a security-update-portal.com
         v
[ Infraestructura Maliciosa ] <-- 5. Envío de credenciales (POST)
```

---

## Limpieza

Una vez finalizado el laboratorio, asegúrate de detener y eliminar los contenedores para liberar recursos en tu sistema:

```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores, redes y volúmenes asociados
docker-compose down -v

# Opcional: Eliminar imágenes huérfanas
docker image prune -f
```

---

## Troubleshooting

- **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  **Solución:** Verifica si tienes otro laboratorio corriendo con `docker ps`. Usa `docker-compose down` en el directorio del laboratorio anterior.

- **Problema:** El comando `hunt_smtp` devuelve "command not found".
  **Solución:** Asegúrate de estar ejecutando los comandos dentro del contenedor `smtp-analyst` y no en tu máquina host. Verifica con `whoami` o el prompt de la terminal.

- **Problema:** `tshark` muestra un error de permisos al leer `capture.pcap`.
  **Solución:** Verifica los permisos del archivo con `ls -l capture.pcap`. Si es necesario, cambia los permisos con `chmod 644 capture.pcap` o ejecuta los comandos como root dentro del contenedor.

- **Problema:** No se extraen archivos al ejecutar `hunt_smtp extract`.
  **Solución:** Asegúrate de estar en el directorio correcto donde se encuentra el archivo PCAP. Verifica que el archivo PCAP no esté corrupto ejecutando `capinfos capture.pcap`.
