# Lab 6 — Detección de Ataques Web (SQLi + Web Shell)

**Curso:** MAR404 - Threat Hunting 2026  
**Clase:** 03  

---

## Descripción del Escenario

El equipo del Centro de Operaciones de Seguridad (SOC) ha recibido una alerta crítica de alta prioridad sobre un posible compromiso en la aplicación web principal de e-commerce de la empresa. Los indicadores iniciales de compromiso (IoCs) sugieren que un atacante externo ha logrado extraer información altamente sensible de la base de datos de producción. 

Posteriormente, el atacante ha utilizado esta información para evadir los controles de acceso, escalar privilegios y establecer persistencia en el servidor web mediante la carga de un script malicioso. Tu misión como Threat Hunter es analizar exhaustivamente los registros de tráfico HTTP, los logs de la aplicación y los eventos del sistema para reconstruir la cadena de ataque completa, desde el reconocimiento inicial hasta la exfiltración de datos confidenciales.

---

## Objetivos de Aprendizaje

- **Identificar y analizar** intentos de inyección SQL (SQLi) en el tráfico HTTP, comprendiendo cómo los atacantes manipulan las consultas a la base de datos.
- **Detectar la carga (upload)** de archivos maliciosos y la instalación de web shells en directorios expuestos públicamente.
- **Correlacionar** la ejecución de comandos del sistema operativo a través de un web shell con el tráfico de red anómalo.
- **Reconstruir la cadena de ataque completa (Kill Chain)** basándose en la evidencia recolectada de múltiples fuentes de logs.
- **Documentar los hallazgos** de manera estructurada y profesional utilizando la metodología y plantilla PEAK.

---

## Requisitos Previos

Para ejecutar este laboratorio correctamente, asegúrate de cumplir con los siguientes requisitos en tu entorno de trabajo:

- **Docker y Docker Compose:** Instalados y actualizados a la última versión estable.
- **Memoria RAM:** Mínimo 2 GB de memoria RAM disponibles para los contenedores.
- **Espacio en Disco:** Al menos 5 GB de espacio libre.
- **Puertos de Red:** Los puertos 80 (HTTP) y 443 (HTTPS) deben estar libres en el host.
- **Conocimientos Previos:** Familiaridad básica con la línea de comandos de Linux, conceptos de redes y análisis de tráfico web.

---

## Despliegue Paso a Paso

Sigue estas instrucciones cuidadosamente para desplegar el entorno del laboratorio. Verifica cada paso antes de continuar.

1. **Clonar o acceder al directorio del laboratorio:**
   Navega al directorio donde se encuentran los archivos de configuración del laboratorio.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-03/docker/lab6-web-attacks
   ```

2. **Levantar el entorno con Docker Compose:**
   Inicia los contenedores en modo "detached" (en segundo plano).
   ```bash
   docker-compose up -d
   ```

3. **Verificar que los contenedores estén en ejecución:**
   Comprueba el estado de los contenedores para asegurarte de que se han iniciado correctamente.
   ```bash
   docker ps | grep lab6-web-attacks
   ```
   *Verificación:* Deberías ver el contenedor `web-attack-analyst` (y posiblemente otros servicios como la base de datos) en estado "Up".

4. **Acceder al contenedor de análisis:**
   Abre una sesión interactiva de bash dentro del contenedor de análisis.
   ```bash
   docker exec -it web-attack-analyst bash
   ```
   *Verificación:* El prompt de tu terminal debería cambiar, indicando que ahora estás dentro del contenedor (ej. `root@web-attack-analyst:/#`).

---

## Ejercicios Paso a Paso

A continuación, se presentan los ejercicios prácticos. Sigue las instrucciones y responde a las preguntas de análisis.

### Ejercicio 1: Detección de SQL Injection

**Hipótesis de Hunting:**  
"Un atacante ha explotado una vulnerabilidad de inyección SQL en los parámetros de búsqueda de la aplicación web para extraer credenciales de la base de datos."

**Comandos a ejecutar:**
```bash
# Listar todas las peticiones HTTP para identificar el endpoint vulnerable
hunt_web requests

# Filtrar y detectar intentos específicos de SQL Injection
hunt_web sqli

# Decodificar los payloads SQLi encontrados para entender la consulta del atacante
decode_payloads --type sqli
```

*Explicación de flags:*
- `requests`: Muestra un resumen tabular de todas las peticiones HTTP registradas en los logs.
- `sqli`: Filtra los logs buscando patrones comunes de inyección SQL (ej. comillas simples, palabras clave SQL).
- `--type sqli`: Indica a la herramienta de decodificación que procese los payloads específicamente como inyecciones SQL.

**Qué buscar en la salida:**
Busca peticiones hacia el endpoint `/products/search?id=` que contengan palabras clave como `UNION SELECT`. Identifica si alguna de estas peticiones devolvió un código de estado HTTP 200 con un tamaño de respuesta inusualmente grande, lo que indicaría una extracción exitosa.

**Preguntas de análisis:**
1. ¿Cuál es la dirección IP de origen del atacante?
2. ¿Qué parámetro específico en la URL fue vulnerable a la inyección SQL?
3. ¿Qué información sensible logró extraer el atacante de la base de datos?

**Respuestas esperadas:**
- **R1:** La IP del atacante es `192.168.1.100`.
- **R2:** El parámetro `id` en la URI `/products/search?id=`.
- **R3:** El atacante extrajo las credenciales `upload_svc:Upload2026!`.

---

### Ejercicio 2: Identificación de Web Shell Upload

**Hipótesis de Hunting:**  
"Utilizando las credenciales comprometidas en la fase anterior, el atacante ha subido un archivo malicioso (web shell) al servidor web para establecer persistencia."

**Comandos a ejecutar:**
```bash
# Buscar peticiones de subida de archivos en los logs web
hunt_web uploads

# Analizar las peticiones POST hacia el directorio de subidas
hunt_web requests | grep "POST /uploads"
```

*Explicación de flags:*
- `uploads`: Analiza los logs en busca de peticiones `multipart/form-data` o accesos a endpoints conocidos de subida de archivos.
- `grep "POST /uploads"`: Filtra la salida estándar para mostrar únicamente las peticiones POST dirigidas al directorio de subidas.

**Qué buscar en la salida:**
Identifica peticiones POST exitosas (código HTTP 200 o 201) que suban archivos con extensiones ejecutables (como `.php`, `.jsp`, `.sh`) en lugar de los formatos de imagen esperados.

**Preguntas de análisis:**
1. ¿Qué cuenta de usuario se utilizó para autenticarse y autorizar la subida del archivo?
2. ¿Cuál es el nombre exacto y la ruta del archivo malicioso subido al servidor?
3. ¿En qué marca de tiempo (timestamp) ocurrió la subida exitosa del archivo?

**Respuestas esperadas:**
- **R1:** Se utilizó la cuenta `upload_svc`.
- **R2:** El archivo es `/uploads/img_2026.php`.
- **R3:** (El timestamp exacto dependerá de la generación de logs del entorno, pero debe coincidir con el evento de subida en la línea de tiempo general).

---

### Ejercicio 3: Análisis de Ejecución de Comandos

**Hipótesis de Hunting:**  
"El atacante ha interactuado con el web shell subido para ejecutar comandos del sistema operativo, realizar reconocimiento interno y exfiltrar información adicional."

**Comandos a ejecutar:**
```bash
# Detectar interacciones con el web shell identificado
hunt_web webshell

# Generar una línea de tiempo completa del ataque
hunt_web timeline

# Decodificar los comandos enviados al web shell
decode_payloads --type webshell
```

*Explicación de flags:*
- `webshell`: Busca patrones de interacción típicos de web shells, como el uso de parámetros `cmd`, `exec`, o cadenas codificadas en base64.
- `timeline`: Correlaciona todos los eventos web y de sistema ordenados cronológicamente para visualizar la secuencia del ataque.
- `--type webshell`: Decodifica los payloads en base64 o URL-encoded enviados específicamente al web shell.

**Qué buscar en la salida:**
Revisa las peticiones POST o GET hacia `/uploads/img_2026.php` y observa los comandos del sistema operativo encapsulados en los parámetros de la petición. Presta atención a las respuestas del servidor que contengan la salida de estos comandos.

**Preguntas de análisis:**
1. ¿Qué comandos del sistema operativo ejecutó el atacante a través del web shell?
2. ¿Qué información adicional logró exfiltrar el atacante tras ejecutar estos comandos?
3. ¿Cuánto tiempo transcurrió entre el reconocimiento inicial y la exfiltración final?

**Respuestas esperadas:**
- **R1:** Los comandos ejecutados fueron `whoami`, `id`, `cat /etc/passwd`, y `netstat`.
- **R2:** El atacante logró exfiltrar las credenciales de la base de datos: `shop_user:Sh0p_DB_2026!`.
- **R3:** (El tiempo exacto se verifica en la salida del comando timeline, mostrando la duración total de la cadena de ataque desde el primer escaneo hasta el último comando).

---

## Mapeo MITRE ATT&CK

La siguiente tabla mapea las acciones del atacante con las tácticas y técnicas del framework MITRE ATT&CK:

| ID Técnica | Nombre de la Técnica | Evidencia en el Laboratorio |
|------------|----------------------|-----------------------------|
| **T1190** | Exploit Public-Facing Application | Peticiones HTTP GET con payloads `UNION SELECT` hacia el endpoint `/products/search`. |
| **T1078** | Valid Accounts | Uso de las credenciales robadas `upload_svc` para acceder al panel de subida de archivos. |
| **T1505.003** | Server Software Component: Web Shell | Subida exitosa y acceso continuo al archivo `/uploads/img_2026.php`. |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Ejecución de comandos del sistema como `whoami` y `cat /etc/passwd` vía web shell. |
| **T1005** | Data from Local System | Exfiltración de credenciales de la base de datos (`shop_user:Sh0p_DB_2026!`) desde archivos locales. |

---

## Cadena de Ataque Completa

El siguiente diagrama ilustra la secuencia completa de eventos (Kill Chain) ejecutada por el atacante:

```text
+-------------------+       +-------------------+       +-------------------+
|  Reconocimiento   | ----> |   SQL Injection   | ----> | Login con Creds   |
| (Escaneo de URIs) |       | (Extracción Creds)|       |      Robadas      |
+-------------------+       +-------------------+       +-------------------+
                                                                |
                                                                v
+-------------------+       +-------------------+       +-------------------+
| Exfiltración de   | <---- |   Ejecución de    | <---- | Upload Web Shell  |
|  Configuración    |       |     Comandos      |       | (/img_2026.php)   |
+-------------------+       +-------------------+       +-------------------+
```

---

## Limpieza

Una vez finalizado el laboratorio y documentados los hallazgos, es fundamental liberar los recursos del sistema para evitar conflictos con futuros laboratorios:

1. **Salir del contenedor de análisis:**
   ```bash
   exit
   ```

2. **Detener y eliminar los contenedores, redes y volúmenes:**
   ```bash
   docker-compose down -v
   ```

3. **Eliminar imágenes huérfanas (opcional pero recomendado):**
   ```bash
   docker image prune -f
   ```

---

## Troubleshooting

Si encuentras problemas durante la ejecución del laboratorio, consulta las siguientes soluciones a problemas comunes:

**Problema 1: El contenedor `web-attack-analyst` no inicia o se reinicia constantemente.**
- *Solución:* Verifica que los puertos 80 y 443 no estén siendo utilizados por otro servicio en tu máquina host (como Apache o Nginx). Puedes usar el comando `netstat -tuln | grep -E '80|443'` para comprobarlo y detener el servicio conflictivo.

**Problema 2: El comando `hunt_web` o `decode_payloads` no se encuentra (command not found).**
- *Solución:* Asegúrate de estar ejecutando los comandos dentro del contenedor correcto. Debes ejecutar `docker exec -it web-attack-analyst bash` antes de intentar usar las herramientas de análisis. No funcionarán en tu máquina host.

**Problema 3: No se ven resultados al ejecutar `hunt_web sqli` o los logs están vacíos.**
- *Solución:* Es posible que los logs tarden unos segundos en generarse completamente al iniciar el laboratorio. Espera al menos 30 segundos y vuelve a ejecutar el comando. Si el problema persiste, reinicia los contenedores con `docker-compose restart`.

**Problema 4: Error de permisos al ejecutar comandos de Docker o Docker Compose.**
- *Solución:* Si estás en un entorno Linux, es posible que necesites ejecutar los comandos de Docker con privilegios de superusuario (ej. `sudo docker-compose up -d`) o agregar tu usuario actual al grupo `docker` mediante `sudo usermod -aG docker $USER`.

**Problema 5: La salida de los comandos se ve desordenada o truncada en la terminal.**
- *Solución:* Ajusta el tamaño de tu ventana de terminal para que sea más ancha, o utiliza herramientas como `less` (ej. `hunt_web requests | less`) para navegar por la salida de manera paginada y ordenada.
