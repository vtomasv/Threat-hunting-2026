# Lab 20 — Detección de Web Shells
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 10

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha recibido múltiples alertas sobre tráfico anómalo proveniente del servidor web corporativo principal. Los analistas sospechan que un actor de amenazas ha logrado evadir los controles perimetrales y ha comprometido el servidor, instalando mecanismos de persistencia. La evidencia preliminar sugiere la presencia de múltiples web shells ocultas en diferentes directorios del servidor. Tu misión como Threat Hunter es analizar la imagen del servidor comprometido, identificar las 4 web shells (incluyendo variantes ofuscadas y sofisticadas), rastrear la IP del atacante y determinar el alcance de la intrusión.

## Objetivos de Aprendizaje
* Identificar y analizar diferentes tipos de web shells (one-liners, ofuscadas, disfrazadas y sofisticadas).
* Utilizar herramientas de línea de comandos y scripts personalizados para la detección de anomalías en el sistema de archivos.
* Analizar logs de acceso web (Apache) para reconstruir la actividad del atacante y extraer indicadores de compromiso (IoCs).
* Desarrollar reglas YARA personalizadas para la detección de web shells avanzadas.

## Requisitos Previos
* **Docker y Docker Compose:** Instalados y actualizados en el sistema host.
* **Memoria RAM:** Mínimo 2 GB disponibles para el contenedor.
* **Puertos:** Ningún puerto expuesto requerido (análisis offline sobre volumen montado).

## Despliegue Paso a Paso

1. **Clonar o acceder al directorio del laboratorio:**
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-10/docker/lab20-webshell-detection/
   ```

2. **Levantar el entorno con Docker Compose:**
   ```bash
   docker-compose up -d
   ```
   *Verificación:* Ejecuta `docker ps` y asegúrate de que el contenedor `webshell-analyst` esté en estado "Up".

3. **Acceder al contenedor de análisis:**
   ```bash
   docker exec -it webshell-analyst bash
   ```
   *Verificación:* El prompt debe cambiar a `root@webshell-analyst:/#`. Verifica que las herramientas estén presentes ejecutando `ls -la /evidence/var/www/html/` y `python3 webshell_hunter.py -h`.

---

## Ejercicios Paso a Paso

### Ejercicio 1: Cacería de Web Shells Básicas y Ofuscadas

**Hipótesis de Hunting:**
Los atacantes suelen inyectar código malicioso en archivos PHP legítimos o subir archivos con extensiones engañosas. Podemos identificar estas anomalías buscando funciones peligrosas de PHP y analizando la entropía o codificación en los archivos.

**Comandos EXACTOS a ejecutar:**
```bash
# Buscar funciones peligrosas comunes en archivos PHP
grep -RnE "(eval|system|shell_exec|base64_decode|rot13)" /evidence/var/www/html/

# Explicación de flags:
# -R: Búsqueda recursiva en todos los subdirectorios.
# -n: Muestra el número de línea donde ocurre la coincidencia.
# -E: Permite el uso de expresiones regulares extendidas.

# Ejecutar el script de escaneo automatizado
python3 webshell_hunter.py --scan

# Explicación de flags:
# --scan: Ejecuta el módulo de escaneo de archivos en busca de firmas conocidas de web shells.
```

**Qué buscar en la salida:**
* Archivos legítimos (como `config.php`) que contengan funciones como `eval()` en una sola línea (one-liner).
* Archivos en el directorio `uploads/` con cadenas largas en base64 o funciones de ofuscación como `str_rot13`.
* Archivos con doble extensión o extensiones engañosas (ej. `.php.jpg`) en el directorio `images/`.

**Preguntas de análisis:**
1. ¿Qué archivo contiene la web shell tipo "China Chopper" y en qué línea se encuentra?
2. ¿Qué técnica de ofuscación se utilizó en el archivo encontrado en el directorio `uploads/`?
3. ¿Cómo logró el atacante ocultar la web shell en el directorio `images/`?

**Respuestas esperadas:**
* **Pregunta 1:** La web shell China Chopper se encuentra en `/evidence/var/www/html/includes/config.php`, inyectada como un one-liner usando la función `eval()`.
* **Pregunta 2:** El archivo en `uploads/` utiliza una combinación de `str_rot13` y `base64_decode` para ofuscar el payload malicioso.
* **Pregunta 3:** El atacante disfrazó el archivo usando una doble extensión `.php.jpg` o configurando el servidor para interpretar archivos `.jpg` como PHP, evadiendo filtros de subida básicos.

---

### Ejercicio 2: Análisis de Logs y Reconstrucción de la Actividad

**Hipótesis de Hunting:**
La interacción con las web shells dejará rastros en los logs de acceso del servidor web. Analizando las peticiones HTTP (métodos POST, parámetros inusuales, User-Agents anómalos), podemos identificar la IP del atacante y los comandos ejecutados.

**Comandos EXACTOS a ejecutar:**
```bash
# Extraer las IPs con más peticiones POST
cat /evidence/var/log/apache2/access.log | awk '($8 ~ /POST/) {print $1}' | sort | uniq -c | sort -nr

# Explicación de flags:
# awk '($8 ~ /POST/) {print $1}': Filtra líneas con método POST y extrae la IP (columna 1).
# sort | uniq -c | sort -nr: Ordena, cuenta ocurrencias únicas y ordena numéricamente de forma descendente.

# Buscar peticiones a los archivos sospechosos encontrados en el Ejercicio 1
grep -E "(config\.php|uploads/|images/)" /evidence/var/log/apache2/access.log

# Explicación de flags:
# -E: Permite el uso de expresiones regulares extendidas para buscar múltiples patrones.

# Ejecutar el análisis de logs automatizado
python3 webshell_hunter.py --logs

# Explicación de flags:
# --logs: Analiza los logs de Apache en busca de patrones de interacción con web shells.
```

**Qué buscar en la salida:**
* Direcciones IP que realizan múltiples peticiones POST a archivos PHP específicos.
* Parámetros en la URL o en el cuerpo de la petición que contengan comandos del sistema operativo (ej. `whoami`, `ls`, `cat /etc/passwd`).
* Códigos de estado HTTP 200 en peticiones a archivos con extensiones inusuales.

**Preguntas de análisis:**
1. ¿Cuál es la dirección IP principal del atacante?
2. ¿Qué comandos del sistema operativo intentó ejecutar el atacante a través de la web shell?
3. ¿Se observa el uso de alguna herramienta automatizada por parte del atacante basándose en el User-Agent?

**Respuestas esperadas:**
* **Pregunta 1:** La IP del atacante es `203.0.113.45` (o la IP que destaque en el análisis de logs).
* **Pregunta 2:** El atacante ejecutó comandos de reconocimiento como `whoami`, `id`, `uname -a` y `cat /etc/passwd`.
* **Pregunta 3:** Sí, el User-Agent revela el uso de herramientas como "AntSword" o "Behinder", comunes para la gestión de web shells.

---

### Ejercicio 3: Detección Avanzada con YARA

**Hipótesis de Hunting:**
Las web shells sofisticadas pueden evadir la detección basada en firmas simples mediante el uso de autenticación por cabeceras HTTP o cifrado. Podemos crear reglas YARA personalizadas para identificar patrones de comportamiento o estructuras de código específicas de estas amenazas avanzadas.

**Comandos EXACTOS a ejecutar:**
```bash
# Inspeccionar el contenido de la web shell sofisticada
cat /evidence/var/www/html/api/handler.php

# Crear un archivo para la regla YARA
cat << 'EOF' > /root/custom_webshell.yar
rule Sophisticated_Webshell {
    meta:
        description = "Detecta web shell con autenticación por cabecera HTTP"
        author = "Threat Hunter"
    strings:
        $auth = "HTTP_X_CUSTOM_AUTH"
        $exec1 = "eval("
        $exec2 = "system("
    condition:
        $auth and ($exec1 or $exec2)
}
EOF

# Ejecutar el escaneo YARA con la regla personalizada
python3 webshell_hunter.py --yara /root/custom_webshell.yar

# Explicación de flags:
# --yara: Ejecuta el motor YARA utilizando el archivo de reglas especificado contra el directorio web.
```

**Qué buscar en la salida:**
* En el código de `handler.php`, buscar validaciones de cabeceras HTTP (ej. `$_SERVER['HTTP_X_CUSTOM_AUTH']`) o funciones de descifrado.
* La salida del script `webshell_hunter.py` debe confirmar que la regla YARA ha detectado exitosamente el archivo `handler.php`.

**Preguntas de análisis:**
1. ¿Qué mecanismo de autenticación utiliza la web shell sofisticada para evitar el acceso no autorizado?
2. ¿Qué cadenas o patrones específicos incluiste en tu regla YARA para detectar esta web shell sin generar falsos positivos?
3. ¿Por qué las firmas de antivirus tradicionales podrían fallar al detectar esta web shell?

**Respuestas esperadas:**
* **Pregunta 1:** La web shell verifica la presencia y el valor de una cabecera HTTP específica (ej. `X-Custom-Auth`) antes de ejecutar cualquier comando.
* **Pregunta 2:** La regla YARA incluye cadenas que buscan la validación de la cabecera (`HTTP_X_CUSTOM_AUTH`) y funciones de ejecución (`eval` o `system`).
* **Pregunta 3:** Los antivirus tradicionales suelen buscar firmas estáticas conocidas. Esta web shell utiliza código personalizado y mecanismos de autenticación que no coinciden con las firmas públicas de web shells comunes.

---

## Mapeo MITRE ATT&CK

| Táctica | Técnica ID | Nombre de la Técnica | Evidencia en el Laboratorio |
| :--- | :--- | :--- | :--- |
| Persistence | T1505.003 | Server Software Component: Web Shell | Archivos `config.php`, `handler.php` y scripts en `uploads/` e `images/`. |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Comandos ejecutados a través de las web shells (`whoami`, `id`). |
| Defense Evasion | T1027 | Obfuscated Files or Information | Uso de `base64_decode` y `str_rot13` en la web shell de `uploads/`. |
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | Archivo con doble extensión `.php.jpg` en el directorio `images/`. |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Tráfico HTTP/HTTPS malicioso registrado en `access.log`. |

---

## Cadena de Ataque Completa

```text
[Atacante: 203.0.113.45]
       |
       | 1. Explotación de vulnerabilidad web / Subida de archivos
       v
[Servidor Web (Apache)]
       |
       | 2. Instalación de Web Shells
       +---> /includes/config.php (China Chopper)
       +---> /uploads/backup.php (Ofuscada)
       +---> /images/logo.php.jpg (Disfrazada)
       +---> /api/handler.php (Sofisticada con Auth)
       |
       | 3. Ejecución de Comandos (C2)
       v
[Sistema Operativo Linux]
       |---> whoami
       |---> cat /etc/passwd
       |---> uname -a
```

---

## Limpieza

Una vez finalizado el laboratorio, asegúrate de detener y eliminar los contenedores para liberar recursos en tu sistema host.

```bash
# Salir del contenedor
exit

# Detener y eliminar los contenedores, redes y volúmenes asociados
docker-compose down -v

# Opcional: Eliminar la imagen construida si no se volverá a usar
docker rmi lab20-webshell-detection_webshell-analyst
```

---

## Troubleshooting

1. **El contenedor no inicia o se reinicia constantemente:**
   * *Solución:* Verifica que no haya otro servicio ocupando los puertos requeridos. Revisa los logs con `docker-compose logs`.
2. **No se encuentra el script `webshell_hunter.py`:**
   * *Solución:* Asegúrate de estar en el directorio correcto (`/`) o utiliza la ruta absoluta. Verifica que el volumen se haya montado correctamente.
3. **Los comandos de análisis de logs no devuelven resultados:**
   * *Solución:* Verifica que la ruta del log sea correcta (`/evidence/var/log/apache2/access.log`). Puedes usar `ls -la /evidence/var/log/apache2/` para confirmar la existencia del archivo.
4. **La regla YARA genera errores de sintaxis:**
   * *Solución:* Revisa la sintaxis de tu archivo `.yar`. Asegúrate de que las secciones `strings` y `condition` estén correctamente definidas y que las llaves `{}` estén balanceadas.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
