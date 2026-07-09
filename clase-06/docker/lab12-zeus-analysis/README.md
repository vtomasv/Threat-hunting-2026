# Lab 12 — Análisis de Zeus Botnet en Memoria
**Curso:** MAR404 — Cacería de Amenazas
**Clase:** 06

## Descripción del Escenario
El equipo del Centro de Operaciones de Seguridad (SOC) ha detectado actividad anómala proveniente de una estación de trabajo del departamento de finanzas. Los sistemas de prevención de intrusiones alertaron sobre conexiones sospechosas hacia dominios no categorizados. Se sospecha que el equipo ha sido comprometido por una variante de la botnet Zeus/Zbot, conocida por robar credenciales bancarias. Se ha capturado un volcado de memoria del equipo afectado y se ha preparado un entorno de análisis para investigar el incidente. El malware parece haber inyectado código en procesos legítimos, establecido hooks en APIs críticas para capturar credenciales, y configurado persistencia en el registro.

## Objetivos de Aprendizaje
- Identificar procesos comprometidos mediante inyección de código (DLL Injection).
- Analizar y detectar API hooks utilizados para el robo de credenciales y ocultamiento.
- Extraer y descifrar la configuración del malware para identificar los objetivos bancarios.
- Reconstruir la cadena de ataque y mapear las técnicas utilizadas al framework MITRE ATT&CK.

## Requisitos Previos
- **Docker** y **Docker Compose** instalados en el sistema anfitrión.
- Al menos **2 GB de RAM** disponibles para el contenedor.
- Puertos: No se requieren puertos expuestos para este laboratorio.

## Despliegue Paso a Paso

1. **Clonar o acceder al directorio del laboratorio:**
   Asegúrate de estar en el directorio correcto donde se encuentra el archivo `docker-compose.yml`.
   ```bash
   cd /home/ubuntu/MAR404-threat-hunting-2026/clase-06/docker/lab12-zeus-analysis/
   ```

2. **Levantar el entorno:**
   Inicia el contenedor en modo detached (segundo plano).
   ```bash
   docker-compose up -d
   ```

3. **Verificar el estado del contenedor:**
   Asegúrate de que el contenedor `zeus-analyst` esté en ejecución.
   ```bash
   docker ps | grep zeus-analyst
   ```

4. **Acceder al contenedor:**
   Abre una sesión interactiva de bash dentro del contenedor para comenzar el análisis.
   ```bash
   docker exec -it zeus-analyst bash
   ```

## Ejercicios Paso a Paso

### Ejercicio 1: Detección Integral de Zeus
**Hipótesis de Hunting:** El malware Zeus suele inyectarse en procesos legítimos del sistema, como `explorer.exe` o navegadores web, para evadir la detección y monitorear la actividad del usuario.

**Comandos a ejecutar:**
Ejecuta la herramienta de detección integral para buscar indicadores de compromiso (IoCs) asociados a Zeus en el volcado de memoria.
```bash
zeus_detector
```

**Qué buscar en la salida:**
- Identificadores de procesos (PIDs) sospechosos.
- Nombres de procesos comprometidos (ej. `explorer.exe`, `iexplore.exe`).
- Direcciones de memoria donde se ha inyectado código.

**Preguntas de análisis:**
1. ¿Qué procesos han sido identificados como comprometidos por la herramienta?
2. ¿Cuáles son los PIDs de estos procesos?
3. ¿Qué tipo de anomalía detectó la herramienta en estos procesos?

**Respuestas esperadas:**
1. Los procesos comprometidos son `explorer.exe` y `iexplore.exe`.
2. Los PIDs variarán según la ejecución, pero deben coincidir con los mostrados en la salida de `zeus_detector`.
3. La herramienta detectó inyección de código (DLL Injection) en el espacio de memoria de estos procesos.

---

### Ejercicio 2: Análisis Detallado de API Hooks
**Hipótesis de Hunting:** Para robar credenciales y ocultar su presencia, Zeus establece hooks en funciones críticas de la API de Windows, como las relacionadas con la red (`wininet.dll`) y el sistema (`ntdll.dll`).

**Comandos a ejecutar:**
Utiliza la herramienta de análisis de hooks, especificando el PID de uno de los procesos comprometidos identificados en el ejercicio anterior (reemplaza `<PID>` con el valor real).
```bash
hook_analyzer --pid <PID>
```
*Explicación del flag:* `--pid` indica el identificador del proceso que se va a analizar en busca de hooks.

**Qué buscar en la salida:**
- Nombres de las funciones de la API que han sido hookeadas.
- Módulos (DLLs) a los que pertenecen estas funciones.
- Direcciones de memoria originales y modificadas.

**Preguntas de análisis:**
1. ¿Qué funciones de la API en `ntdll.dll` han sido hookeadas y cuál podría ser su propósito?
2. ¿Qué funciones en `wininet.dll` han sido hookeadas?
3. ¿Cómo ayuda el hooking de `HttpSendRequestW` al atacante?

**Respuestas esperadas:**
1. Funciones como `NtQueryDirectoryFile` han sido hookeadas, probablemente para ocultar archivos maliciosos (T1564.001).
2. Funciones como `HttpSendRequestW` y `InternetReadFile` en `wininet.dll`.
3. El hooking de `HttpSendRequestW` permite al atacante interceptar y capturar credenciales antes de que sean enviadas cifradas por la red (T1056.004).

---

### Ejercicio 3: Extracción de la Configuración del Malware
**Hipótesis de Hunting:** Zeus utiliza un archivo de configuración cifrado que contiene la lista de entidades bancarias objetivo y las direcciones de los servidores de Comando y Control (C2).

**Comandos a ejecutar:**
Ejecuta la herramienta de extracción para descifrar y mostrar la configuración del malware.
```bash
config_extractor
```

**Qué buscar en la salida:**
- URLs o direcciones IP de los servidores C2.
- Lista de dominios o URLs de bancos objetivo (targets).
- Reglas de inyección web (webinjects).

**Preguntas de análisis:**
1. ¿Cuáles son las direcciones de los servidores C2 identificados en la configuración?
2. ¿Qué regiones o países parecen ser el objetivo principal según los bancos listados?
3. ¿Qué mecanismo de persistencia se revela en la configuración o en el análisis previo?

**Respuestas esperadas:**
1. Las direcciones C2 específicas mostradas en la salida de `config_extractor`.
2. Los objetivos bancarios son principalmente instituciones latinoamericanas.
3. El malware utiliza llaves de ejecución del registro (Registry Run Keys) para asegurar su persistencia tras un reinicio (T1547.001).

## Mapeo MITRE ATT&CK

| ID | Técnica | Evidencia / Contexto |
|----|---------|----------------------|
| T1055.001 | DLL Injection | Inyección de código detectada en `explorer.exe` e `iexplore.exe` mediante `zeus_detector`. |
| T1056.004 | Credential API Hooking | Hooks identificados en `HttpSendRequestW` (wininet.dll) usando `hook_analyzer`. |
| T1185 | Browser Session Hijacking | Modificación de respuestas HTTP y robo de sesiones evidenciado por los hooks en APIs de red. |
| T1564.001 | Hidden Files | Hook en `NtQueryDirectoryFile` (ntdll.dll) para ocultar artefactos del malware. |
| T1547.001 | Registry Run Keys | Configuración de persistencia en el registro de Windows. |

## Cadena de Ataque Completa

```text
[Infección Inicial] --> [Ejecución] --> [Inyección de Código] --> [Establecimiento de Hooks] --> [Robo de Credenciales]
       |                    |                   |                          |                             |
  (Phishing/Drive-by)  (Malware Dropper)  (T1055.001 en explorer)  (T1056.004 en wininet.dll)  (Interceptación HTTP)
                                                |                          |
                                         [Persistencia]             [Ocultamiento]
                                                |                          |
                                     (T1547.001 Registry Keys)  (T1564.001 NtQueryDirectoryFile)
```

## Limpieza

Una vez finalizado el análisis, sal del contenedor y detén el entorno para liberar recursos.

1. **Salir del contenedor:**
   ```bash
   exit
   ```

2. **Detener y eliminar los contenedores:**
   ```bash
   docker-compose down
   ```

## Troubleshooting

- **Problema:** El comando `docker-compose up -d` falla indicando que el puerto ya está en uso.
  **Solución:** Aunque este laboratorio no expone puertos, si hay conflictos, verifica qué contenedores están corriendo con `docker ps` y detén los que no necesites con `docker stop <container_id>`.

- **Problema:** No se encuentra el comando `zeus_detector` o `hook_analyzer` dentro del contenedor.
  **Solución:** Asegúrate de haber accedido al contenedor correcto (`zeus-analyst`). Verifica que la imagen se haya construido correctamente revisando los logs con `docker-compose logs`.

- **Problema:** El contenedor se detiene inmediatamente después de iniciarlo.
  **Solución:** Revisa los logs del contenedor con `docker logs zeus-analyst` para identificar errores de inicio. Asegúrate de tener suficiente memoria RAM disponible en el sistema anfitrión.

- **Problema:** Permisos denegados al ejecutar docker.
  **Solución:** Asegúrate de que tu usuario pertenezca al grupo `docker` o ejecuta los comandos con `sudo`.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
