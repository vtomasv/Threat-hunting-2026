# Lab 1: Threat Hunt — Análisis de Logs Sysmon con ELK

## Curso MAR404 — Cacería de Amenazas (Threat Hunter) — Clase 1
### Universidad Mayor 2026

---

## Descripción

Este laboratorio despliega un entorno completo de Elasticsearch + Kibana pre-cargado con logs de Sysmon (Windows) que contienen actividad benigna y tres eventos maliciosos inyectados. Los estudiantes deben aplicar el Hunting Loop para formular hipótesis, buscar evidencia y documentar hallazgos.

## Requisitos Previos

- Docker Engine 24.0+ y Docker Compose v2
- Mínimo 4 GB de RAM disponible
- Puertos 9200 y 5601 libres

## Despliegue

```bash
# Clonar o descargar este directorio
cd lab1-sysmon-elk

# Levantar el entorno
docker-compose up -d

# Verificar que todos los contenedores están corriendo
docker-compose ps

# Esperar ~60 segundos para la carga de datos
# Verificar logs del loader:
docker-compose logs data-loader
```

## Acceso

| Servicio | URL | Credenciales |
|----------|-----|--------------|
| Kibana | http://localhost:5601 | Sin autenticación |
| Elasticsearch | http://localhost:9200 | Sin autenticación |

## Ejercicios de Hunting

### Ejercicio 1: Detección de certutil.exe (T1105 — Ingress Tool Transfer)

**Hipótesis**: Un adversario utilizó `certutil.exe` para descargar un payload desde un servidor externo.

**Query KQL en Kibana Discover**:
```
event.code: "1" AND process.name: "certutil.exe" AND process.command_line: *urlcache*
```

**Preguntas guía**:
1. ¿Qué archivo fue descargado y dónde se guardó?
2. ¿Cuál fue el proceso padre de certutil.exe?
3. ¿Qué IP/URL se utilizó como origen?
4. ¿A qué técnica MITRE ATT&CK corresponde?

---

### Ejercicio 2: Detección de PowerShell Encoded (T1059.001)

**Hipótesis**: Se ejecutó PowerShell con un comando codificado en Base64 para evadir detección.

**Query KQL**:
```
event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*-Enc* OR *-encodedcommand* OR *-EncodedCommand*)
```

**Preguntas guía**:
1. ¿Cuál es el proceso padre de PowerShell? ¿Es normal?
2. Decodifique el comando Base64. ¿Qué hace?
3. ¿Qué flags adicionales se usaron (-NoP, -NonI, -W Hidden)?
4. ¿Cómo se relaciona con el evento anterior (certutil)?

**Tip para decodificar**:
```bash
echo "SQBFAFgA..." | base64 -d | iconv -f UTF-16LE -t UTF-8
```

---

### Ejercicio 3: Detección de Scheduled Task (T1053.005)

**Hipótesis**: Se creó una tarea programada para mantener persistencia.

**Query KQL**:
```
event.code: "1" AND process.name: "schtasks.exe" AND process.command_line: *create*
```

**Preguntas guía**:
1. ¿Qué nombre tiene la tarea creada?
2. ¿Qué binario ejecuta la tarea?
3. ¿Con qué frecuencia se ejecuta?
4. ¿Bajo qué usuario se ejecutará?
5. ¿Cómo se conecta con los eventos anteriores (cadena de ataque)?

---

## Cadena de Ataque Completa

Los tres eventos maliciosos forman una cadena de ataque coherente:

```
cmd.exe → certutil.exe (descarga payload)
    → svchost.exe falso (payload ejecutado)
        → powershell.exe -Enc (descarga beacon)
            → schtasks.exe (establece persistencia)
```

**Mapeo MITRE ATT&CK**:
- T1105: Ingress Tool Transfer (certutil download)
- T1059.001: Command and Scripting Interpreter: PowerShell
- T1053.005: Scheduled Task/Job: Scheduled Task
- T1036.005: Masquerading: Match Legitimate Name (svchost.exe falso)

## Limpieza

```bash
docker-compose down -v
```

## Troubleshooting

- **Kibana no carga**: Esperar 2-3 minutos adicionales, verificar con `docker-compose logs kibana`
- **No aparecen datos**: Verificar que el data-loader terminó exitosamente con `docker-compose logs data-loader`
- **Error de memoria**: Aumentar memoria asignada a Docker (mínimo 4 GB)
