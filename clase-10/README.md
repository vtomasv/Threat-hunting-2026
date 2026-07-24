# Clase 10 — Artefactos Forenses, YARA y Web Shells

## MAR404 — Cacería de Amenazas (Threat Hunter)
### Universidad Mayor 2026

---

## Datos de la Clase

| Campo | Detalle |
|-------|---------|
| **Clase** | 10 de 11 |
| **Horario** | 08:00 — 13:30 (5.5 horas) |
| **Unidad** | Unidad 4: Análisis de Endpoints y Caza Avanzada |
| **Modalidad** | 100% Presencial — Laboratorios hands-on con noVNC |
| **Evaluación** | Caso práctico integrador (entrega al final de la clase) |

---

## Agenda de la Clase

| Bloque | Horario | Actividad | Duración |
|--------|---------|-----------|----------|
| **Apertura** | 08:00 — 08:15 | Briefing del día, objetivos y contexto | 15 min |
| **Teoría** | 08:15 — 09:00 | Artefactos forenses de Windows: Prefetch, Amcache, UserAssist, MFT | 45 min |
| **Lab 19** | 09:00 — 11:00 | Laboratorio: Análisis Forense de Artefactos + Timestomping | 2 horas |
| **Break** | 11:00 — 11:15 | Pausa | 15 min |
| **Teoría** | 11:15 — 11:45 | Web Shells: tipos, técnicas de evasión, detección con YARA | 30 min |
| **Lab 20** | 11:45 — 13:15 | Laboratorio: Detección de Web Shells en Servidor Comprometido | 1.5 horas |
| **Cierre** | 13:15 — 13:30 | Debriefing, discusión de hallazgos, asignación de tarea | 15 min |

---

## Contenidos Teóricos

### Bloque 1: Artefactos Forenses de Windows (45 min)

1. **Prefetch** — Registro de ejecución de programas en Windows
   - Estructura del archivo `.pf` (formato MAM, versión 30)
   - Información disponible: run count, timestamps, directorios accedidos
   - Detección de LOLBins y herramientas de ataque
   - Limitaciones: máximo 1024 archivos en Windows 10/2019

2. **Amcache.hve** — Inventario de aplicaciones
   - Registry hive con hashes SHA1 de ejecutables
   - Detección de binarios sin firma digital
   - Correlación con VirusTotal y plataformas de TI
   - Detección de masquerading (T1036.005)

3. **UserAssist** — Programas ejecutados via shell
   - Codificación ROT13 de nombres de programa
   - Focus count y focus time como indicadores de comportamiento
   - Detección de ejecuciones en background (beacons C2)

4. **MFT y Timestomping** — Manipulación de timestamps
   - Atributos $STANDARD_INFORMATION vs $FILE_NAME
   - Técnica T1070.006: Indicator Removal: Timestomp
   - Métodos de detección: comparación SI vs FN
   - Herramientas: MFTECmd, analyzeMFT, python-mft

### Bloque 2: Web Shells y Detección (30 min)

1. **Tipos de Web Shells**
   - One-liners (China Chopper, WSO)
   - Shells ofuscadas (base64, ROT13, gzinflate)
   - Shells disfrazadas (doble extensión, magic bytes)
   - Shells cifradas (AES, comunicación encriptada)

2. **Técnicas de Detección**
   - Búsqueda de funciones peligrosas (grep)
   - Análisis de entropía de Shannon
   - Reglas YARA para detección automatizada
   - Análisis de logs de acceso web
   - Detección de .htaccess maliciosos

3. **MITRE ATT&CK: T1505.003** — Server Software Component: Web Shell

---

## Laboratorios

### Lab 19: Análisis Forense de Artefactos Windows

| Aspecto | Detalle |
|---------|---------|
| **Escenario** | Servidor SRV-FIN-01 comprometido por APT |
| **Artefactos** | Prefetch, Amcache, UserAssist, MFT |
| **Técnicas** | Masquerading, LOLBins, Timestomping, Credential Dumping |
| **Herramientas** | Python parsers, jq, timeline builder |
| **Acceso** | `http://localhost:6080/vnc.html` |
| **Duración** | 2 horas |

### Lab 20: Detección de Web Shells

| Aspecto | Detalle |
|---------|---------|
| **Escenario** | Servidor web corporativo con 4 web shells ocultas |
| **Shells** | China Chopper, Ofuscada, Disfrazada, Cifrada AES |
| **Técnicas** | Ofuscación, doble extensión, .htaccess override, AES |
| **Herramientas** | grep, YARA, Python scanners, log analysis |
| **Acceso** | `http://localhost:6081/vnc.html` |
| **Duración** | 1.5 horas |

---

## Despliegue Rápido

### Opción 1: Ambos laboratorios simultáneamente

```bash
cd clase-10-labs/
docker-compose up -d --build
```

Acceso:
- Lab 19: `http://localhost:6080/vnc.html` (password: `hunter2026`)
- Lab 20: `http://localhost:6081/vnc.html` (password: `hunter2026`)

### Opción 2: Un laboratorio a la vez

```bash
# Solo Lab 19
cd clase-10-labs/lab19-forensic-artifacts/
docker-compose up -d --build

# Solo Lab 20
cd clase-10-labs/lab20-webshell-detection/
docker-compose up -d --build
```

### Detener todo

```bash
cd clase-10-labs/
docker-compose down -v
```

---

## Compatibilidad

| Plataforma | Arquitectura | Estado |
|-----------|--------------|--------|
| macOS (Apple Silicon M1/M2/M3/M4) | ARM64 | Soportado |
| macOS (Intel) | AMD64 | Soportado |
| Windows 10/11 + Docker Desktop | AMD64 | Soportado |
| Linux (Ubuntu/Debian/Fedora) | AMD64 | Soportado |
| Linux (Raspberry Pi, AWS Graviton) | ARM64 | Soportado |

La imagen base `ubuntu:22.04` es multi-arch y se adapta automáticamente a la arquitectura del host. Todas las herramientas instaladas (Python, YARA, Sleuth Kit) están disponibles para ambas arquitecturas.

---

## Evaluación de la Clase

Al finalizar ambos laboratorios, cada estudiante debe entregar:

1. **Reporte del Lab 19:** Timeline consolidada del ataque con mapeo MITRE ATT&CK completo.
2. **Reporte del Lab 20:** Lista de las 4 web shells encontradas con técnica de detección utilizada para cada una.
3. **Regla YARA personalizada** que detecte al menos una de las web shells avanzadas.
4. **Lista de IOCs** extraídos de ambos casos.

---

## Tarea Autónoma (para la Clase 11)

Preparar un **plan de caza completo** que integre los artefactos forenses de la Clase 10 con las herramientas de la Clase 9 (Osquery, Sigma Rules). El plan debe incluir:
- Hipótesis de caza basada en los TTPs identificados
- Queries de Osquery para detectar los mismos IOCs en endpoints vivos
- Reglas Sigma para alertar sobre comportamiento similar
- Propuesta de respuesta y contención

---

## Referencias

- [SANS Poster: Windows Forensic Analysis](https://www.sans.org/posters/windows-forensic-analysis/)
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
- [MITRE ATT&CK: Timestomp T1070.006](https://attack.mitre.org/techniques/T1070/006/)
- [MITRE ATT&CK: Web Shell T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [NeoPI: Web Shell Detection Tool](https://github.com/Neohapsis/NeoPI)

---

*MAR404 — Cacería de Amenazas (Threat Hunter) — Universidad Mayor 2026*
