# MAR404 — Cacería de Amenazas (Threat Hunter)

## Magíster en Ciberdefensa — Universidad Mayor — Edición 2026

---

## Descripción del Curso

El curso forma Threat Hunters capaces de realizar cacerías proactivas de amenazas en entornos empresariales, combinando análisis forense de red, memoria y endpoints con metodologías modernas de hunting (PEAK Framework, Hunting Loop, MITRE ATT&CK).

---

## Estructura del Repositorio

```
MAR404-threat-hunting-2026/
├── README.md                    # Este archivo
├── clase-01/                    # Introducción al Threat Hunting + IR
│   └── docker/                  # Laboratorios Docker de la clase
│       ├── lab1-sysmon-elk/     # Lab 1: Hunting con Sysmon + ELK
│       └── lab2-network-analysis/ # Lab 2: Detección de Beaconing C2
├── clase-02/                    # Análisis Forense de Red I
│   └── docker/
│       ├── lab3-smtp-phishing/  # Lab 3: Detección de Phishing SMTP
│       └── lab4-http-anomalies/ # Lab 4: User-Agents Anómalos
├── clase-03/                    # Análisis Forense de Red II
│   └── docker/
│       ├── lab5-tunnels-detection/ # Lab 5: Túneles DNS
│       └── lab6-web-attacks/    # Lab 6: SQLi + Web Shells
├── clase-04/                    # Análisis Forense de Red III
│   └── docker/
│       ├── lab7-buffer-overflow/ # Lab 7: Buffer Overflow + File Upload
│       └── lab8-caso-integrador-red/ # Lab 8: EVALUACIÓN - Caso Integrador Red
├── clase-05/                    # Análisis Forense de Memoria I
│   └── docker/
│       ├── lab9-volatility-fundamentals/ # Lab 9: Volatility 3 Basics
│       └── lab10-windows-processes/ # Lab 10: Find Evil Advanced
├── clase-06/                    # Análisis Forense de Memoria II
│   └── docker/
│       ├── lab11-process-injection/ # Lab 11: Process Injection
│       └── lab12-zeus-analysis/ # Lab 12: Zeus Botnet
├── clase-07/                    # Análisis Forense de Memoria III
│   └── docker/
│       ├── lab13-dll-injection/ # Lab 13: DLL Side-Loading + Trojan
│       └── lab14-caso-integrador-memoria/ # Lab 14: EVALUACIÓN - Caso Integrador Memoria
├── clase-08/                    # Análisis de Endpoints I
│   └── docker/
│       ├── lab15-sysmon-elk-hunting/ # Lab 15: Sysmon + ELK Avanzado
│       └── lab16-windows-eventids/ # Lab 16: Windows Event IDs
├── clase-09/                    # Caza Avanzada
│   └── docker/
│       ├── lab17-osquery-hunting/ # Lab 17: Hunting con Osquery
│       └── lab18-sigma-rules/   # Lab 18: Sigma Rules
├── clase-10/                    # Forensics + YARA
│   └── docker/
│       ├── lab19-forensic-artifacts/ # Lab 19: Artefactos Forenses
│       └── lab20-webshell-detection/ # Lab 20: Web Shell Detection + YARA
├── clase-11/                    # Simulación APT + Evaluación Final
│   └── docker/
│       ├── lab21-apt-simulation/ # Lab 21: APT29 Simulation
│       └── lab22-evaluacion-final/ # Lab 22: EVALUACIÓN FINAL
└── recursos-comunes/            # Recursos compartidos entre clases
```

---

## Información del Curso

| Campo | Detalle |
|-------|---------|
| **Código** | MAR404 |
| **Nombre** | Cacería de Amenazas (Threat Hunter) |
| **Programa** | Magíster en Ciberdefensa |
| **Universidad** | Universidad Mayor |
| **Edición** | 2026 |
| **Duración** | 11 clases |
| **Modalidad** | 100% presencial |
| **Prerrequisito** | MAR303 aprobado |
| **Práctica** | Mínimo 60-65% del tiempo en laboratorios |
| **Laboratorios** | 22 labs Docker autocontenidos |

---

## Mapa de Laboratorios

| Lab | Clase | Tema | Técnicas MITRE ATT&CK |
|-----|-------|------|----------------------|
| 1 | 1 | Sysmon + ELK: Hunting Loop | T1105, T1059.001, T1053.005 |
| 2 | 1 | Detección de Beaconing C2 | T1071.001, T1029 |
| 3 | 2 | Phishing SMTP | T1566.001, T1598 |
| 4 | 2 | User-Agents Anómalos HTTP | T1071.001, T1036 |
| 5 | 3 | Túneles DNS (exfiltración) | T1048.001, T1071.004 |
| 6 | 3 | SQL Injection + Web Shell | T1190, T1505.003 |
| 7 | 4 | Buffer Overflow + File Upload | T1203, T1505.003 |
| 8 | 4 | **Caso Integrador Red** (Evaluación) | Multi-fase |
| 9 | 5 | Volatility 3 Fundamentals | T1036.005, T1055 |
| 10 | 5 | Find Evil: Windows Processes | T1055.012, T1134 |
| 11 | 6 | Process Injection | T1055.001, T1055.012 |
| 12 | 6 | Zeus Botnet Analysis | T1055, T1056.004 |
| 13 | 7 | DLL Side-Loading + Trojan | T1574.002, T1547.001 |
| 14 | 7 | **Caso Integrador Memoria** (Evaluación) | Multi-fase |
| 15 | 8 | Sysmon + ELK Avanzado | T1003.001, T1047, T1055.001 |
| 16 | 8 | Windows Event IDs Hunting | T1078, T1021.001, T1070.001 |
| 17 | 9 | Hunting con Osquery | T1053.005, T1547.001 |
| 18 | 9 | Sigma Rules | T1003.001, T1059.001 |
| 19 | 10 | Artefactos Forenses | T1547.001, T1070.004 |
| 20 | 10 | Web Shell Detection + YARA | T1505.003, T1059.004 |
| 21 | 11 | APT29 Simulation | Kill Chain completa |
| 22 | 11 | **EVALUACIÓN FINAL** (Lazarus/SWIFT) | Kill Chain completa |

---

## Evaluación

| Evaluación | Clase | Ponderación | Tipo |
|------------|-------|-------------|------|
| Caso Integrador Red (Lab 8) | 4 | 30% | Caso práctico |
| Caso Integrador Memoria (Lab 14) | 7 | 30% | Caso práctico |
| Evaluación Final (Lab 22) | 11 | 30% | Hunting Mission |
| Participación + Tareas | 1-11 | 10% | Continua |

Exigencia mínima: 60%

---

## Requisitos Técnicos

Para ejecutar los laboratorios Docker, los estudiantes necesitan:

- **Hardware mínimo**: 16 GB RAM, 100 GB disco libre, procesador con virtualización
- **Software**:
  - Docker Engine 24.0+ y Docker Compose v2
  - Git
  - Wireshark (para análisis visual de PCAPs)
  - Terminal con acceso a bash/zsh
- **Conectividad**: Acceso a Docker Hub para descargar imágenes base

---

## Cómo Usar Este Repositorio

### Clonar el repositorio
```bash
git clone https://github.com/vtomasv/MAR404-threat-hunting-2026.git
cd MAR404-threat-hunting-2026
```

### Ejecutar un laboratorio específico
```bash
cd clase-01/docker/lab1-sysmon-elk
docker compose up -d
```

### Verificar el estado de los contenedores
```bash
docker compose ps
docker compose logs
```

### Acceder al contenedor de análisis
```bash
docker exec -it <container-name> bash
```

### Limpiar después de la clase
```bash
docker compose down -v
```

---

## Herramientas del Curso

| Herramienta | Uso Principal | Clases |
|-------------|---------------|--------|
| Docker / Docker Compose | Despliegue de laboratorios | Todas |
| Wireshark / tshark | Análisis de tráfico de red | 1-4 |
| tcpdump | Captura y filtrado de tráfico | 1-4 |
| ELK Stack (Elasticsearch + Kibana) | SIEM / Análisis de logs | 1, 8, 15-16 |
| Sysmon | Telemetría de endpoint Windows | 1, 8 |
| Volatility 3 | Análisis forense de memoria | 5-7 |
| Osquery | Consultas a endpoints | 9 |
| MITRE ATT&CK Navigator | Mapeo visual de técnicas | Todas |
| Sigma | Reglas de detección | 9, 18 |
| YARA | Detección de malware | 10, 20 |

---

## Competencias

- **CE03**: Desempeña roles de ciberdefensa para prevenir y proteger, integrando procedimientos para detectar amenazas y generando documentación pertinente.
- **CG02**: Autoaprendizaje y Pensamiento Crítico — gestiona recursos y herramientas para la autorregulación y juicio reflexivo.

---

## Licencia

Material educativo de uso exclusivo para el programa de Magíster en Ciberdefensa de la Universidad Mayor. No redistribuir sin autorización.

---

## Contacto

Profesor: Tomás Vera — tomas.vera@umayor.cl
