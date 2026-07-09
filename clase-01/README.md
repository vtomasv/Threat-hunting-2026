# Clase 01 — Introducción al Threat Hunting y Pasos de Respuesta a Incidentes

## Unidad 1 del Programa MAR404

---

## Resumen

Esta clase establece los cimientos conceptuales y metodológicos del curso completo. Los estudiantes aprenderán qué es el Threat Hunting, cómo se diferencia del monitoreo reactivo y la respuesta a incidentes, y aplicarán el Hunting Loop en dos laboratorios prácticos con entornos Docker.

## Objetivos de Aprendizaje

1. Definir Threat Hunting y diferenciarlo del SOC reactivo y DFIR
2. Describir el ciclo de vida de IR según NIST SP 800-61 Rev 3 (2025)
3. Aplicar el Hunting Loop en un escenario guiado introductorio
4. Identificar los componentes del modelo Personas-Procesos-Tecnología
5. Utilizar herramientas básicas de análisis (Wireshark, ELK, Sysmon) en Docker

## Estructura de la Clase (6 horas)

| Bloque | Horario | Contenido |
|--------|---------|-----------|
| Bloque 1 | 09:00–12:00 | Teoría: Hunting, Frameworks, NIST IR, PPT |
| Bloque 2 | 13:00–16:00 | Labs: Sysmon+ELK, Network Analysis, Debriefing |

## Laboratorios Docker

### Lab 1: Sysmon + ELK (Primer Hunt)

```bash
cd docker/lab1-sysmon-elk
docker-compose up -d
# Acceder a Kibana: http://localhost:5601
```

**Objetivo**: Formular hipótesis, buscar evidencia de certutil.exe abuse en logs Sysmon.

### Lab 2: Network Analysis (Beaconing C2)

```bash
cd docker/lab2-network-analysis
docker-compose up -d
docker exec -it hunt-network-analyst bash
```

**Objetivo**: Identificar patrones de beaconing C2 en un PCAP de 30 minutos.

## Contenido del Directorio

```
clase-01/
├── README.md                          # Este archivo
├── CLASE_01_MAPA_COMPLETO.md          # Mapa detallado de la clase
├── docker/
│   ├── lab1-sysmon-elk/               # Lab 1: ELK + Sysmon logs
│   │   ├── docker-compose.yml
│   │   ├── Dockerfile.loader
│   │   ├── scripts/
│   │   └── README.md
│   └── lab2-network-analysis/         # Lab 2: Análisis de red
│       ├── docker-compose.yml
│       ├── Dockerfile.analyst
│       ├── Dockerfile.generator
│       ├── Dockerfile.c2
│       ├── scripts/
│       └── README.md
├── materiales/
│   ├── plantilla_hallazgo_hunting.md  # Plantilla de documentación
│   ├── hunting_loop.png               # Diagrama del Hunting Loop
│   ├── nist_ir_lifecycle.png          # Diagrama NIST IR
│   ├── peak_framework.png            # Diagrama PEAK Framework
│   ├── pyramid_of_pain.png           # Diagrama Pyramid of Pain
│   ├── hmm_maturity.png              # Diagrama HMM
│   └── attack_chain_lab1.png         # Cadena de ataque del Lab 1
```
