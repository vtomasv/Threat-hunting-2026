# Clase 6 — Process Injection, Process Hollowing y Análisis de Zeus Botnet

## Unidad 3: Análisis Forense de Memoria (continuación)

### Contenidos
- Taxonomía completa de Process Injection (MITRE T1055)
- Process Hollowing: flujo técnico y detección
- Zeus Botnet: anatomía, API hooks, configuración, IOCs
- Detección con Volatility 3: malfind, vadinfo

### Laboratorios

| Lab | Descripción | Duración |
|-----|-------------|----------|
| Lab 11 | Detección de Process Injection (DLL, Hollowing, APC) | 75 min |
| Lab 12 | Análisis de Zeus Botnet en Memoria | 75 min |

### Despliegue rápido
```bash
# Lab 11
cd docker/lab11-process-injection && docker-compose up -d
docker exec -it injection-analyst bash

# Lab 12
cd docker/lab12-zeus-analysis && docker-compose up -d
docker exec -it zeus-analyst bash
```

### Técnicas MITRE ATT&CK
T1055.001, T1055.002, T1055.003, T1055.004, T1055.012, T1071.001, T1185, T1056.004, T1564.001, T1547.001, T1568.002

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
