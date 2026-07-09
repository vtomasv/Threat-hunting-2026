# Clase 9 — Osquery, MITRE ATT&CK Navigator y Sigma Rules

## Unidad 4: Análisis de Endpoints y Caza Avanzada

### Contenidos
- Osquery: SQL para endpoints, tablas clave, queries de hunting
- MITRE ATT&CK Navigator: layers de cobertura, gap analysis
- Sigma Rules: sintaxis YAML, conversión multiplataforma
- Integración de las 3 herramientas en workflow de hunting

### Laboratorios
| Lab | Nombre | Descripción |
|-----|--------|-------------|
| 17 | Osquery Hunting | Endpoint comprometido con 6 IOCs a detectar via SQL |
| 18 | Sigma Rules | Escritura de 5 reglas + conversión a Elastic/Splunk |

### Despliegue
```bash
cd docker/lab17-osquery-hunting && docker-compose up -d
cd docker/lab18-sigma-rules && docker-compose up -d
```

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
