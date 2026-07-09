# Clase 10 — Forensic Artifacts, VirusTotal, YARA y Web Shells

## Unidad 4: Análisis de Endpoints y Caza Avanzada

### Contenidos
- Artefactos forenses: Prefetch, Amcache, ShimCache, UserAssist, MFT
- VirusTotal API: lookup de hashes, IPs, dominios
- YARA Rules: sintaxis, escritura de reglas, Loki scanner
- Web Shells: tipos, detección por contenido, entropía y logs

### Laboratorios
| Lab | Nombre | Descripción |
|-----|--------|-------------|
| 19 | Forensic Artifacts | Análisis de Prefetch, Amcache, MFT con timestomping |
| 20 | Web Shell Detection | 4 web shells ocultas + YARA + log analysis |

### Despliegue
```bash
cd docker/lab19-forensic-artifacts && docker-compose up -d
cd docker/lab20-webshell-detection && docker-compose up -d
```

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
