# Clase 5 — Análisis Forense de Memoria: Windows Internals y Volatility 3

## Información General

| Campo | Valor |
|-------|-------|
| **Número** | Clase 5 de 11 |
| **Duración** | 6 horas (2 bloques de 3h) |
| **Unidad** | Unidad 3 — Análisis Forense de Memoria (inicio) |
| **Tema** | Windows Internals, Procesos Core, Metodología Find Evil, Volatility 3 |

## Contenidos

### Bloque 1 (09:00–12:00) — Teoría
- Fundamentos de memoria forense y orden de volatilidad
- Adquisición de memoria: herramientas y formatos
- Windows Internals: 7 procesos fundamentales y relaciones padre-hijo
- Metodología Find Evil (SANS): checklist de 7 puntos
- Volatility 3: comandos fundamentales (pslist, pstree, cmdline, netscan, malfind)

### Bloque 2 (13:00–16:00) — Laboratorios
- **Lab 9**: Análisis de Procesos con Volatility 3 (75 min)
- **Lab 10**: Find Evil — Identificar Procesos Maliciosos Avanzados (60 min)
- Debriefing y discusión de hallazgos

## Laboratorios

### Lab 9 — Volatility 3 Fundamentals
```bash
cd docker/lab9-volatility-fundamentals
docker-compose up -d
docker exec -it vol3-analyst bash
```
**Técnicas**: Masquerading (T1036), Credential Dumping (T1003), Wrong Path, Encoded PowerShell

### Lab 10 — Find Evil Advanced
```bash
cd docker/lab10-windows-processes
docker-compose up -d
docker exec -it findevil-analyst bash
```
**Técnicas**: Process Hollowing (T1055.012), DLL Side-Loading (T1574.002), Parent PID Spoofing (T1134.004), Token Manipulation (T1134.001)

## Herramientas

| Herramienta | Descripción |
|-------------|-------------|
| `hunt_processes` | Muestra salida simulada de Volatility |
| `find_evil_checker` | Aplica reglas Find Evil básicas |
| `find_evil_advanced` | Detecta técnicas avanzadas de evasión |
| `process_timeline` | Timeline de creación de procesos |
| `network_correlator` | Correlación red ↔ procesos |
| `vol_cheatsheet` | Referencia rápida de Volatility 3 |

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
