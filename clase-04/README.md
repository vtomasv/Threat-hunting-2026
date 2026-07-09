# Clase 4 — Desbordamiento de Búfer en Red + Caso Integrador

## Información General

| Campo | Valor |
|-------|-------|
| **Número** | Clase 4 de 11 |
| **Duración** | 6 horas (2 bloques de 3h) |
| **Unidad** | Unidad 2 — Análisis Forense de Red (cierre) |
| **Tema** | Buffer Overflow en red, File Upload malicioso, Caso Integrador |

## Contenidos

### Bloque 1 (09:00–12:00) — Teoría
- Desbordamiento de búfer: stack overflow, heap overflow, NOP sled
- Detección de exploits en tráfico de red (patrones binarios)
- File Upload malicioso: detección por magic bytes
- Repaso integrador de Unidad 2

### Bloque 2 (13:00–16:00) — Laboratorios
- **Lab 7**: Buffer Overflow + File Upload (detección en PCAP)
- **Lab 8**: Caso Integrador — Incidente completo de red (evaluación parcial)

## Laboratorios

### Lab 7 — Buffer Overflow y File Upload
```bash
cd docker/lab7-buffer-overflow
docker-compose up -d
docker exec -it bof-analyst bash
```

### Lab 8 — Caso Integrador de Red (Evaluación)
```bash
cd docker/lab8-caso-integrador-red
docker-compose up -d
docker exec -it incident-analyst bash
```

## Evaluación

El Lab 8 constituye la **Evaluación Parcial 1** (Caso 1 del programa).
Los estudiantes deben entregar un reporte forense completo con timeline, IOCs y mapeo ATT&CK.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
