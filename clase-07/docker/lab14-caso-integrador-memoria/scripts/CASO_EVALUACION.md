# EVALUACIÓN PARCIAL 2 — Caso Integrador de Memoria

## Contexto del Incidente

El equipo de seguridad de la empresa ACME Corp detectó tráfico anómalo saliente desde el servidor de archivos `FILESVR` (10.0.1.50) hacia una IP externa (198.51.100.10) en puerto 443. Se realizó una captura de memoria RAM del servidor para análisis forense.

**Su tarea**: Analizar el memory dump, reconstruir la cadena de ataque completa, extraer IOCs y generar un reporte forense profesional.

## Tiempo: 90 minutos

## Herramientas Disponibles

| Comando | Descripción |
|---------|-------------|
| `memory_hunter --summary` | Resumen general del análisis |
| `memory_hunter --processes` | Análisis detallado de procesos maliciosos |
| `memory_hunter --malfind` | Regiones de memoria sospechosas |
| `memory_hunter --network` | Conexiones de red |
| `timeline_builder` | Reconstrucción temporal del incidente |
| `ioc_extractor` | Extracción de IOCs |
| `attack_mapper` | Mapeo a MITRE ATT&CK |

## Datos Crudos (simulan salida de Volatility 3)
```
cat /data/vol3_pslist.txt
cat /data/vol3_cmdline.txt
cat /data/vol3_netscan.txt
cat /data/vol3_malfind.txt
cat /data/vol3_handles.txt
```

## Instrucciones

### Fase 1: Reconocimiento (20 min)
1. Revise la lista de procesos (`vol3_pslist.txt`)
2. Identifique anomalías en relaciones padre-hijo
3. Busque procesos con timestamps sospechosos

### Fase 2: Análisis Profundo (30 min)
4. Analice las líneas de comando (`vol3_cmdline.txt`)
5. Revise las regiones malfind (`vol3_malfind.txt`)
6. Correlacione con conexiones de red (`vol3_netscan.txt`)
7. Verifique handles cross-process (`vol3_handles.txt`)

### Fase 3: Reconstrucción (20 min)
8. Construya el timeline completo del ataque
9. Identifique todas las fases (Initial Access → Exfiltration)
10. Mapee cada acción a MITRE ATT&CK

### Fase 4: Reporte (20 min)
11. Complete la plantilla de reporte (`/plantilla/reporte_memoria.md`)
12. Liste IOCs para bloqueo inmediato
13. Proponga medidas de contención

## Criterios de Evaluación

| Criterio | Peso |
|----------|------|
| Identificación correcta de procesos maliciosos | 25% |
| Timeline completo y preciso | 20% |
| IOCs extraídos correctamente | 20% |
| Mapeo MITRE ATT&CK correcto | 15% |
| Recomendaciones de contención | 10% |
| Calidad del reporte | 10% |

## Nota
- Puede usar las herramientas automatizadas para validar, pero debe demostrar análisis manual primero
- El reporte debe ser profesional y presentable a un CISO

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
