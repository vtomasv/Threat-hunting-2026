# Lab 10 — Find Evil: Identificar Procesos Maliciosos

## Contexto

Se ha obtenido un memory dump de una estación de trabajo corporativa (Windows 10) del usuario `john.smith`. El equipo de IR sospecha que la máquina fue comprometida a través de un email de phishing. Su tarea es identificar TODOS los procesos maliciosos y las técnicas utilizadas.

## Objetivos

1. Identificar procesos con comportamiento anómalo
2. Clasificar las técnicas de evasión utilizadas
3. Reconstruir la cadena de ataque
4. Mapear a MITRE ATT&CK

## Ejercicios

### Ejercicio 1: Análisis de pslist y timeline (15 min)
```bash
cat /data/vol3_pslist.txt
process_timeline
```
- ¿Qué procesos se crearon mucho después del boot?
- ¿Hay procesos con timestamps sospechosos?

### Ejercicio 2: Análisis de cmdline (10 min)
```bash
cat /data/vol3_cmdline.txt
```
- ¿Hay argumentos inusuales?
- ¿Algún proceso tiene cmdline que no corresponde a su función?

### Ejercicio 3: Correlación de red (15 min)
```bash
network_correlator
cat /data/vol3_netscan.txt
```
- ¿Qué procesos tienen conexiones a IPs externas?
- ¿Algún proceso NO debería tener conexiones de red?

### Ejercicio 4: Detección de inyección (10 min)
```bash
cat /data/vol3_malfind.txt
```
- ¿Qué procesos tienen regiones de memoria RWX?
- ¿Se detecta algún PE inyectado (MZ header)?

### Ejercicio 5: Find Evil completo (10 min)
```bash
find_evil_advanced
```
- Compare sus hallazgos manuales con la detección automática
- ¿Encontró algo que el script no detectó?

## Entregable

Complete la siguiente tabla para cada proceso sospechoso:

| PID | Nombre | Técnica MITRE | Evidencia | Veredicto |
|-----|--------|---------------|-----------|-----------|
| | | | | Malicioso/Legítimo |

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
