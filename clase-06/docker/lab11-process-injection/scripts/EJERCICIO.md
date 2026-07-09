# Lab 11 — Detección de Process Injection

## Contexto
Una estación de trabajo fue comprometida. El análisis inicial revela que el atacante utilizó un dropper (`update.exe`) que realizó 3 tipos diferentes de inyección de procesos. Su tarea es identificar cada técnica y documentar la evidencia.

## Objetivos
1. Identificar las 3 técnicas de inyección utilizadas
2. Determinar qué proceso fue el injector (origen)
3. Extraer IOCs de cada inyección
4. Mapear a MITRE ATT&CK

## Ejercicios (75 minutos)

### Paso 1: Reconocimiento (10 min)
```bash
cat /data/vol3_pslist.txt
cat /data/vol3_malfind.txt
```
- ¿Qué procesos tienen regiones RWX?
- ¿Cuántos procesos son sospechosos?

### Paso 2: Análisis de VAD por proceso (20 min)
```bash
vad_inspector --pid 2200    # explorer.exe
vad_inspector --pid 3344    # svchost.exe
vad_inspector --pid 4100    # notepad.exe
vad_inspector --pid 5500    # update.exe (dropper)
```
- ¿Qué tipo de contenido hay en cada región RWX?
- ¿Hay MZ headers? ¿Shellcode?

### Paso 3: Análisis de threads (15 min)
```bash
thread_checker
```
- ¿Qué threads tienen start address en módulos UNKNOWN?
- ¿Qué significa un thread en región sin backing file?

### Paso 4: Identificar el injector (10 min)
```bash
vad_inspector --pid 5500
```
- ¿Qué handles cross-process tiene el dropper?
- ¿A qué procesos apuntan?

### Paso 5: Análisis completo (20 min)
```bash
injection_analyzer
```
- Compare sus hallazgos manuales con el análisis automático
- Complete la tabla de entregable

## Entregable

| PID | Proceso | Técnica | MITRE ID | Evidencia Clave | IOC |
|-----|---------|---------|----------|-----------------|-----|
| | | | | | |

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
