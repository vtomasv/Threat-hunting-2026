# Lab 13 — DLL Side-Loading + Trojan Analysis

## Contexto
Un servidor fue comprometido. El atacante utilizó DLL Side-Loading para ejecutar un troyano personalizado que se esconde detrás de un proceso legítimo de Microsoft (OneDriveUpdater.exe).

## Objetivos
1. Identificar la DLL maliciosa side-loaded
2. Determinar las capacidades del troyano
3. Extraer IOCs (C2, archivos, persistencia)
4. Mapear a MITRE ATT&CK

## Ejercicios (45 minutos)

### Paso 1: Identificar el proceso sospechoso (10 min)
```bash
cat /data/vol3_pslist.txt
cat /data/vol3_dlllist.txt
```
- ¿Qué proceso carga DLLs sospechosas?
- ¿Cuál es la DLL que no debería estar ahí?

### Paso 2: Analizar la DLL maliciosa (15 min)
```bash
dll_analyzer
```
- ¿Cuál es el path legítimo vs el path actual de version.dll?
- ¿Qué exports tiene que son sospechosos?
- ¿Qué imports revelan sobre sus capacidades?

### Paso 3: Perfilar el troyano (10 min)
```bash
trojan_profiler
```
- ¿Cuántas capacidades tiene?
- ¿Cómo exfiltra datos?
- ¿Cuál es el C2?

### Paso 4: Verificar persistencia (10 min)
```bash
persistence_checker
```
- ¿Cómo logra persistencia?
- ¿Por qué es difícil de detectar?

## Entregable
Tabla con: DLL maliciosa, capacidades, C2, persistencia, MITRE mapping.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
