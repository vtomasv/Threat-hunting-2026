# Lab 12 — Análisis de Zeus Botnet en Memoria

## Contexto
Una estación de trabajo de un cajero bancario fue reportada por actividad sospechosa. El equipo de IR capturó un memory dump. Su tarea es confirmar la infección con Zeus, extraer IOCs y determinar el alcance del compromiso.

## Objetivos
1. Identificar el proceso inyectado por Zeus
2. Detectar los API hooks instalados
3. Extraer la configuración del bot (C2, targets)
4. Determinar qué información fue comprometida
5. Generar reporte de IOCs para bloqueo

## Ejercicios (75 minutos)

### Paso 1: Reconocimiento de procesos (10 min)
```bash
cat /data/vol3_pslist.txt
```
- ¿Qué procesos tienen notas sospechosas?
- ¿Cuál es el proceso principal inyectado?
- ¿Qué navegadores están activos?

### Paso 2: Detección de API Hooks (20 min)
```bash
cat /data/vol3_apihooks.txt
hook_analyzer
hook_analyzer --pid 2200
hook_analyzer --pid 3100
```
- ¿Qué funciones están hookeadas?
- ¿Cuál es el propósito de cada hook?
- ¿Cómo captura Zeus las credenciales bancarias?

### Paso 3: Extracción de configuración (20 min)
```bash
config_extractor
```
- ¿Cuáles son las URLs de C2?
- ¿Qué bancos son targets?
- ¿Qué datos exfiltra Zeus?
- ¿Cuál es el mecanismo de persistencia?

### Paso 4: Análisis de conexiones (10 min)
```bash
cat /data/connections.json | python3 -m json.tool
```
- ¿Qué conexiones son maliciosas?
- ¿El C2 está activo?

### Paso 5: Detección integral (15 min)
```bash
zeus_detector --full
```
- Compare con sus hallazgos manuales
- Complete el reporte de IOCs

## Entregable

### Reporte de IOCs para bloqueo inmediato:
- IPs de C2: ___
- Dominios DGA: ___
- Mutex: ___
- Registry persistence: ___
- File paths: ___

### Evaluación de impacto:
- ¿Qué credenciales pudieron ser comprometidas?
- ¿Qué bancos fueron targeted?
- ¿Cuánto tiempo estuvo activa la infección?

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
