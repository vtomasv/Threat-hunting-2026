# Clase 7 — DLL Injection Avanzada, Troyanos y Caso Integrador de Memoria

## Unidad 3: Análisis Forense de Memoria (cierre)

### Contenidos
- DLL Injection Avanzada: Reflective, Side-Loading, Module Stomping
- Troyanos modernos en memoria: Emotet, Qakbot, Raspberry Robin
- Técnicas de evasión de EDR: Direct Syscalls, Unhooking, Sleep Obfuscation
- Caso Integrador de Memoria (Evaluación Parcial 2)

### Laboratorios

| Lab | Descripción | Duración |
|-----|-------------|----------|
| Lab 13 | DLL Side-Loading + Trojan Analysis | 45 min |
| Lab 14 | **Caso Integrador de Memoria (EVALUACIÓN)** | 90 min |

### Despliegue rápido
```bash
# Lab 13
cd docker/lab13-dll-injection && docker-compose up -d
docker exec -it dll-analyst bash

# Lab 14 (Evaluación)
cd docker/lab14-caso-integrador-memoria && docker-compose up -d
docker exec -it memory-forensics bash
```

### Evaluación Parcial 2
El Lab 14 constituye la Evaluación Parcial 2 (35% de la nota). Los estudiantes tienen 90 minutos para analizar un memory dump con una cadena de ataque completa y entregar un reporte forense profesional.

### Técnicas MITRE ATT&CK
T1055.001, T1574.002, T1055.012, T1003.001, T1059.001, T1566.001, T1053.005, T1570, T1018, T1074.001, T1560.001

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
