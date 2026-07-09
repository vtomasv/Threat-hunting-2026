# Clase 8 — Windows Event IDs, Sysmon y ELK Stack

## Unidad 4: Análisis de Endpoints y Caza Avanzada

### Contenidos
- Windows Event IDs críticos para hunting (4624, 4625, 4648, 4688, 4697, 7045, 1102)
- Sysmon: configuración, Event IDs (1, 3, 7, 8, 10, 11, 13, 22, 25)
- ELK Stack para Threat Hunting: KQL queries
- Detección basada en comportamiento

### Laboratorios
| Lab | Nombre | Descripción |
|-----|--------|-------------|
| 15 | Sysmon + ELK Hunting | 500+ eventos con 8 técnicas ATT&CK para detectar |
| 16 | Windows Event IDs | 250+ eventos con 5 escenarios de ataque |

### Despliegue
```bash
cd docker/lab15-sysmon-elk-hunting && docker-compose up -d
cd docker/lab16-windows-eventids && docker-compose up -d
```

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
