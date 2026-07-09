# EVALUACIÓN PARCIAL 1 — Caso Integrador de Red Forense

## Contexto del Incidente

Usted es un Threat Hunter del SOC de la empresa **TechCorp S.A.** El equipo de monitoreo detectó alertas de tráfico anómalo proveniente de su servidor web público (`192.168.10.20`). Se le ha proporcionado una captura de red de 15 minutos para su análisis.

## Objetivo

Reconstruir completamente el incidente, identificar todas las fases del ataque, extraer IOCs y producir un reporte forense profesional.

## Entregables

1. **Reporte de Análisis Forense** (usar plantilla en `/plantilla/reporte_forense.md`)
2. **Timeline completa** del incidente
3. **Lista de IOCs** extraídos
4. **Mapeo MITRE ATT&CK** de las técnicas identificadas

## Instrucciones

1. Comience con un análisis general del PCAP:
   ```bash
   tshark -r /data/lab8_incident.pcap -q -z conv,tcp
   tshark -r /data/lab8_incident.pcap -q -z endpoints,ip
   ```

2. Use las herramientas proporcionadas como punto de partida:
   ```bash
   timeline_builder /data/lab8_incident.pcap
   ioc_extractor /data/lab8_incident.pcap
   ```

3. Profundice en cada fase con queries tshark específicas

4. Complete la plantilla de reporte con toda la evidencia

## Criterios de Evaluación

| Criterio | Peso |
|----------|------|
| Timeline completa y precisa | 30% |
| Identificación correcta de IOCs | 25% |
| Mapeo MITRE ATT&CK | 20% |
| Calidad del reporte | 15% |
| Recomendaciones de mitigación | 10% |

## Plazo

7 días calendario desde la fecha de la clase.

---
*MAR404 — Cacería de Amenazas — Universidad Mayor 2026*
