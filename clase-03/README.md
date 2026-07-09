# Clase 03 — Análisis Forense de Red: Ransomware, Túneles y Ataques Web

## Unidad del Programa
Unidad 2 — Análisis forense de la red para la cacería de amenazas

## Objetivos de Aprendizaje
1. Analizar tráfico de red asociado a ransomware (fases pre/post cifrado)
2. Detectar túneles de evasión (SSH, ICMP, DNS) mediante análisis de anomalías
3. Identificar ataques de inyección SQL y web shells en tráfico HTTP
4. Aplicar análisis de entropía de Shannon para detectar datos encoded
5. Documentar hallazgos usando el framework PEAK

## Laboratorios

### Lab 5 — Detección de Túneles DNS y Exfiltración
```bash
cd docker/lab5-tunnels-detection
docker-compose up -d
docker exec -it dns-tunnel-analyst bash
```

### Lab 6 — Detección de Ataques Web (SQLi + Web Shell)
```bash
cd docker/lab6-web-attacks
docker-compose up -d
docker exec -it web-attack-analyst bash
```

## Técnicas MITRE ATT&CK
- T1048.001 — Exfiltration Over Alternative Protocol: DNS
- T1572 — Protocol Tunneling
- T1071.004 — Application Layer Protocol: DNS
- T1190 — Exploit Public-Facing Application
- T1505.003 — Server Software Component: Web Shell
- T1486 — Data Encrypted for Impact

## Materiales
- `CLASE_03_MAPA_COMPLETO.md` — Documento maestro de la clase
- `docker/` — Laboratorios Docker listos para desplegar
