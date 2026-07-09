# Clase 02 — Análisis Forense de Red: Protocolos de Aplicación y Detección de Phishing

## Unidad del Programa
Unidad 2 — Análisis forense de la red para la cacería de amenazas

## Objetivos de Aprendizaje
1. Analizar tráfico SMTP para identificar emails de phishing mediante headers forenses
2. Detectar User-Agents anómalos como indicadores de comunicación C2
3. Aplicar filtros tshark/Wireshark para hunting en protocolos HTTP y DNS
4. Documentar hallazgos usando el framework PEAK

## Laboratorios

### Lab 3 — Detección de Phishing en Tráfico SMTP
```bash
cd docker/lab3-smtp-phishing
docker-compose up -d
docker exec -it smtp-analyst bash
```

### Lab 4 — Análisis de Tráfico HTTP y User-Agents Anómalos
```bash
cd docker/lab4-http-anomalies
docker-compose up -d
docker exec -it http-analyst bash
```

## Técnicas MITRE ATT&CK
- T1566.001 — Spearphishing Attachment
- T1071.001 — Application Layer Protocol: Web Protocols
- T1132.001 — Data Encoding: Standard Encoding
- T1036 — Masquerading

## Materiales
- `CLASE_02_MAPA_COMPLETO.md` — Documento maestro de la clase
- `docker/` — Laboratorios Docker listos para desplegar
