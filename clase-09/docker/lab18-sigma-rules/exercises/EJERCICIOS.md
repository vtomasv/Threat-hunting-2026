# Ejercicios de Sigma Rules — Lab 18

## Ejercicio 1: PowerShell Encoded Command
Escriba una regla Sigma que detecte PowerShell con parámetro `-enc` o `-encodedcommand`.
- Logsource: process_creation, windows
- Nivel: high
- MITRE: T1059.001

## Ejercicio 2: Service Installation desde Temp
Escriba una regla que detecte instalación de servicios con binarios en C:\Windows\Temp o C:\Users.
- Logsource: system (Event ID 7045)
- Nivel: critical
- MITRE: T1543.003

## Ejercicio 3: Scheduled Task via schtasks
Escriba una regla que detecte creación de scheduled tasks via línea de comandos.
- Logsource: process_creation, windows
- Nivel: medium
- MITRE: T1053.005

## Ejercicio 4: DNS Query a TLD sospechoso
Escriba una regla que detecte queries DNS a dominios .xyz, .top, .tk, .ml.
- Logsource: dns_query (Sysmon Event ID 22)
- Nivel: medium
- MITRE: T1568.002

## Ejercicio 5: Certutil Download
Escriba una regla que detecte uso de certutil para descargar archivos.
- Logsource: process_creation, windows
- Nivel: high
- MITRE: T1105

## Validación
Después de escribir cada regla, conviértala con:
```bash
sigma convert -t elasticsearch -p sysmon rules/mi_regla.yml
sigma convert -t splunk -p sysmon rules/mi_regla.yml
```

## Entrega
Guarde sus 5 reglas en /app/rules/ con nombres descriptivos.
