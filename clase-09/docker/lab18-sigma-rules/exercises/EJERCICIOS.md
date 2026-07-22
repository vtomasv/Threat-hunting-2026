# Ejercicios de Sigma Rules — Lab 18

## Parte A: Análisis de Reglas Existentes (Guiado)

### Ejercicio A1: Analizar la regla Mimikatz
```bash
# 1. Ver la regla
cat rules/example_mimikatz.yml

# 2. Verificar su sintaxis
sigma check rules/example_mimikatz.yml

# 3. Convertir a Elasticsearch Query (KQL)
sigma convert -t elasticsearch -p sysmon rules/example_mimikatz.yml

# 4. Convertir a Splunk SPL
sigma convert -t splunk -p sysmon rules/example_mimikatz.yml

# 5. Validar contra el dataset
trigger validate example_mimikatz.yml
```
**Preguntas**: ¿Qué access rights busca? ¿Por qué excluye taskmgr.exe?

### Ejercicio A2: Analizar la regla de Ransomware
```bash
# 1. Ver la regla
cat rules/ransomware_shadow_delete.yml

# 2. Observar las 3 variantes de detección (vssadmin, wmic, powershell)
# 3. Convertir a Elasticsearch
sigma convert -t elasticsearch -p sysmon rules/ransomware_shadow_delete.yml

# 4. Disparar el escenario de ransomware
trigger ransomware_attack

# 5. Validar
trigger validate ransomware_shadow_delete.yml
```
**Preguntas**: ¿Por qué se necesitan 3 variantes? ¿Qué otros métodos existen?

### Ejercicio A3: Analizar la cadena de Lateral Movement
```bash
# 1. Ver las reglas de lateral movement
cat rules/wmi_lateral_movement.yml
cat rules/psexec_lateral.yml

# 2. Disparar el escenario
trigger lateral_movement_chain

# 3. Validar ambas reglas
trigger validate wmi_lateral_movement.yml
trigger validate psexec_lateral.yml
```
**Preguntas**: ¿Cómo diferenciar PsExec legítimo del malicioso?

---

## Parte B: Disparar Escenarios y Detectar (Semi-guiado)

### Ejercicio B1: Ataque APT - Initial Access
```bash
# 1. Disparar el escenario
trigger apt_initial_access

# 2. Validar contra TODAS las reglas
trigger validate

# 3. Identificar qué reglas se dispararon
# 4. Mapear a MITRE ATT&CK: ¿qué tácticas se usaron?
```

### Ejercicio B2: Exfiltración de Datos
```bash
# 1. Disparar el escenario
trigger data_exfiltration

# 2. Validar
trigger validate

# 3. ¿Qué LOLBins se usaron? ¿Qué reglas los detectaron?
```

### Ejercicio B3: Evasión de Defensas Completa
```bash
# 1. Disparar el escenario
trigger defense_evasion_full

# 2. Validar
trigger validate

# 3. ¿Cuántas reglas se dispararon? ¿Hay algún evento sin cobertura?
```

### Ejercicio B4: Robo de Credenciales
```bash
# 1. Disparar el escenario
trigger credential_theft

# 2. Validar
trigger validate

# 3. ¿Qué técnicas T1003 se detectaron?
```

### Ejercicio B5: Ataque Completo (Todos los escenarios)
```bash
# 1. Disparar TODOS los escenarios
trigger all

# 2. Validar contra todas las reglas
trigger validate

# 3. Generar un reporte de cobertura:
#    - ¿Cuántos true positives?
#    - ¿Cuántos false positives?
#    - ¿Qué tácticas MITRE tienen mejor cobertura?
```

---

## Parte C: Escritura de Reglas Propias (Autónomo)

### Ejercicio C1: Detectar PowerShell Download Cradle
Escriba una regla que detecte PowerShell usando `Invoke-WebRequest`, `Net.WebClient`,
o `Start-BitsTransfer` para descargar archivos.
```yaml
# Estructura base:
title: PowerShell Download Cradle
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ???  # Complete aquí
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
```
**Validación**: Guarde en `rules/ps_download_cradle.yml` y ejecute:
```bash
sigma check rules/ps_download_cradle.yml
trigger validate ps_download_cradle.yml
```

### Ejercicio C2: Detectar Creación de Usuarios Locales
Escriba una regla que detecte `net user /add` o `net localgroup administrators /add`.
- MITRE: T1136.001
- Nivel: high

### Ejercicio C3: Detectar Disable Firewall
Escriba una regla que detecte `netsh advfirewall set allprofiles state off`.
- MITRE: T1562.004
- Nivel: high

### Ejercicio C4: Detectar Enumeración de Dominio
Escriba una regla que detecte herramientas como `nltest`, `dsquery`, `adfind`.
- MITRE: T1482
- Nivel: medium

### Ejercicio C5: Detectar Acceso a SAM/SYSTEM Hives
Escriba una regla que detecte `reg save HKLM\SAM` o `reg save HKLM\SYSTEM`.
- MITRE: T1003.002
- Nivel: critical

### Ejercicio C6: Detectar Proxy Execution via Regsvr32
Escriba una regla que detecte `regsvr32 /s /n /u /i:http://...`.
- MITRE: T1218.010
- Nivel: high

### Ejercicio C7: Detectar Token Impersonation
Escriba una regla que detecte herramientas que usan `whoami /priv` seguido de
`SeImpersonatePrivilege` o `SeDebugPrivilege`.
- MITRE: T1134.001
- Nivel: high

---

## Parte D: Conversión y Despliegue (Avanzado)

### Ejercicio D1: Pipeline Sigma → Elasticsearch
```bash
# Convertir TODAS las reglas a queries de Elasticsearch
for rule in rules/*.yml; do
    echo "=== $(basename $rule) ==="
    sigma convert -t elasticsearch -p sysmon "$rule" 2>/dev/null
    echo ""
done
```

### Ejercicio D2: Pipeline Sigma → Splunk
```bash
# Convertir TODAS las reglas a SPL queries
for rule in rules/*.yml; do
    echo "=== $(basename $rule) ==="
    sigma convert -t splunk -p sysmon "$rule" 2>/dev/null
    echo ""
done
```

### Ejercicio D3: Crear un Reporte de Cobertura MITRE
```bash
# Extraer todos los tags ATT&CK de las reglas
grep -h "attack.t" rules/*.yml | sort | uniq -c | sort -rn
```

---

## Parte E: Desafío Final

### Ejercicio E1: Crear un Pack de Detección
Cree un pack de 5 reglas Sigma que cubra un ataque APT completo:
1. Initial Access (macro/phishing)
2. Execution (PowerShell/LOLBin)
3. Persistence (scheduled task/registry)
4. Lateral Movement (WMI/PsExec)
5. Exfiltration (certutil/bitsadmin)

**Requisitos**:
- Todas deben pasar `sigma check`
- Todas deben tener tags MITRE correctos
- Todas deben convertirse sin errores a Elasticsearch y Splunk
- Validar contra el dataset con `trigger validate`

```bash
# Verificar todo el pack
sigma check rules/
trigger all
trigger validate
```
