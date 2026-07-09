#!/usr/bin/env python3
"""
hook_analyzer.py - Analiza API hooks instalados por Zeus
Curso MAR404 - Clase 6
"""
import json, sys
DATA_DIR = "/data"

def main():
    with open(f"{DATA_DIR}/hooks.json") as f:
        hooks = json.load(f)
    with open(f"{DATA_DIR}/processes.json") as f:
        processes = json.load(f)
    
    pid_filter = None
    if "--pid" in sys.argv:
        pid_filter = int(sys.argv[sys.argv.index("--pid") + 1])
    
    print("=" * 70)
    print("  HOOK ANALYZER — Detección de API Hooks (Zeus/Zbot)")
    print("=" * 70)
    
    hook_list = hooks["hooks"]
    if pid_filter:
        hook_list = [h for h in hook_list if h["pid"] == pid_filter]
    
    if not hook_list:
        print(f"\n  No se encontraron hooks para PID {pid_filter}")
        return
    
    print(f"\n  Total hooks detectados: {len(hook_list)}")
    print(f"  Procesos afectados: {', '.join(set(h['process'] for h in hook_list))}")
    
    for i, hook in enumerate(hook_list, 1):
        print(f"\n  {'─'*60}")
        print(f"  Hook #{i}")
        print(f"  {'─'*60}")
        print(f"  Proceso:     {hook['process']} (PID {hook['pid']})")
        print(f"  Módulo:      {hook['module']}")
        print(f"  Función:     {hook['function']}")
        print(f"  Tipo:        {hook['hook_type']}")
        print(f"  Dirección:   {hook['hook_address']}")
        print(f"  Destino:     {hook['destination']}")
        print(f"  Original:    {hook['original_bytes']}")
        print(f"  Hookeado:    {hook['hooked_bytes']}")
        print(f"  Propósito:   {hook['purpose']}")
        print(f"  MITRE:       {hook['mitre']}")
    
    # Explicación educativa
    print(f"\n\n{'='*70}")
    print("  EXPLICACIÓN: ¿Cómo funciona un Inline Hook?")
    print(f"{'='*70}")
    print("""
  1. Zeus localiza la función target (ej: HttpSendRequestW) en memoria
  2. Guarda los primeros bytes originales (prólogo de la función)
  3. Sobreescribe con un JMP (e9 xx xx xx xx) a su código inyectado
  4. El código inyectado:
     a) Ejecuta la lógica maliciosa (captura credenciales)
     b) Restaura bytes originales temporalmente
     c) Llama a la función original (para que todo funcione normal)
     d) Vuelve a instalar el hook
  5. El usuario no nota nada — sus credenciales son exfiltradas silenciosamente
  
  Detección:
  • Comparar bytes en memoria vs bytes en disco del módulo
  • Verificar que los primeros bytes de funciones críticas no son JMP
  • Buscar regiones RWX cerca de módulos del sistema
    """)

if __name__ == "__main__":
    main()
