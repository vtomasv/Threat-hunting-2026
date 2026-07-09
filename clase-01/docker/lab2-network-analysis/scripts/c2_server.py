#!/usr/bin/env python3
"""
c2_server.py
============
Servidor HTTP que simula un C2 básico para demostración en vivo.
Responde a beacons con comandos simples y registra las conexiones.

NOTA: Este servidor es SOLO para fines educativos en un entorno controlado.

Curso MAR404 - Cacería de Amenazas - Clase 1
Universidad Mayor 2026
"""

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - C2-SIM - %(message)s'
)

# Registro de beacons recibidos
beacon_log = []


class C2Handler(BaseHTTPRequestHandler):
    """Handler para simular respuestas de un C2 server."""
    
    def do_GET(self):
        """Responde a beacons de los implantes."""
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        # Registrar beacon
        beacon_entry = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "path": self.path
        }
        beacon_log.append(beacon_entry)
        
        logging.info(f"BEACON from {client_ip} | UA: {user_agent} | Path: {self.path}")
        
        if self.path == "/api/v1/check":
            # Respuesta estándar de beacon (sleep/no-op)
            response = json.dumps({
                "status": "ok",
                "cmd": "sleep",
                "interval": 60
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "nginx/1.24.0")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode())
            
        elif self.path == "/api/v1/tasks":
            # Simular entrega de tarea (para demo avanzada)
            response = json.dumps({
                "status": "ok",
                "tasks": [
                    {"id": 1, "type": "whoami", "args": ""}
                ]
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "nginx/1.24.0")
            self.end_headers()
            self.wfile.write(response.encode())
            
        elif self.path == "/stats":
            # Endpoint para que el profesor vea las conexiones
            response = json.dumps({
                "total_beacons": len(beacon_log),
                "recent": beacon_log[-10:] if beacon_log else []
            }, indent=2)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(response.encode())
            
        else:
            # 404 para cualquier otra ruta
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "nginx/1.24.0")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
    
    def do_POST(self):
        """Recibe datos exfiltrados (simulación)."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        logging.info(f"DATA EXFIL from {self.client_address[0]} | Size: {content_length} bytes")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "received"}).encode())
    
    def log_message(self, format, *args):
        """Silenciar logs HTTP estándar (usamos nuestro propio logging)."""
        pass


def main():
    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, C2Handler)
    
    print("=" * 50)
    print("  C2 SIMULATOR - Solo para fines educativos")
    print("  MAR404 - Cacería de Amenazas")
    print("=" * 50)
    print(f"  Escuchando en: http://0.0.0.0:80")
    print(f"  Endpoint beacon: /api/v1/check")
    print(f"  Endpoint stats:  /stats")
    print("=" * 50)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido")
        httpd.server_close()


if __name__ == "__main__":
    main()
