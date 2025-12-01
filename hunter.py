#hunter.py

import time
import schedule
import json
import logging
import psutil
import os
from datetime import datetime


#CONFIGURACION

#cargamos las reglas desde rules.json
CONFIG_PATH = os.path.join("config","rules.json")

def load_rules():
    
    try:
        with open(CONFIG_PATH, 'r') as file:
            rules = json.load(file)
        return rules
    except Exception as e:
        print(f"Error loading rules: {e}")
        return {}

config = load_rules()

#LOGGING    

#configuro el sistema de logs
logging.basicConfig(
    filename='hunter_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

print("INCIDENT HUNTER INICIADO - Vigilando sistema Windows...")
logging.info("Incident Hunter iniciado.")

#FUNCIONES DE CAZA

def check_processes():
    """busca los procesos prohibidos en rules.json"""
    print("escaneando procesos")

    #lista negra del config
    blacklist = config.get("process_hunter", {}).get("blacklisted_names", [])
    suspicius_paths = config.get("process_hunter", {}).get("suspicious_paths", [])
    
    #iteramos sobre todos los procesos activos
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            p_name = proc.info['name']
            p_path = proc.info['exe']
            
            #1. chequeo de nombre
            if p_name in blacklist:
                alerta = f"ALERTA: proceso prohibido detectado: {p_name} (PID: {proc.info['pid']})"
                print(alerta)
                logging.warning(alerta)
            
            #2. chequeo de ruta sospechosa
            if p_path:
                for susp_path in suspicius_paths:
                    if susp_path.lower() in p_path.lower():
                        alerta = f"ALERTA: proceso en ruta sospechosa detectado: {p_name} (PID: {proc.info['pid']}, Ruta: {p_path})"
                        print(alerta)
                        logging.warning(alerta)
                        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def check_network():
    """Busca conexiones sospechosas (Reverse Shells o C2)"""
    print("📡 Escaneando conexiones de red...")
    
    # Puertos que consideramos "seguros" o estándar (Web, DNS, etc.)
    # En un entorno real, esta lista sería mucho más larga.
    safe_ports = [80, 443, 53, 445, 135, 139] 
    
    # Obtenemos conexiones activas (tipo INET = IPv4)
    for conn in psutil.net_connections(kind='inet'):
        
        # Solo nos interesan las conexiones ESTABLECIDAS (conectadas activamente)
        if conn.status == 'ESTABLISHED':
            
            # Verificamos el puerto remoto (a dónde se conecta mi PC)
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            
            # Si el puerto NO está en la lista segura... ¡SOSPECHOSO!
            if remote_port not in safe_ports:
                try:
                    process = psutil.Process(pid)
                    proc_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Unknown"

                alerta = (f"🚨 ALERTA DE RED: Conexión a puerto extraño {remote_port} "
                          f"desde {proc_name} (PID: {pid}) -> IP Destino: {remote_ip}")
                
                print(alerta)
                logging.warning(alerta)

#PROGRAMACION DE TAREAS

#se ejecuta el escaneo cada X cantidad de segundos
interval = config.get("process_hunter", {}).get("scan_interval_seconds", 60)

schedule.every(interval).seconds.do(check_processes)
# schedule.every(interval).seconds.do(check_network) # Descomentar cuando esté listo

# --- BUCLE PRINCIPAL ---
if __name__ == "__main__":
    # Ejecutar una vez al inicio para probar
    check_processes()
    
    while True:
        schedule.run_pending()
        time.sleep(1)
               
              
        



