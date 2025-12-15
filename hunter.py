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
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

print("INCIDENT HUNTER INICIADO - Vigilando sistema Windows...")
logging.info("Incident Hunter iniciado.")



# --- LOGGING ---
logging.basicConfig(
    filename='hunter_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8' 
)

def check_network():
    """Busca conexiones sospechosas"""
    print(" Escaneando conexiones de red...")
    
    # Puertos estándar
    safe_ports = [80, 443, 53, 445, 135, 139]
    
    # Lista blanca de programas (Nombres exactos de tus logs)
    whitelist_apps = [
        "steam.exe", "steamwebhelper.exe", "discord.exe", 
         "chrome.exe", "nvidia web helper.exe",
        "nvcontainer.exe", "nvidia share.exe", "lghub_agent.exe",
        "svchost.exe" 
    ]

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            
            # FILTRO 1: Ignorar Localhost (La PC hablando consigo misma)
            if remote_ip == "127.0.0.1":
                continue 

            # Intentamos obtener el nombre del proceso
            try:
                process = psutil.Process(pid)
                proc_name = process.name().lower() # Convertimos a minúsculas para comparar
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue # Si no podemos leerlo, pasamos (o podríamos alertar)

            # FILTRO 2: Ignorar Apps de la Lista Blanca
            if proc_name in [app.lower() for app in whitelist_apps]:
                continue

            # SI PASA LOS FILTROS Y EL PUERTO ES RARO -> ALERTA
            if remote_port not in safe_ports:
                alerta = (f" ALERTA REAL: Conexión extraña detectada en puerto {remote_port} "
                          f"desde {proc_name} (PID: {pid}) -> IP Destino: {remote_ip}")
                
                print(alerta)
                logging.warning(alerta)

#PROGRAMACION DE TAREAS

#se ejecuta el escaneo cada X cantidad de segundos
interval = config.get("process_hunter", {}).get("scan_interval_seconds", 60)

schedule.every(interval).seconds.do(check_processes)
schedule.every(interval).seconds.do(check_network)

# --- BUCLE PRINCIPAL ---
if __name__ == "__main__":
    # Ejecutar una vez al inicio para probar
    check_processes()
    
    while True:
        schedule.run_pending()
        time.sleep(1)
               
              
        



