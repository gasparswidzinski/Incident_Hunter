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
        
               
              
        



