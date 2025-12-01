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




