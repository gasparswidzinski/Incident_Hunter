#hunter.py

import time
import schedule
import json
import logging
import os
from datetime import datetime

from module.detection import check_processes, check_network
from module.alerts import send_email_alert


# --- CONFIGURACIÓN ---
CONFIG_PATH = os.path.join("config", "rules.json")

def load_rules():
    try:
        with open(CONFIG_PATH, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"❌ Error fatal cargando reglas: {e}")
        return {}

config = load_rules()

# --- LOGGING ---
# Solo lo configuramos UNA vez aquí
logging.basicConfig(
    filename='hunter_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

print("INCIDENT HUNTER INICIADO - Vigilando sistema Windows...")
logging.info("Incident Hunter iniciado.")

# --- PROGRAMACIÓN DE TAREAS ---
# Leemos el intervalo del JSON
interval = config.get("system_monitor", {}).get("check_interval_seconds", 60)

# Usamos schedule pasando 'config' como argumento a las funciones
schedule.every(interval).seconds.do(check_processes, config)
schedule.every(interval).seconds.do(check_network, config)

# --- BUCLE PRINCIPAL ---
if __name__ == "__main__":
    # Ejecución inicial de prueba
    check_processes(config)
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nIncident Hunter detenido por el usuario.")
        logging.info("Incident Hunter detenido.")
        



