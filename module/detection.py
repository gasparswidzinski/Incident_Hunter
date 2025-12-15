#detection.py

import psutil
import logging

def check_processes(config):
    """Busca los procesos prohibidos definidos en la configuración"""
    print(" Escaneando procesos...")

    # Extraemos las reglas del diccionario config que recibimos
    blacklist = config.get("process_hunter", {}).get("blacklisted_names", [])
    suspicious_paths = config.get("process_hunter", {}).get("suspicious_paths", [])
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            p_name = proc.info['name']
            p_path = proc.info['exe']
            
            # 1. Chequeo de nombre
            if p_name in blacklist:
                alerta = f" ALERTA: Proceso prohibido detectado: {p_name} (PID: {proc.info['pid']})"
                print(alerta)
                logging.warning(alerta)
            
            # 2. Chequeo de ruta sospechosa
            if p_path:
                for susp_path in suspicious_paths:
                    if susp_path.lower() in p_path.lower():
                        alerta = f"⚠️ ALERTA: Ejecución en ruta sospechosa: {p_name} (Ruta: {p_path})"
                        print(alerta)
                        logging.warning(alerta)
                        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def check_network(config):
    """Busca conexiones sospechosas basándose en la configuración"""
    print(" Escaneando conexiones de red...")
    
    net_config = config.get("network_hunter", {})
    safe_ports = net_config.get("safe_ports", [])
    whitelist_apps = net_config.get("whitelist_apps", [])
    # Convertimos la whitelist a minúsculas para comparar fácil
    whitelist_apps = [app.lower() for app in whitelist_apps]

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            
            # Ignorar Localhost
            if remote_ip == "127.0.0.1":
                continue 

            try:
                process = psutil.Process(pid)
                proc_name = process.name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue 

            # Ignorar Apps de la Lista Blanca
            if proc_name in whitelist_apps:
                continue

            # Alerta de puerto extraño
            if remote_port not in safe_ports:
                alerta = (f" ALERTA REAL: Conexión extraña en puerto {remote_port} "
                          f"desde {proc_name} (PID: {pid}) -> IP Destino: {remote_ip}")
                print(alerta)
                logging.warning(alerta)