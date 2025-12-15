#detection.py

import psutil
import logging


#FUNCIONES DE CAZA
def check_processes(config):
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
    

def check_network(config):
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
