#alerts.py

import smtplib
import os
import logging
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

def send_email_alert(subject, body):
    """
    Envía una alerta por correo electrónico usando las credenciales del .env
    """
    #recuperamos las credenciales
    sender = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_PASSWORD")
    receiver = os.getenv("EMAIL_RECEIVER")
    
    if not sender or not password or not receiver:
        logging.error("credenciales erroneas en el .env, no se puede enviar el correo")
        return
    
    #creamos el mensaje
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = f"ALERT: {subject}"
    msg['From'] = sender
    msg['To'] = receiver
    
    try:
        # Conexión con el servidor de Gmail (smtp.gmail.com)
        # Puerto 587 es el estándar para envío seguro (TLS)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Iniciamos la conexión segura
        
        #nos logueamos y enviamos el mensaje
        server.loggin(sender,password)
        server.send_message(msg)
        server.quit()
        
        print("Correo de alerta enviado con éxito.")
        logging.info(f"Correo enviado: {subject }")
        
    except Exception as e:
        print(f"Error enviando correo: {e}")
        logging.error(f"Error enviando correo: {e}")
        
        