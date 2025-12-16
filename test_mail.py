#test_mail.py

from module.alerts import send_email_alert

print("✉️ Intentando enviar correo de prueba...")
send_email_alert("Prueba de Incident Hunter", "Si lees esto, el sistema de alertas funciona correctamente.")