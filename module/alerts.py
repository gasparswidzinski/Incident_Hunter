#alerts.py

import smtplib
import os
import logging
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()