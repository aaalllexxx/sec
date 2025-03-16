from rich import print
import os
from logging.handlers import RotatingFileHandler
import logging

class Logger:
    def __init__(self, app):
        self.app = app.flask
        if not os.path.exists("logs"):
            os.mkdir("logs")
        handler = RotatingFileHandler("logs/app.log")
        handler.setLevel(logging.INFO)
        # Формат логов: время, IP-адрес клиента, метод HTTP, URL
        formatter = logging.Formatter('%(asctime)s - %(remote_addr)s - %(method)s - %(url)s')
        handler.setFormatter(formatter)
        self.app.logger.addHandler(handler)

    def warning(msg):
        print(f"[yellow][!] {msg}[/yellow]")
    
    def success(msg):
        print(f"[green][+] {msg}[/green]")

    def fail(msg):
        print(f"[red][-] {msg}[/red]")

