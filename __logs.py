from rich import print
import os
from logging.handlers import RotatingFileHandler

class Logger:
    def __init__(self, app):
        self.app = app.flask
        if not os.path.exists("logs"):
            os.mkdir("logs")
        handler = RotatingFileHandler("logs/app.log")
        self.app.logger.addHandler(handler)

    def warning(msg):
        print(f"[yellow][!] {msg}[/yellow]")
    
    def success(msg):
        print(f"[green][+] {msg}[/green]")

    def fail(msg):
        print(f"[red][-] {msg}[/red]")

