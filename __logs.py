import os
import logging
from logging import FileHandler, StreamHandler
from flask import Flask
from rich import print

class Logger:
    def __init__(self, app):
        # Здесь app — это ваш класс App, у которого есть поле flask: Flask
        self.app: Flask = app.flask
        
        # Создадим папку logs, если её нет
        if not os.path.exists("logs"):
            os.mkdir("logs")

        # --- Хендлер, пишущий в файл ---
        file_handler = FileHandler("logs/app.log")
        file_handler.setLevel(logging.INFO)

        # --- Хендлер, пишущий в консоль ---
        console_handler = StreamHandler()
        console_handler.setLevel(logging.INFO)

        # (необязательно) Определим общий формат логов
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Настроим logger самого приложения
        self.app.logger.setLevel(logging.INFO)
        self.app.logger.addHandler(file_handler)
        self.app.logger.addHandler(console_handler)

        # Настроим logger веб-сервера (Werkzeug), чтобы видеть запросы (GET /... 200)
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.INFO)
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)

    @staticmethod
    def warning(msg):
        print(f"[yellow][!] {msg}[/yellow]")
    
    @staticmethod
    def success(msg):
        print(f"[green][+] {msg}[/green]")
    
    @staticmethod
    def fail(msg):
        print(f"[red][-] {msg}[/red]")
