import os
import logging
from logging import FileHandler
from flask import Flask, request, has_request_context
from rich import print

class RequestFormatter(logging.Formatter):
    """
    Кастомный форматтер, который пытается подставить в запись лога
    IP-адрес, метод и URL из контекста Flask (request).
    """
    def format(self, record):
        # Значения по умолчанию на случай, если
        # лог пишется вне контекста запроса
        record.remote_addr = '-'
        record.method = '-'
        record.url = '-'
        
        if has_request_context():
            record.remote_addr = request.remote_addr or '-'
            record.method = request.method
            record.url = request.url
        
        return super().format(record)


class Logger:
    def __init__(self, app):
        # Здесь app — это ваш класс App, у которого есть поле flask: Flask
        self.app: Flask = app.flask
        
        if not os.path.exists("logs"):
            os.mkdir("logs")

        # Создаём FileHandler
        handler = FileHandler("logs/app.log")
        handler.setLevel(logging.INFO)
        
        # Указываем формат логов:
        # время - IP - метод - URL
        formatter = RequestFormatter(
            '%(asctime)s - %(remote_addr)s - %(method)s - %(url)s'
        )
        handler.setFormatter(formatter)

        # Привязываем хендлер к logger-у самого приложения Flask
        self.app.logger.setLevel(logging.INFO)
        self.app.logger.addHandler(handler)

        # Чтобы видеть логи запроса (GET / ...), нужно добавить хендлер в logger "werkzeug"
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.INFO)
        werkzeug_logger.addHandler(handler)

    @staticmethod
    def warning(msg):
        print(f"[yellow][!] {msg}[/yellow]")
    
    @staticmethod
    def success(msg):
        print(f"[green][+] {msg}[/green]")
    
    @staticmethod
    def fail(msg):
        print(f"[red][-] {msg}[/red]")
