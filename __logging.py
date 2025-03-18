import os
import re
import logging
from logging import FileHandler, StreamHandler
from flask import Flask, request
from rich import print

class RemoveAnsiAndRichMarkupFormatter(logging.Formatter):
    """
    Кастомный Formatter, который после стандартного форматирования
    убирает из итоговой строки ANSI-коды ([33m ...) и Rich-теги ([yellow], [/yellow], ...).
    """
    ANSI_PATTERN = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    RICH_TAGS_PATTERN = re.compile(r'\[/?[^\]]+\]')

    def format(self, record):
        # Сформировать базовую строку (уже с подстановкой %s, %d, etc.)
        s = super().format(record)
        # Удалить ANSI escape-последовательности
        s = self.ANSI_PATTERN.sub('', s)
        # Удалить теги вида [yellow] или [/yellow]
        s = self.RICH_TAGS_PATTERN.sub('', s)
        return s

class Logger:
    def __init__(self, app):
        # Здесь app — это ваш класс App, у которого есть поле flask: Flask
        self.app = app.flask
        
        # Создадим папку logs, если её нет
        if not os.path.exists("logs"):
            os.mkdir("logs")

        # --- Хендлер, пишущий в файл ---
        file_handler = FileHandler("logs/app.log")
        file_handler.setLevel(logging.INFO)

        # --- Хендлер, пишущий в консоль ---
        console_handler = StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Шаблон лога
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        # Форматтер для файла — с «очисткой» ANSI и Rich
        file_formatter = RemoveAnsiAndRichMarkupFormatter(log_format)
        # Форматтер для консоли — обычный, (или хотите тот же, но тогда исчезнут цвета в консоли)
        console_formatter = logging.Formatter(log_format)

        file_handler.setFormatter(file_formatter)
        console_handler.setFormatter(console_formatter)

        # Логгер приложения Flask
        self.app.logger.setLevel(logging.INFO)
        self.app.logger.addHandler(file_handler)
        self.app.logger.addHandler(console_handler)

        # Логгер Werkzeug (для GET /… 200)
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.INFO)
        # Чтобы не плодить дубли в консоли, можете убрать этот хендлер,
        # но если нужно видеть запросы и там, и там — оставьте
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)

        # Регистрируем before_request, чтобы логировать IP и метод
        self.register_hooks()

    def register_hooks(self):
        @self.app.before_request
        def log_ip():
            ip = request.remote_addr or 'Unknown IP'
            method = request.method
