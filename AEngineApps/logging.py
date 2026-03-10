import os
import re
import logging
from logging import FileHandler, StreamHandler
from flask import Flask, request, Response
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
        self.app.logger.propagate = False
        self.app.logger.handlers.clear()

        # Создадим папку logs, если её нет
        if not os.path.exists(app.project_root + "logs"):
            os.mkdir(app.project_root + "logs")
            

        # --- Хендлер, пишущий в файл ---
        file_handler = FileHandler(app.project_root + "logs/app.log")
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
        # Удалим добавление хендлеров в werkzeug:
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.WARNING)  # вместо INFO, чтобы он молчал

        # Чтобы не плодить дубли в консоли, можете убрать этот хендлер,
        # но если нужно видеть запросы и там, и там — оставьте
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)

        # Регистрируем before_request, чтобы логировать IP и метод
        self.register_hooks()

    def register_hooks(self):
        @self.app.after_request
        def log_ip(response: Response):
            ip = request.remote_addr or 'Unknown IP'
            method = request.method
            user_agent = request.headers.get('User-Agent', 'Unknown User-Agent')
            path = request.full_path
            self.app.logger.info(f"{ip} {method} {path} - {user_agent} - {response.status_code}")
            return response
