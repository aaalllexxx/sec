"""
sec/__intrusions.py — IDS/IPS система для AEngineApps.
Проверяет GET, POST, JSON данные запросов.
"""

from flask import Flask, request, abort
from urllib.parse import unquote
from typing import Callable, Optional
from collections import defaultdict
import os
import re
import shutil
import time
from abc import ABC, abstractmethod


# ─── Утилиты ─────────────────────────────────────────────────

def _get_all_input_values() -> list[str]:
    """Извлекает ВСЕ пользовательские данные из запроса (GET, POST, JSON)."""
    values = []
    
    # GET параметры
    for val in request.args.values():
        values.append(val)
    
    # POST form data
    if request.form:
        for val in request.form.values():
            values.append(val)
    
    # JSON body
    if request.is_json:
        try:
            json_data = request.get_json(silent=True) or {}
            values.extend(_flatten_json(json_data))
        except Exception:
            pass
    
    return values


def _flatten_json(data, prefix: str = "") -> list[str]:
    """Рекурсивно извлекает все строковые значения из JSON."""
    values = []
    if isinstance(data, dict):
        for k, v in data.items():
            values.extend(_flatten_json(v, f"{prefix}.{k}"))
    elif isinstance(data, list):
        for item in data:
            values.extend(_flatten_json(item, prefix))
    elif isinstance(data, str):
        values.append(data)
    return values


def _get_request_full_data() -> str:
    """Извлекает АБСОЛЮТНО ВСЕ данные запроса для полнотекстового анализа.
    
    Включает:
    - Полный путь и параметры (Full Path)
    - Все заголовки (Headers)
    - Тело запроса (Raw Body)
    """
    parts = []
    
    # 1. Путь и Query String
    parts.append(f"PATH: {request.full_path}")
    
    # 2. Заголовки (Headers)
    header_str = "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
    parts.append(f"HEADERS:\n{header_str}")
    
    # 3. Тело (Body)
    if request.is_json:
        parts.append(f"BODY (JSON): {request.get_data(as_text=True)}")
    elif request.form:
        parts.append(f"BODY (FORM): {request.get_data(as_text=True)}")
    else:
        # Пытаемся взять сырые данные, если они есть
        try:
            raw = request.get_data(as_text=True)
            if raw:
                parts.append(f"BODY (RAW): {raw}")
        except:
            pass
            
    return "\n---\n".join(parts)


# ─── Абстрактный детектор ─────────────────────────────────────

class BaseDetector(ABC):
    """Базовый класс детектора атак."""
    
    def __init__(self, app: Flask):
        self.app = app

    @abstractmethod
    def run(self) -> None:
        pass

    def log(self, message: str) -> None:
        """Логирует критическое событие."""
        self.app.logger.critical(message)

    def trigger_response(self) -> None:
        """Вызывается при обнаружении атаки (переопределяется IDS/IPS)."""
        pass


# ─── Детекторы ─────────────────────────────────────────────────

class RCEDetector(BaseDetector):
    """Обнаружение Remote Code Execution."""
    dangerous = ["echo", "eval", "exec", "system", "popen", "subprocess"]

    def run(self) -> None:
        # Проверяем только параметры и тело для предотвращения логов от User-Agent и т.д.
        user_inputs = _get_all_input_values()
        user_inputs.append(request.full_path)
        
        for val in user_inputs:
            decoded = unquote(val).lower()
            # Проверка по списку опасных команд
            for el in decoded.split():
                if el in self.dangerous or shutil.which(el):
                    self.log(f"DETECTED RCE: {request.method} {request.path} | payload: {val[:50]}")
                    self.trigger_response()
                    return


class LFIDetector(BaseDetector):
    """Обнаружение Local/Remote File Inclusion."""
    
    patterns = re.compile(
        r"(?:\.\./|\.\.\\|%2e%2e|%252e%252e|/etc/|/proc/|c:\\|%00)",
        re.IGNORECASE
    )
    
    def run(self) -> None:
        # Проверяем только параметры и тело
        user_inputs = _get_all_input_values()
        user_inputs.append(request.full_path)
        
        for val in user_inputs:
            decoded = unquote(val)
            if self.patterns.search(decoded):
                self.log(f"DETECTED LFI/RFI: {request.method} {request.path} | payload: {val[:50]}")
                self.trigger_response()
                return
            
            # Дополнительная проверка на существование путей
            if os.path.exists(decoded) and len(val) > 3:
                # Исключаем базовые пути проекта и статику
                if not any(x in decoded.replace("\\", "/") for x in ["/static/", "/templates/"]):
                    self.log(f"DETECTED LFI (path exists): {request.method} {request.path} | path: {val[:50]}")
                    self.trigger_response()
                    return


class SQLiDetector(BaseDetector):
    """Обнаружение SQL Injection."""
    dangerous = {
        "@VARIABLE", "AND", "OR", "AS", "WHERE", "ORDER", 
        "RLIKE", "SLEEP", "SELECT", "UNION", "DROP",
        "INSERT", "UPDATE", "DELETE", "CONCAT", "BENCHMARK"
    }
    special = {"--", "/*", "*/", "#", ";"}

    def run(self) -> None:
        # 1. Проверка ключевых слов по всему потоку (включая заголовки)
        full_data = _get_request_full_data()
        upper = unquote(full_data).upper()
        
        words = re.split(r"[\W_]+", upper)
        words = [w for w in words if w]
        if any(w in self.dangerous for w in words):
            self.log(f"DETECTED SQLi (keyword): {request.method} {request.path} | keyword found in stream")
            self.trigger_response()
            return

        # 2. Проверка спецсимволов ТОЛЬКО в данных пользователя (параметры и тело)
        # Мы НЕ проверяем заголовки на спецсимволы, так как там часто бывают ';' и '#'
        user_inputs = _get_all_input_values()
        # Добавляем путь запроса в проверку
        user_inputs.append(request.full_path)
        
        for val in user_inputs:
            decoded_val = unquote(val).upper()
            if any(s in decoded_val for s in self.special):
                # Исключаем ложное срабатывание на простые ';' в параметрах, если это не похоже на инъекцию
                # Но для безопасности блокируем большинство спецсимволов в параметрах
                self.log(f"DETECTED SQLi (special char): {request.method} {request.path} | char in payload: {val[:50]}")
                self.trigger_response()
                return


class XSSDetector(BaseDetector):
    """Обнаружение Cross-Site Scripting."""
    # Разделяем на критические (сразу бан) и подозрительные (нужно комбо)
    critical_patterns = [
        "<script", "javascript:", "onerror=", "onload=", "onclick=", "eval(", "alert("
    ]
    suspicious_patterns = [
        "<", ">", "/*", "*/", " src=", " href=", "document.", "cookie"
    ]

    def run(self) -> None:
        user_inputs = _get_all_input_values()
        user_inputs.append(request.full_path)
        
        for val in user_inputs:
            decoded = unquote(val).lower()
            
            # 1. Проверка критических паттернов
            for p in self.critical_patterns:
                if p in decoded:
                    self.log(f"DETECTED XSS (critical): {request.method} {request.path} | pattern '{p}' in {val[:30]}")
                    self.trigger_response()
                    return
            
            # 2. Проверка комбинации подозрительных (3 и более)
            matches = [p for p in self.suspicious_patterns if p in decoded]
            if len(matches) >= 3:
                self.log(f"DETECTED XSS (pattern match): {request.method} {request.path} | patterns {matches} in {val[:30]}")
                self.trigger_response()
                return


class SignatureDetector(BaseDetector):
    """Сигнатурный анализ: поиск известных CVE и паттернов атак.
    
    Загружает сигнатуры из открытой базы signatures_db.json.
    Если файл не найден — использует встроенный набор.
    """
    
    # Встроенные сигнатуры (fallback)
    _builtin_signatures = {
        "Log4Shell (CVE-2021-44228)": re.compile(r"\$\{jndi:(ldap|rmi|ldaps|dns):", re.I),
        "Spring4Shell (CVE-2022-22965)": re.compile(r"class\.module\.classLoader\.(resources|URLs)", re.I),
        "Shellshock (CVE-2014-6271)": re.compile(r"\(\)\s*\{\s*[:;]\s*\}\s*;", re.I),
        "Struts2 RCE (S2-045)": re.compile(r"%\{\(#[^}]+\)\.?(getValue|exec|getRuntime)", re.I),
        "PHP Serialization Exploit": re.compile(r"O:\d+:\"[^\"]+\":\d+:\{", re.I),
        "Generic Web Shell": re.compile(r"(passthru|shell_exec|system|phpinfo|base64_decode)\s*\(", re.I),
    }
    
    signatures = {}
    _db_loaded = False

    def __init__(self, app: Flask):
        super().__init__(app)
        if not SignatureDetector._db_loaded:
            SignatureDetector._load_db()
    
    @classmethod
    def _load_db(cls):
        """Загружает сигнатуры из signatures_db.json рядом с этим файлом."""
        import json
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures_db.json")
        
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    db = json.load(f)
                
                loaded = 0
                for sig in db.get("signatures", []):
                    name = sig.get("name", "Unknown")
                    pattern = sig.get("pattern")
                    flags_str = sig.get("flags", "")
                    
                    if not pattern:
                        continue
                    
                    flags = 0
                    if "i" in flags_str:
                        flags |= re.IGNORECASE
                    if "s" in flags_str:
                        flags |= re.DOTALL
                    if "m" in flags_str:
                        flags |= re.MULTILINE
                    
                    try:
                        cls.signatures[name] = re.compile(pattern, flags)
                        loaded += 1
                    except re.error:
                        pass
                
                cls._db_loaded = True
                print(f"[IPS] Загружено {loaded} сигнатур из открытой базы ({os.path.basename(db_path)})")
                return
            except (json.JSONDecodeError, IOError) as e:
                print(f"[IPS] Ошибка загрузки базы сигнатур: {e}, используем встроенные")
        
        cls.signatures = dict(cls._builtin_signatures)
        cls._db_loaded = True
        print(f"[IPS] Используется встроенная база ({len(cls.signatures)} сигнатур)")
    
    @classmethod
    def load_signatures(cls, path: str):
        """Загрузить дополнительные сигнатуры из указанного JSON файла."""
        import json
        try:
            with open(path, "r", encoding="utf-8") as f:
                db = json.load(f)
            for sig in db.get("signatures", []):
                pattern = sig.get("pattern")
                if pattern:
                    flags = re.IGNORECASE if "i" in sig.get("flags", "") else 0
                    if "s" in sig.get("flags", ""):
                        flags |= re.DOTALL
                    cls.signatures[sig.get("name", "Custom")] = re.compile(pattern, flags)
        except Exception as e:
            print(f"[IPS] Ошибка загрузки доп. сигнатур: {e}")

    def run(self) -> None:
        full_data = _get_request_full_data()
        decoded = unquote(full_data)
        
        for name, pattern in self.signatures.items():
            if pattern.search(decoded):
                self.log(f"DETECTED SIGNATURE: {name} | {request.method} {request.path}")
                self.trigger_response()
                return


class RuleDetector(BaseDetector):
    """Анализ на основе правил (Rule-based Analysis)."""
    
    rules = [] # Список функций-правил или объектов

    def add_rule(self, condition_fn, action_msg="Rule Triggered"):
        self.rules.append((condition_fn, action_msg))

    def run(self) -> None:
        # Пример дефолтного правила: блокировка curl (если нужно)
        # if "curl" in request.headers.get("User-Agent", "").lower():
        #     self.log("BLOCK RULE: curl access denied")
        #     self.trigger_response()
        #     return

        for condition, msg in self.rules:
            try:
                if condition(request):
                    self.log(f"BLOCK RULE: {msg} | {request.method} {request.path}")
                    self.trigger_response()
                    return
            except Exception as e:
                pass


# ─── Rate Limiter ─────────────────────────────────────────────

class RateLimiter:
    """Ограничитель частоты запросов по IP.
    
    Пример:
        limiter = RateLimiter(app, max_requests=100, window=60)
        # Макс. 100 запросов в минуту с одного IP
    """
    
    def __init__(self, app, max_requests: int = 100, window: int = 60):
        self.flask_app: Flask = app.flask
        self.max_requests = max_requests
        self.window = window  # секунды
        self._requests: dict[str, list[float]] = defaultdict(list)
        self.flask_app.before_request(self._check_rate)
    
    def _check_rate(self):
        ip = request.remote_addr or "unknown"
        now = time.time()
        
        # Убираем устаревшие записи для текущего IP
        self._requests[ip] = [
            t for t in self._requests[ip] 
            if now - t < self.window
        ]
        
        if len(self._requests[ip]) >= self.max_requests:
            self.flask_app.logger.warning(f"RATE LIMIT: {ip} ({len(self._requests[ip])} req/{self.window}s)")
            abort(429)
        
        self._requests[ip].append(now)

        # Легковесная очистка словаря от старых IP (защита от утечек памяти)
        if len(self._requests) > 1000:
            for k in list(self._requests.keys()):
                self._requests[k] = [t for t in self._requests[k] if now - t < self.window]
                if not self._requests[k]:
                    del self._requests[k]


# ─── IDS ──────────────────────────────────────────────────────

class IDS:
    """Intrusion Detection System.
    
    Пример:
        from AEngineApps.app import App
        from AEngineApps.intrusions import IDS, XSSDetector, SQLiDetector
        
        app = App()
        ids = IDS(app)
        ids.add_detector(XSSDetector)
        ids.add_detector(SQLiDetector)
        
        @ids.on_trigger
        def on_attack():
            print("Атака обнаружена!")
    """
    
    def __init__(self, app):
        self.app: Flask = app.flask
        self.detectors: list[BaseDetector] = []
        self.detect_funcs: list[Callable] = []
        self.app.before_request(self.run_detectors)

    def add_detector(self, detector_cls: type) -> None:
        """Добавляет детектор."""
        self.detectors.append(detector_cls(self.app))

    def run_detectors(self) -> None:
        """Запускает все детекторы на текущем запросе."""
        for detector in self.detectors:
            detector.trigger_response = self._on_detection_triggered
            detector.run()

    def _on_detection_triggered(self) -> None:
        for func in self.detect_funcs:
            func()

    def on_trigger(self, func: Callable) -> Callable:
        """Регистрирует обработчик срабатывания (можно как декоратор)."""
        self.detect_funcs.append(func)
        return func


# ─── IPS ──────────────────────────────────────────────────────

class IPS(IDS):
    """Intrusion Prevention System — блокирует запрос при обнаружении атаки.
    
    Пример:
        ips = IPS(app)
        ips.add_detector(XSSDetector)
        ips.add_detector(RCEDetector)
        # Атаки автоматически блокируются (abort 400)
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.on_trigger(self.block_request)
        
        # Регистрация стандартных детекторов по умолчанию
        self.add_detector(SQLiDetector)
        self.add_detector(XSSDetector)
        self.add_detector(LFIDetector)
        self.add_detector(RCEDetector)
        self.add_detector(SignatureDetector)
        self.add_detector(RuleDetector)

    def block_request(self) -> None:
        self.app.logger.info(f"BLOCKED: {request.remote_addr} {request.method} {request.full_path}")
        abort(400)
__all__ = [
    "IDS", "IPS", "BaseDetector", 
    "SQLiDetector", "XSSDetector", "LFIDetector", "RCEDetector",
    "SignatureDetector", "RuleDetector", "RateLimiter"
]
