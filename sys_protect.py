"""
sec.__sys_protect — Продвинутая защита системы.
Сканирует процессы, конфигурации приложения и действия пользователей ОС.
Подключается одной строкой: AdvancedSystemProtection(app)
"""
import os
import platform
import logging
import time
import threading

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("sec.sys_protect")


# ─────────── База подозрительных паттернов ───────────
SUSPICIOUS_PROCESS_NAMES = [
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",        # Майнеры
    "nc", "ncat", "netcat", "socat",                               # Reverse shell утилиты
    "mimikatz", "lazagne", "procdump",                             # Кража учётных данных
    "hydra", "medusa", "john", "hashcat",                          # Брутфорс
    "sqlmap", "nikto", "nmap", "masscan",                          # Сканеры
    "cobaltstrike", "meterpreter", "powershell_empire",            # C2 фреймворки
]

SUSPICIOUS_DIRS_WINDOWS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\public\\", "\\programdata\\",
]

SUSPICIOUS_DIRS_LINUX = [
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/run/user/",
]

WEAK_SECRET_KEYS = [
    "secret", "default_secret", "changeme", "password",
    "12345", "admin", "key", "supersecretkey", "flask_secret",
]


# ─────────── Утилиты заголовков безопасности ───────────

def enable_cors(app, origins: str = "*", methods: str = "GET,POST,PUT,DELETE,OPTIONS",
                headers: str = "Content-Type,Authorization") -> None:
    """Включает CORS для API-режима."""
    # Получаем исходный инстанс Flask
    flask_app = app.flask if hasattr(app, 'flask') else app
    
    @flask_app.after_request
    def cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = origins
        response.headers["Access-Control-Allow-Methods"] = methods
        response.headers["Access-Control-Allow-Headers"] = headers
        return response

def enable_csp(app, policy: str = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;") -> None:
    """Включает Content Security Policy (CSP) и другие базовые заголовки защиты от XSS."""
    flask_app = app.flask if hasattr(app, 'flask') else app

    @flask_app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = policy
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


# Топ-120+ самых распространенных слабых паролей для аудита
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567890", "1234", "111111", 
    "123123", "1234567", "654321", "p@ssword", "admin", "admin123", "root", "guest", "user", "login",
    "letmein", "password123", "football", "dragon", "monkey", "shadow", "master", "superman", "batman",
    "iloveyou", "princess", "sunshine", "welcome", "abc123", "password1", "secret", "666666", "888888",
    "999999", "000000", "777777", "555555", "444444", "333333", "222222", "121212", "search", "google",
    "youtube", "facebook", "twitter", "instagram", "tiktok", "netflix", "disney", "marvel", "starwars",
    "minecraft", "roblox", "fortnite", "pokemon", "nintendo", "xbox", "playstation", "apple", "iphone",
    "samsung", "android", "microsoft", "windows", "linux", "ubuntu", "chrome", "firefox", "safari",
    "opera", "internet", "network", "server", "database", "system", "security", "hacker", "hacking",
    "cyber", "expert", "pro", "master", "elite", "god", "boss", "king", "queen", "prince", "lord",
    "knight", "warrior", "ninja", "samurai", "hero", "legend", "myth", "magic", "spirit", "ghost",
    "alien", "zombie", "vampire", "werewolf", "dragon", "phoenix", "tiger", "lion", "eagle", "wolf",
    "bear", "shark", "whale", "dolphin", "panda", "koala", "penguin", "monkey", "elephant", "giraffe"
]


class AdvancedSystemProtection:
    """
    Продвинутый модуль защиты системы.
    
    Подключение:
        from sec.sys_protect import AdvancedSystemProtection
        protection = AdvancedSystemProtection(app)
    
    Автоматически:
    - Сканирует процессы на подозрительные имена и пути запуска.
    - Проверяет конфигурацию приложения на небезопасные настройки.
    - Мониторит активных пользователей ОС.
    - Проверяет перегрузки CPU/RAM.
    
    Всё это делается в фоновом потоке с настраиваемым интервалом.
    Результаты доступны через .get_report() или .last_report.
    """

    def __init__(self, app=None, scan_interval: int = 30,
                 max_cpu: float = 90.0, max_ram: float = 90.0,
                 max_users: int = 5, auto_start: bool = True):
        """
        Args:
            app: Экземпляр AEngineApps App. Если передан — проверяет конфигурацию
                 и регистрирует before_request хук.
            scan_interval: Интервал фонового сканирования (сек). 0 = без фонового потока.
            max_cpu: Порог CPU (%) для предупреждения.
            max_ram: Порог RAM (%) для предупреждения.
            max_users: Порог количества терминальных сессий для предупреждения.
            auto_start: Запускать ли фоновый сканер автоматически.
        """
        self.app = app
        self.scan_interval = scan_interval
        self.max_cpu = max_cpu
        self.max_ram = max_ram
        self.max_users = max_users

        self.last_report = {}
        self._running = False
        self._thread = None
        self._callbacks = []

        if app is not None:
            self._check_app_config(app)
            app.before_request(self._request_hook)

        if auto_start and scan_interval > 0:
            self.start()

    # ─────────── Публичный API ───────────

    def start(self):
        """Запускает фоновый сканер в отдельном потоке."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._background_loop, daemon=True)
        self._thread.start()
        logger.info("[SysProtect] Фоновый сканер запущен (интервал %d сек)", self.scan_interval)

    def stop(self):
        """Останавливает фоновый сканер."""
        self._running = False

    def on_alert(self, callback):
        """Регистрирует колбэк при обнаружении угрозы. callback(alert_dict)."""
        self._callbacks.append(callback)
        return callback

    def scan(self) -> dict:
        """
        Выполняет полное сканирование системы.
        Возвращает отчёт-словарь со всеми результатами.
        """
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "platform": platform.system(),
            "alerts": [],
            "resources": self._check_resources(),
            "processes": self._scan_processes(),
            "users": self._check_users(),
            "accounts": self._check_user_accounts(),
            "stored_xss": self._check_stored_xss(),
            "config": self._check_app_config(self.app) if self.app else {"status": "skipped"},
        }

        # Собираем все алерты
        for section in ["resources", "processes", "users", "accounts", "stored_xss", "config"]:
            data = report[section]
            if isinstance(data, dict) and data.get("alerts"):
                report["alerts"].extend(data["alerts"])

        report["status"] = "danger" if report["alerts"] else "ok"

        self.last_report = report

        # Вызываем коллбэки если есть алерты
        if report["alerts"]:
            for cb in self._callbacks:
                try:
                    cb(report)
                except Exception as e:
                    logger.error("[SysProtect] Ошибка в коллбэке: %s", e)

        return report

    def get_report(self) -> dict:
        """Возвращает последний сгенерированный отчёт."""
        return self.last_report if self.last_report else self.scan()

    # ─────────── Внутренние методы ───────────

    def _background_loop(self):
        """Цикл фонового сканирования."""
        while self._running:
            try:
                self.scan()
            except Exception as e:
                logger.error("[SysProtect] Ошибка фонового сканирования: %s", e)
            time.sleep(self.scan_interval)

    def _request_hook(self):
        """Хук before_request — при каждом HTTP-запросе проверяем последний отчёт."""
        if self.last_report.get("status") == "danger":
            # Логируем критические алерты, но не блокируем запрос
            for alert in self.last_report.get("alerts", []):
                logger.warning("[SysProtect] Активное предупреждение: %s", alert)

    def _check_resources(self) -> dict:
        """Проверка CPU и RAM."""
        if not psutil:
            return {"status": "skipped", "reason": "psutil не установлен", "alerts": []}

        cpu = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent if platform.system() != "Windows" else psutil.disk_usage("C:\\").percent

        alerts = []
        if cpu > self.max_cpu:
            alerts.append(f"CPU перегрузка: {cpu:.1f}% (порог {self.max_cpu}%)")
        if ram > self.max_ram:
            alerts.append(f"RAM перегрузка: {ram:.1f}% (порог {self.max_ram}%)")
        if disk > 95:
            alerts.append(f"Диск почти заполнен: {disk:.1f}%")

        return {
            "status": "danger" if alerts else "ok",
            "cpu_percent": cpu,
            "ram_percent": ram,
            "disk_percent": disk,
            "alerts": alerts,
        }

    def _scan_processes(self) -> dict:
        """Сканирование запущенных процессов на подозрительные имена и пути."""
        if not psutil:
            return {"status": "skipped", "reason": "psutil не установлен", "alerts": []}

        suspicious = []
        alerts = []
        is_windows = platform.system() == "Windows"
        suspect_dirs = SUSPICIOUS_DIRS_WINDOWS if is_windows else SUSPICIOUS_DIRS_LINUX

        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                info = proc.info
                pname = (info.get("name") or "").lower()
                pexe = (info.get("exe") or "").lower()

                # Проверка имени процесса
                for bad_name in SUSPICIOUS_PROCESS_NAMES:
                    if bad_name in pname:
                        msg = f"Подозрительный процесс: '{info['name']}' (PID {info['pid']}, user: {info.get('username', '?')})"
                        suspicious.append(info)
                        alerts.append(msg)
                        break

                # Проверка пути запуска (из временных директорий)
                if pexe:
                    for bad_dir in suspect_dirs:
                        if bad_dir in pexe:
                            msg = f"Процесс из временной директории: '{info['name']}' -> {info['exe']} (PID {info['pid']})"
                            suspicious.append(info)
                            alerts.append(msg)
                            break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            "status": "danger" if alerts else "ok",
            "suspicious_count": len(suspicious),
            "details": suspicious[:20],  # Ограничиваем выдачу
            "alerts": alerts,
        }

    def _check_users(self) -> dict:
        """Проверка активных терминальных сессий ОС."""
        if not psutil:
            return {"status": "skipped", "reason": "psutil не установлен", "alerts": []}

        users = psutil.users()
        alerts = []

        if len(users) > self.max_users:
            alerts.append(f"Аномальное количество терминальных сессий: {len(users)} (порог {self.max_users})")

        # Проверяем дублирующихся пользователей с разных хостов
        user_hosts = {}
        for u in users:
            name = u.name
            host = u.host or "local"
            user_hosts.setdefault(name, set()).add(host)

        for name, hosts in user_hosts.items():
            if len(hosts) > 2:
                alerts.append(f"Пользователь '{name}' подключён из {len(hosts)} хостов: {', '.join(hosts)}")

        user_list = [{"name": u.name, "terminal": u.terminal or "-", "host": u.host or "local"} for u in users]

        return {
            "status": "warning" if alerts else "ok",
            "active_sessions": len(users),
            "users": user_list,
            "alerts": alerts,
        }

    def _check_app_config(self, app) -> dict:
        """Проверка конфигурации приложения на опасные настройки."""
        if app is None:
            return {"status": "skipped", "alerts": []}

        alerts = []
        warnings = []

        # Проверка debug режима
        debug = getattr(app, "debug", False)
        if debug:
            alerts.append("Приложение запущено в DEBUG режиме! Отключите debug в продакшене.")

        # Проверка secret_key
        secret = None
        if hasattr(app, "flask"):
            secret = app.flask.secret_key
        elif hasattr(app, "secret_key"):
            secret = app.secret_key

        if secret:
            if isinstance(secret, str) and secret.lower() in WEAK_SECRET_KEYS:
                alerts.append(f"Слабый secret_key: '{secret}'. Используйте длинный случайный ключ.")
            elif isinstance(secret, str) and len(secret) < 16:
                warnings.append(f"Короткий secret_key ({len(secret)} символов). Рекомендуется минимум 32.")

        # Проверка CORS
        if hasattr(app, "flask"):
            cors_origins = app.flask.config.get("CORS_ORIGINS", None)
            if cors_origins == "*":
                warnings.append("CORS разрешён для всех доменов ('*'). Это может быть небезопасно.")

        # Проверка привилегий
        is_admin = False
        try:
            if platform.system() == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                is_admin = os.geteuid() == 0
        except Exception:
            pass

        if is_admin:
            alerts.append("Приложение запущено с правами Administrator/root!")

        # Глубокий аудит Flask config (Session security)
        if hasattr(app, "flask"):
            f_conf = app.flask.config
            
            # HttpOnly
            if not f_conf.get("SESSION_COOKIE_HTTPONLY", True):
                warnings.append("Флаг SESSION_COOKIE_HTTPONLY отключен! Это увеличивает риск XSS-кражи сессий.")
            
            # Secure (только HTTPS)
            if not f_conf.get("SESSION_COOKIE_SECURE", False):
                warnings.append("Флаг SESSION_COOKIE_SECURE отключен! Сессии будут передаваться по HTTP в открытом виде.")
            
            # SameSite
            if f_conf.get("SESSION_COOKIE_SAMESITE") is None:
                warnings.append("Флаг SESSION_COOKIE_SAMESITE не установлен. Рекомендуется 'Lax' или 'Strict'.")
            
            # Permanent Session
            if not f_conf.get("SESSION_REFRESH_EACH_REQUEST", True):
                warnings.append("Агрессивное продление сессий отключено (SESSION_REFRESH_EACH_REQUEST=False).")

        all_issues = alerts + warnings
        return {
            "status": "danger" if alerts else ("warning" if warnings else "ok"),
            "alerts": all_issues,
            "debug_mode": debug,
            "is_admin": is_admin,
            "flask_security_score": 100 - (len(warnings) * 15) - (len(alerts) * 40)
        }

    def _check_user_accounts(self) -> dict:
        """Аудит учетных записей пользователей на предмет слабых паролей."""
        from AEngineApps.global_storage import GlobalStorage
        storage = GlobalStorage()
        db = storage.get("db")
        
        alerts = []
        weak_count = 0
        
        if db and hasattr(db, "dictionary"):
            users = db.dictionary.get("users", [])
            for user in users:
                pwd = str(user.get("password", "")).lower()
                if not pwd:
                    continue
                
                # Проверка по списку
                if pwd in COMMON_PASSWORDS:
                    alerts.append(f"Обнаружен пользователь со слабым паролем: '{user.get('username', 'Unknown')}'")
                    weak_count += 1
                elif len(pwd) < 6:
                    alerts.append(f"Слишком короткий пароль у пользователя: '{user.get('username', 'Unknown')}'")
                    weak_count += 1
        
        return {
            "status": "danger" if alerts else "ok",
            "weak_passwords_found": weak_count,
            "alerts": alerts
        }

    def _check_stored_xss(self) -> dict:
        """Сканирование GlobalStorage на наличие внедрённых XSS-скриптов."""
        from AEngineApps.global_storage import GlobalStorage
        import re
        
        storage = GlobalStorage()
        db = storage.get("db")
        
        alerts = []
        # Паттерны для поиска XSS (упрощенная версия из intrusions.py)
        xss_patterns = [
            r"<script.*?>", r"javascript:", r"onerror=", r"onload=", 
            r"onclick=", r"eval\(", r"alert\("
        ]
        regex = re.compile("|".join(xss_patterns), re.I)
        
        def scan_recursive(data, path=""):
            found = []
            if isinstance(data, dict):
                for k, v in data.items():
                    found.extend(scan_recursive(v, f"{path}.{k}" if path else k))
            elif isinstance(data, list):
                for i, v in enumerate(data):
                    found.extend(scan_recursive(v, f"{path}[{i}]"))
            elif isinstance(data, str):
                if regex.search(data):
                    found.append(f"Обнаружена подозрительная строка в поле '{path}': {data[:50]}")
            return found

        if db and hasattr(db, "dictionary"):
            alerts = scan_recursive(db.dictionary)
        
        return {
            "status": "danger" if alerts else "ok",
            "xss_payloads_found": len(alerts),
            "alerts": alerts
        }


__all__ = ["AdvancedSystemProtection"]


__all__ = ['AdvancedSystemProtection', 'enable_cors', 'enable_csp']
