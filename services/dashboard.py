from AEngineApps.service import Service
from AEngineApps.api import API
import os
import re
import json
import secrets
import time
from flask import session, redirect, url_for, render_template, request, abort

# Пытаемся импортировать защиту для вывода статусов
try:
    from sec.os_protect import get_os_protection_module
    from sec.net_analyzer import get_network_analyzer
    from sec.sys_protect import AdvancedSystemProtection
    from sec import auth
except ImportError:
    try:
        from AEngineApps.os_protect import get_os_protection_module
        from AEngineApps.net_analyzer import get_network_analyzer
        from AEngineApps.sys_protect import AdvancedSystemProtection
        try:
             import auth
        except ImportError:
             import AEngineApps.sec_auth as auth # Fallback if renamed during merge
    except ImportError:
        # Заглушки если модули еще не установлены
        get_os_protection_module = lambda: None
        get_network_analyzer = lambda: None
        AdvancedSystemProtection = None
        auth = None

# Загрузка конфига
sec_config = None
def load_sec_config():
    global sec_config
    try:
        import AEngineApps.sec_config as sec_config_mod
        import importlib
        importlib.reload(sec_config_mod) # Перезагружаем чтобы видеть изменения
        sec_config = sec_config_mod
    except ImportError:
        try:
            import sec_config as sec_config_mod
            import importlib
            importlib.reload(sec_config_mod)
            sec_config = sec_config_mod
        except ImportError:
            pass

load_sec_config()

if not sec_config:
    class sec_config:
        ADMIN_LOGIN = "admin"
        ADMIN_PASS = "admin"
        MODULES_STATUS = {}

class SecDashboardService(Service):
    """
    Микросервис Дашборда Безопасности.
    Подключается к `App`, предоставляет UI для мониторинга логов и управления защитой.
    """
    # Статическое хранилище попыток входа для Rate Limiting
    # { "ip": {"count": N, "blocked_until": TIMESTAMP} }
    _login_attempts = {}

    def __init__(self, prefix: str = "/sec-admin", admin_login: str = None, admin_pass: str = None):
        super().__init__("sec_dashboard", prefix=prefix)
        self.admin_login = admin_login or getattr(sec_config, "ADMIN_LOGIN", "admin")
        self.admin_pass = admin_pass or getattr(sec_config, "ADMIN_PASS", "admin")
        self._setup_routes()
        # Выводим уведомление о запуске дашборда
        from rich.panel import Panel
        print(Panel(
            f"🔐 [bold green]Security Dashboard Activated[/bold green]\n"
            f"Логин-панель: [white underline]http://[your-host]{self.prefix}/login[/white underline]\n"
            f"Администратор: [cyan]{self.admin_login}[/cyan]",
            title="[bold cyan]SEC Service[/bold cyan]",
            expand=False
        ))

    def _generate_csrf_token(self):
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    def _verify_csrf_token(self):
        # Проверяем токен из заголовка или из тела формы
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            abort(403, description="CSRF Token Missing or Invalid")

    def _setup_routes(self):
        service_instance = self

        class LoginScreen(API):
            methods = ["GET", "POST"]
            def get(self):
                if session.get("sec_admin_logged_in"):
                    return redirect(url_for("sec_dashboard.dashboard_page"))
                return render_template("sec/login.html", error=None, csrf_token=service_instance._generate_csrf_token())
            
            def post(self):
                # 1. CSRF Check
                service_instance._verify_csrf_token()

                # 2. Rate Limiting Check
                ip = request.remote_addr
                now = time.time()
                attempt_info = service_instance._login_attempts.get(ip, {"count": 0, "blocked_until": 0})
                
                if attempt_info["blocked_until"] > now:
                    wait_sec = int(attempt_info["blocked_until"] - now)
                    return render_template("sec/login.html", error=f"Слишком много попыток. Подождите {wait_sec} сек.", csrf_token=service_instance._generate_csrf_token())

                login = request.form.get("login")
                password = request.form.get("password")
                
                # Приоритет авторизации через хеш в sec_admin.json
                is_valid = False
                if auth:
                    is_valid = auth.verify_password(service_instance._app.project_root, password)
                
                # Известная проблема: при первом запуске может не быть хеша, проверяем по конфигу
                if not is_valid and login == service_instance.admin_login and password == getattr(sec_config, "ADMIN_PASS", None):
                    is_valid = True

                if is_valid:
                    session["sec_admin_logged_in"] = True
                    # Сбрасываем попытки при успешном входе
                    if ip in service_instance._login_attempts:
                        del service_instance._login_attempts[ip]
                    return redirect(url_for("sec_dashboard.dashboard_page"))
                
                # Неверный пароль -> инкремент попыток
                attempt_info["count"] += 1
                if attempt_info["count"] >= 5:
                    attempt_info["blocked_until"] = now + 300 # 5 минут бана
                    service_instance._login_attempts[ip] = attempt_info
                    return render_template("sec/login.html", error="Кабинет заблокирован на 5 минут из-за перебора.", csrf_token=service_instance._generate_csrf_token())
                
                service_instance._login_attempts[ip] = attempt_info
                return render_template("sec/login.html", error=f"Неверный логин или пароль (осталось попыток: {5 - attempt_info['count']})", csrf_token=service_instance._generate_csrf_token())

        class DashboardScreen(API):
            methods = ["GET"]
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return redirect(url_for("sec_dashboard.login_page"))
                return render_template("sec/dashboard.html", csrf_token=service_instance._generate_csrf_token())

        class LogoutAPI(API):
            methods = ["GET"]
            def get(self):
                session.pop("sec_admin_logged_in", None)
                return redirect(url_for("sec_dashboard.login_page"))

        class ModulesAPI(API):
            """API для получения статуса модулей"""
            methods = ["GET"]
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                load_sec_config()
                status = getattr(sec_config, "MODULES_STATUS", {})
                return {"modules": status}

        class ToggleModuleAPI(API):
            """API для включения/выключения модулей"""
            methods = ["POST"]
            def post(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                
                service_instance._verify_csrf_token()

                data = request.json
                module_name = data.get("module")
                enabled = data.get("enabled")
                
                if module_name is None or enabled is None:
                    return {"error": "Invalid data"}, 400
                
                # Обновляем sec_config.py
                self._update_module_status(module_name, enabled)
                return {"status": "ok", "module": module_name, "enabled": enabled}

            def _update_module_status(self, module, enabled):
                # Ищем путь к конфигу
                config_path = ""
                try:
                    import AEngineApps.sec_config as sc
                    config_path = sc.__file__
                except:
                    config_path = "AEngineApps/sec_config.py"
                
                if not os.path.exists(config_path):
                    return

                with open(config_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Парсим MODULES_STATUS и обновляем
                # Мы используем регулярку для поиска значения в словаре
                pattern = rf'"{module}":\s*(True|False)'
                replacement = f'"{module}": {enabled}'
                
                if re.search(pattern, content):
                    new_content = re.sub(pattern, replacement, content)
                else:
                    # Если ключа нет, попробуем добавить в словарь (упрощенно)
                    if "MODULES_STATUS = {" in content:
                        new_content = content.replace("MODULES_STATUS = {", f"MODULES_STATUS = {{\n    \"{module}\": {enabled},")
                    else:
                        new_content = content + f"\nMODULES_STATUS = {{\"{module}\": {enabled}}}\n"

                # Сохраняем (временно снимая Read-Only если есть)
                try:
                    import stat
                    mode = os.stat(config_path).st_mode
                    os.chmod(config_path, mode | stat.S_IWRITE)
                    with open(config_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    os.chmod(config_path, mode)
                except:
                    with open(config_path, "w", encoding="utf-8") as f:
                        f.write(new_content)

        class UpdateCredentialsAPI(API):
            """API для смены логина и пароля администратора"""
            methods = ["POST"]
            def post(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                
                service_instance._verify_csrf_token()

                data = request.json
                old_password = data.get("old_password")
                new_login = data.get("new_login")
                new_password = data.get("new_password")
                
                if not all([old_password, new_login, new_password]):
                    return {"error": "Все поля обязательны"}, 400
                
                # 1. Проверяем старый пароль
                if auth and not auth.verify_password(service_instance._app.project_root, old_password):
                    # Если хеша нет, проверяем по конфигу (для миграции)
                    if old_password != getattr(sec_config, "ADMIN_PASS", None):
                        return {"error": "Неверный текущий пароль"}, 403
                
                # 2. Обновляем данные
                if auth:
                    auth.update_admin_credentials(service_instance._app.project_root, new_login, new_password)
                    # Сразу разлогиниваем для безопасности
                    session.pop("sec_admin_logged_in", None)
                    return {"status": "ok", "message": "Данные успешно обновлены. Пожалуйста, войдите снова."}
                
                return {"error": "Auth module not found"}, 500

        class ScanAPI(API):
            methods = ["GET"]
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                
                res = {"os": {}, "network": {}}
                if get_os_protection_module():
                    res["os"] = get_os_protection_module().run_health_check()
                if get_network_analyzer():
                    res["network"] = get_network_analyzer().run_analysis()
                return res

        class LogReaderAPI(API):
            methods = ["GET"]
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                
                logs = []
                log_file = os.path.join(self._app.project_root, "logs", "app.log")
                if os.path.exists(log_file):
                    try:
                        with open(log_file, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                            for line in reversed(lines[-50:]):
                                logs.append({"message": line.strip()})
                    except: pass
                return {"logs": logs}

        self.add_screen("/login", LoginScreen, endpoint="login_page")
        self.add_screen("/dashboard", DashboardScreen, endpoint="dashboard_page")
        self.add_screen("/logout", LogoutAPI, endpoint="logout_api")
        self.add_screen("/api/modules", ModulesAPI)
        self.add_screen("/api/toggle", ToggleModuleAPI)
        self.add_screen("/api/settings/update", UpdateCredentialsAPI)
        self.add_screen("/api/scan", ScanAPI, endpoint="api_scan")
        self.add_screen("/api/logs", LogReaderAPI)
        
        @self.blueprint.route("/")
        def index_redirect():
            return redirect(url_for("sec_dashboard.dashboard_page"))

# Экземпляр для авто-обнаружения
dashboard_service = SecDashboardService()
