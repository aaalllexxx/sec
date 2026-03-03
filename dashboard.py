from AEngineApps.service import Service
from AEngineApps.screen import Screen
from AEngineApps.api import API
import os
from flask import session, redirect, url_for, render_template

try:
    from sec.os_protect import get_os_protection_module
    from sec.net_analyzer import get_network_analyzer
    from sec.sys_protect import AdvancedSystemProtection
except ImportError:
    from AEngineApps.os_protect import get_os_protection_module
    from AEngineApps.net_analyzer import get_network_analyzer
    from AEngineApps.sys_protect import AdvancedSystemProtection

# Загрузка конфига
try:
    import AEngineApps.sec_config as sec_config
except ImportError:
    # Fallback на дефолты если конфиг не создан
    class sec_config:
        ADMIN_LOGIN = "admin"
        ADMIN_PASS = "admin"

class SecDashboardService(Service):
    """
    Микросервис Дашборда Безопасности.
    Подключается к `App`, предоставляет UI для мониторинга логов и статуса ОС.
    """
    def __init__(self, prefix: str = "/sec-admin", admin_login: str = None, admin_pass: str = None):
        super().__init__("sec_dashboard", prefix=prefix)
        # Приоритет: аргументы конструктора -> sec_config -> дефолт
        self.admin_login = admin_login or getattr(sec_config, "ADMIN_LOGIN", "admin")
        self.admin_pass = admin_pass or getattr(sec_config, "ADMIN_PASS", "admin")
        self._setup_routes()

    def _setup_routes(self):
        # Передаем конфигурацию в классы экранов
        class LoginScreen(API):
            service = self
            methods = ["GET", "POST"]
            
            def get(self):
                if session.get("sec_admin_logged_in"):
                    return redirect(f"{self.service.prefix}/dashboard")
                return render_template("sec/login.html", error=None)
                
            def post(self):
                login = self.request.form.get("login")
                password = self.request.form.get("password")
                
                if login == self.service.admin_login and password == self.service.admin_pass:
                    session["sec_admin_logged_in"] = True
                    return redirect(f"{self.service.prefix}/dashboard")
                return render_template("sec/login.html", error="Неверный логин или пароль")

        class DashboardScreen(API):
            service = self
            methods = ["GET"]
            
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return redirect(f"{self.service.prefix}/login")
                return render_template("sec/dashboard.html")

        class LogoutAPI(API):
            service = self
            methods = ["GET"]
            
            def get(self):
                session.pop("sec_admin_logged_in", None)
                return redirect(f"{self.service.prefix}/login")

        class ScanAPI(API):
            """API для выполнения сканирования (возвращает JSON)"""
            service = self
            methods = ["GET"]
            
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                    
                os_health = get_os_protection_module().run_health_check()
                net_health = get_network_analyzer().run_analysis()
                return {
                    "os": os_health,
                    "network": net_health
                }
                
        class LogReaderAPI(API):
            """API для чтения логов инцидентов (sec_logs.txt)"""
            service = self
            methods = ["GET"]
            
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                
                logs = []
                log_file = "sec_logs.txt"
                if os.path.exists(log_file):
                    try:
                        with open(log_file, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                            # Возвращаем последние 50 записей с конца
                            for line in reversed(lines[-50:]):
                                if not line.strip(): continue
                                parts = line.split("] ", 1)
                                if len(parts) == 2:
                                    ts, rest = parts
                                    level_msg = rest.split(": ", 1)
                                    if len(level_msg) == 2:
                                        level, msg = level_msg
                                        logs.append({
                                            "timestamp": ts.replace("[", ""),
                                            "level": level,
                                            "message": msg.strip()
                                        })
                    except Exception as e:
                        return {"error": str(e)}, 500
                        
                return {"logs": logs}

        class SysProtectScanAPI(API):
            """Полное сканирование системы (processes, users, config)"""
            service = self
            methods = ["GET"]
            
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return {"error": "Unauthorized"}, 401
                scanner = AdvancedSystemProtection(scan_interval=0, auto_start=False)
                return scanner.scan()

        self.add_screen("/login", LoginScreen)
        self.add_screen("/dashboard", DashboardScreen)
        self.add_screen("/logout", LogoutAPI)
        self.add_screen("/api/scan", ScanAPI)
        self.add_screen("/api/logs", LogReaderAPI)
        self.add_screen("/api/sys_scan", SysProtectScanAPI)
        
        # Редирект с корня сервиса на дашборд
        @self.blueprint.route("/")
        def index_redirect():
            return redirect(f"{self.prefix}/dashboard")
