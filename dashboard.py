from AEngineApps.service import Service
from AEngineApps.screen import Screen
from AEngineApps.api import API
import os
from flask import session, redirect, url_for, render_template_string
from sec.os_protect import get_os_protection_module
from sec.net_analyzer import get_network_analyzer

class SecDashboardService(Service):
    """
    Микросервис Дашборда Безопасности.
    Подключается к `App`, предоставляет UI для мониторинга логов и статуса ОС.
    """
    def __init__(self, prefix: str = "/sec-admin", admin_login: str = "admin", admin_pass: str = "admin"):
        super().__init__("sec_dashboard", prefix=prefix)
        self.admin_login = admin_login
        self.admin_pass = admin_pass
        self._setup_routes()

    def _setup_routes(self):
        # Передаем конфигурацию в классы экранов
        class LoginScreen(Screen):
            service = self
            methods = ["GET", "POST"]
            
            def get(self):
                if session.get("sec_admin_logged_in"):
                    return redirect(f"{self.service.prefix}/dashboard")
                return render_template_string(self.service._get_login_html(), error=None)
                
            def post(self):
                login = self.request.form.get("login")
                password = self.request.form.get("password")
                
                if login == self.service.admin_login and password == self.service.admin_pass:
                    session["sec_admin_logged_in"] = True
                    return redirect(f"{self.service.prefix}/dashboard")
                return render_template_string(self.service._get_login_html(), error="Неверный логин или пароль")

        class DashboardScreen(Screen):
            service = self
            methods = ["GET"]
            
            def get(self):
                if not session.get("sec_admin_logged_in"):
                    return redirect(f"{self.service.prefix}/login")
                return render_template_string(self.service._get_dashboard_html())

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

        self.add_screen("/login", LoginScreen)
        self.add_screen("/dashboard", DashboardScreen)
        self.add_screen("/logout", LogoutAPI)
        self.add_screen("/api/scan", ScanAPI)
        self.add_screen("/api/logs", LogReaderAPI)
        
        # Редирект с корня сервиса на дашборд
        @self.blueprint.route("/")
        def index_redirect():
            return redirect(f"{self.prefix}/dashboard")

    def _get_login_html(self):
        return """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>SecAdmin - Вход</title>
            <style>
                body { background-color: #0f172a; color: #f8fafc; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .login-box { background: #1e293b; padding: 2rem; border-radius: 12px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5); width: 100%; max-width: 400px; text-align: center; }
                .login-box h2 { margin-top: 0; color: #38bdf8; }
                input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #334155; border-radius: 6px; background: #0f172a; color: white; box-sizing: border-box;}
                input:focus { outline: none; border-color: #38bdf8; }
                button { width: 100%; padding: 0.75rem; background: #0284c7; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s;}
                button:hover { background: #0369a1; }
                .error { color: #f43f5e; margin-bottom: 1rem; font-size: 0.9rem; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>🛡️ Sec Admin Portal</h2>
                {% if error %}
                    <div class="error">{{ error }}</div>
                {% endif %}
                <form method="POST">
                    <input type="text" name="login" placeholder="Логин" required>
                    <input type="password" name="password" placeholder="Пароль" required>
                    <button type="submit">Войти</button>
                </form>
            </div>
        </body>
        </html>
        """

    def _get_dashboard_html(self):
        return """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>SecAdmin - Дашборд</title>
            <style>
                body { background-color: #0f172a; color: #f8fafc; font-family: 'Inter', sans-serif; margin: 0; padding: 0; }
                .navbar { background: #1e293b; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
                .navbar h1 { margin: 0; color: #38bdf8; font-size: 1.5rem; }
                .logout-btn { background: #f43f5e; color: white; padding: 0.5rem 1rem; text-decoration: none; border-radius: 6px; font-weight: bold; }
                .logout-btn:hover { background: #e11d48; }
                .container { padding: 2rem; max-width: 1200px; margin: auto; }
                .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
                .card { background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; }
                .card h3 { margin-top: 0; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; color: #94a3b8; }
                .status-ok { color: #10b981; font-weight: bold; }
                .status-warning { color: #f59e0b; font-weight: bold; }
                .status-danger { color: #ef4444; font-weight: bold; }
                .scan-btn { background: #0284c7; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 6px; cursor: pointer; font-size: 1rem; width: 100%; transition: background 0.2s;}
                .scan-btn:hover { background: #0369a1; }
                #scan-results pre { background: #0f172a; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.9rem; color: #a5b4fc;}
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #334155; }
                th { color: #94a3b8; }
            </style>
        </head>
        <body>
            <div class="navbar">
                <h1>🛡️ Sec Admin Portal</h1>
                <a href="{{ url_for('sec_dashboard.sec_dashboard_LogoutAPI') }}" class="logout-btn">Выйти</a>
            </div>
            <div class="container">
                <div class="grid">
                    <div class="card">
                        <h3>Системный Сканер (System Health)</h3>
                        <p>Нажмите для актуализации данных о CPU, ОЗУ, Привилегиях (OS Protection) и Сетевых соединениях (Network Analyzer).</p>
                        <button class="scan-btn" onclick="runScan()">Запустить сканирование</button>
                        <div id="scan-results" style="margin-top: 1rem; display: none;">
                            <pre id="scan-json"></pre>
                        </div>
                    </div>
                    
                    <div class="card" style="grid-column: span 1;">
                        <h3>Парсинг логов атак (IDS/IPS)</h3>
                        <p>Загрузка последних инцидентов из <code>sec_logs.txt</code></p>
                        <button class="scan-btn" onclick="loadLogs()" style="background: #4f46e5;">Обновить логи</button>
                    </div>
                </div>
                
                <div class="card" style="grid-column: span 2;">
                    <h3>Последние срабатывания защиты</h3>
                    <div style="overflow-x: auto;">
                        <table id="logs-table">
                            <thead>
                                <tr>
                                    <th>Дата Время</th>
                                    <th>Уровень</th>
                                    <th>Событие</th>
                                </tr>
                            </thead>
                            <tbody id="logs-body">
                                <tr><td colspan="3" style="text-align:center;">Нажмите "Обновить логи" для загрузки...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <script>
                // API endpoints
                const API_BASE = '{{ url_for("sec_dashboard.index_redirect") }}'.replace('/dashboard', '');
                
                async function runScan() {
                    const btn = document.querySelector('.scan-btn');
                    btn.innerText = "Сканирование...";
                    btn.disabled = true;
                    
                    try {
                        const res = await fetch(API_BASE + '/api/scan');
                        const data = await res.json();
                        document.getElementById('scan-results').style.display = 'block';
                        document.getElementById('scan-json').innerText = JSON.stringify(data, null, 2);
                    } catch (e) {
                        alert("Ошибка сканирования: " + e);
                    }
                    
                    btn.innerText = "Запустить сканирование";
                    btn.disabled = false;
                }

                async function loadLogs() {
                    try {
                        const res = await fetch(API_BASE + '/api/logs');
                        const data = await res.json();
                        const tbody = document.getElementById('logs-body');
                        tbody.innerHTML = '';
                        
                        if (data.logs.length === 0) {
                            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;">Логи чисты!</td></tr>';
                            return;
                        }
                        
                        data.logs.forEach(log => {
                            const tr = document.createElement('tr');
                            let color = log.level.includes("CRITICAL") ? "#ef4444" : (log.level.includes("WARNING") ? "#f59e0b" : "white");
                            tr.innerHTML = `
                                <td style="color: #94a3b8;">${log.timestamp}</td>
                                <td style="color: ${color}; font-weight: bold;">${log.level}</td>
                                <td style="font-family: monospace;">${log.message}</td>
                            `;
                            tbody.appendChild(tr);
                        });
                    } catch (e) {
                        alert("Ошибка загрузки логов: " + e);
                    }
                }
            </script>
        </body>
        </html>
        """
