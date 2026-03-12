import os
import re
import logging
from logging import FileHandler, StreamHandler
from flask import Flask, request, Response
from rich import print
from urllib.parse import unquote
import json
import datetime

class RemoveAnsiAndRichMarkupFormatter(logging.Formatter):
    """
    Кастомный Formatter, который после стандартного форматирования
    убирает из итоговой строки ANSI-коды ( [33m ...) и Rich-теги ([yellow], [/yellow], ...).
    """
    ANSI_PATTERN = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    RICH_TAGS_PATTERN = re.compile(r'\[/?[^\]]+\]')

    def format(self, record):
        s = super().format(record)
        s = self.ANSI_PATTERN.sub('', s)
        s = self.RICH_TAGS_PATTERN.sub('', s)
        return s

class Logger:
    def __init__(self, app):
        self.app = app.flask
        self.app.logger.propagate = False
        self.app.logger.handlers.clear()

        if not os.path.exists(app.project_root + "logs"):
            os.mkdir(app.project_root + "logs")

        file_handler = FileHandler(app.project_root + "logs/app.log")
        file_handler.setLevel(logging.INFO)

        console_handler = StreamHandler()
        console_handler.setLevel(logging.INFO)

        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        file_formatter = RemoveAnsiAndRichMarkupFormatter(log_format)
        console_formatter = logging.Formatter(log_format)

        file_handler.setFormatter(file_formatter)
        console_handler.setFormatter(console_formatter)

        self.app.logger.setLevel(logging.INFO)
        self.app.logger.addHandler(file_handler)
        self.app.logger.addHandler(console_handler)

        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.WARNING)
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)

        self.register_hooks()

    def register_hooks(self):
        @self.app.after_request
        def log_ip(response: Response):
            ip = request.remote_addr or 'Unknown IP'
            method = request.method
            ua = request.headers.get('User-Agent', 'Unknown UA')
            path = request.full_path
            self.app.logger.info(f"{ip} {method} {path} - {ua} - {response.status_code}")
            return response

def init(project_root):
    """Инициализация папки с логами."""
    logs_dir = os.path.join(project_root, "logs")
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
        print(f"[green][+] Директория {logs_dir} создана.[/green]")
    else:
        print(f"[*] Директория {logs_dir} уже существует.")

def template_to_regex(template):
    """
    Преобразует строку вида "${status} ${ip} {useragent} {skip} ${path}"
    в гибкое регулярное выражение, где важна только последовательность переменных.
    Любые мусорные разделители игнорируются (заменяются на .*?).
    """
    import re
    # Находим все переменные в виде {var} или ${var}
    variables = re.findall(r'\$?\{([a-z0-9_]+)\}', template.lower())
    
    regex_parts = []
    
    for var in variables:
        if var == 'ip':
            regex_parts.append(r"(?<!\d)(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)")
        elif var == 'status':
            regex_parts.append(r"(?<!\d)(?P<status>[1-5]\d{2})(?!\d)")
        elif var == 'method':
            regex_parts.append(r"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)")
        elif var == 'path':
            # Пути в логах обычно начинаются с '/'
            regex_parts.append(r"(?P<path>/(?:[^\s\"'\|<>]+)?)")
        elif var in ('ts', 'time', 'date'):
            regex_parts.append(r"(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)")
        else:
            # Для skip, useragent и любых других неописанных переменных - просто пропускаем
            pass
            
    if not regex_parts:
        # Если шаблон без известных переменных, вернем что-то безопасное
        return ".*?"
        
    # Соединяем паттерны через .*? (любой мусор между переменными)
    return ".*?".join(regex_parts)

def analyze(project_root, log_file="logs/app.log", custom_pattern=None):
    """
    Advanced Security Analytics Engine (v3.2)
    """
    
    if os.path.isabs(log_file):
        log_path = log_file
    else:
        log_path = os.path.join(project_root, log_file)
        
    report_path = os.path.join(project_root, "logs/security_report.md")
    
    if not os.path.exists(log_path):
        print(f"[red][!] Файл логов {log_path} не найден.[/red]")
        return

    print(f"\n[bold cyan]🚀 Запуск Advanced Security Analytics v3.2[/bold cyan]")
    print(f"[*] Анализ файла: [yellow]{log_path}[/yellow]")
    
    # --- Расширенная База Сигнатур (Категории на English) ---
    signatures_db = [
        {"cat": "SQL Injection", "stage": "Эксплуатация", "pattern": r"(union\s+select|select\s+.*\s+from|drop\s+table|--|' OR '1'='1|admin'--|order\s+by|information_schema|sysdatabases|pg_sleep|waitfor\s+delay)"},
        {"cat": "XSS", "stage": "Эксплуатация", "pattern": r"(<script|javascript:|onerror=|onload=|onclick=|alert\(|<\?php|confirm\(|prompt\(|<img\s+src=x)"},
        {"cat": "RCE/Shell", "stage": "Действия на объекте", "pattern": r"(eval\(|exec\(|system\(|python\s+-c|/bin/bash|/bin/sh|powershell|whoami|nc -lnvp|rm\s+-rf|cat\s+/etc|ls\s+-la|ping\s+-c|curl\s+|wget\s+|chmod\s+|chown\s+|nohup\s+|base64\s+-d)"},
        {"cat": "LFI/Traversal", "stage": "Эксплуатация", "pattern": r"(\.\./|/etc/passwd|/windows/win\.ini|%00|boot\.ini|/proc/self/environ|/var/log/|C:\\Windows\\)"},
        {"cat": "SSRF", "stage": "Эксплуатация", "pattern": r"(http://169\.254\.169\.254|http://localhost|http://127\.0\.0\.1|gopher://|dict://|php://filter)"},
        {"cat": "SSTI/Logic", "stage": "Эксплуатация", "pattern": r"(\{\{.*\}\}|\$\{.*\}|#\{.*\}|\[\[.*\]\])"},
        {"cat": "Information Disclosure", "stage": "Разведка", "pattern": r"(\.git/|\.env|\.htaccess|\.ssh/|wp-config\.php|config\.php\.bak|composer\.json)"},
        {"cat": "Scanners/Fuzzing", "stage": "Разведка", "pattern": r"(acunetix|nessus|sqlmap|nmap|nikto|dirbuster|gobuster|w3af|zgrab)"}
    ]
    
    if custom_pattern:
        if "{" in custom_pattern:
            try:
                pattern_str = template_to_regex(custom_pattern)
                log_regex = re.compile(pattern_str)
                print(f"[*] Шаблон конвертирован в Regex: [magenta]{pattern_str}[/magenta]")
            except Exception as e:
                print(f"[red][!] Ошибка в шаблоне: {e}[/red]")
                return
        else:
            try:
                log_regex = re.compile(custom_pattern)
                print(f"[*] Использование пользовательского Regex паттерна: [magenta]{custom_pattern}[/magenta]")
            except Exception as e:
                print(f"[red][!] Ошибка в регулярном выражении: {e}[/red]")
                return
    else:
        log_regex = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - \w+ - (?:BLOCKED: )?([\d.]+) ([A-Z]+) (/[^ ]*) - .* - (\d{3})")
    
    nodes_by_ip = {}
    
    with open(log_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            
            match = log_regex.search(line)
            if not match: continue
            
            group_dict = match.groupdict()
            if group_dict:
                ts_str = group_dict.get("ts", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                ip = group_dict.get("ip", "0.0.0.0")
                method = group_dict.get("method", "REQ")
                path = group_dict.get("path", "/")
                status = group_dict.get("status", "000")
            else:
                groups = match.groups()
                if len(groups) >= 5:
                    ts_str, ip, method, path, status = groups[:5]
                elif len(groups) >= 3:
                    ts_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ip, path, status = groups[0], groups[1], groups[2]
                    method = "REQ"
                else: continue

            try:
                ts = datetime.datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
            except: ts = datetime.datetime.now()
            
            if ip not in nodes_by_ip:
                nodes_by_ip[ip] = []
            
            nodes_by_ip[ip].append({
                "line": i, "ts": ts, "method": method, "path": path, "status": status,
                "is_blocked": "BLOCKED:" in line
            })

    # --- Подготовка для контекстного анализа ---
    # Собираем все запросы в один отсортированный список для поиска последствий
    all_reqs_sorted = sorted([r for ip_reqs in nodes_by_ip.values() for r in ip_reqs], key=lambda x: x['line'])

    threats = []
    for ip, reqs in nodes_by_ip.items():
        ip_score = 0
        ip_threats = set()
        attack_chain = []
        
        # 1. Поведенческий анализ...
        burst_detected = False
        window_size = 10
        if len(reqs) >= window_size:
            # Сортируем на всякий случай, если логи были не по порядку
            reqs_sorted = sorted(reqs, key=lambda x: x['ts'])
            for i in range(len(reqs_sorted) - window_size + 1):
                t1 = reqs_sorted[i]['ts']
                t2 = reqs_sorted[i + window_size - 1]['ts']
                if (t2 - t1).total_seconds() <= 2.0:  # 10 запросов за 2 секунды = пик 5+ rps
                    burst_detected = True
                    break
        
        if burst_detected:
            ip_score += 40
            ip_threats.add("High Frequency Burst (Bruteforce/Spam)")

        # 2. Анализ ошибок (Сканирование/Фазинг)
        error_count = sum(1 for r in reqs if str(r['status']).startswith('4') or str(r['status']).startswith('5'))
        if error_count > 50:
            ip_score += 50
            ip_threats.add("Aggressive Scanning")
        elif len(reqs) > 10 and (error_count / len(reqs)) > 0.3:
            ip_score += 20
            ip_threats.add("High Error Rate")

        # 3. Анализ сигнатур и Контекстный анализ последствий
        for r in reqs:
            r_threat = None
            r_stage = "Unknown"
            decoded_path = unquote(r['path'])
            
            for sig in signatures_db:
                if re.search(sig['pattern'], decoded_path, re.IGNORECASE):
                    r_threat = sig['cat']
                    r_stage = sig['stage']
                    break
            
            if r_threat:
                if r_threat not in ip_threats:
                    ip_score += 40
                    ip_threats.add(r_threat)
                else:
                    ip_score += 5

            # Определяем, подозрителен ли запрос
            is_suspicious = False
            if r_threat or r['is_blocked']: is_suspicious = True

            # --- КОМПЛЕКСНЫЙ АНАЛИЗ (KILL CHAIN & IMPACT) ---
            consequence = "Разведка"
            kill_chain_stage = "Разведка"
            
            if is_suspicious:
                # Определяем этап на основе сигнатуры или поведения
                if r_threat:
                    kill_chain_stage = r_stage
                elif r['is_blocked']:
                    kill_chain_stage = "Эксплуатация"
                
                # Повышаем этап, если это код 200 (Доставка/Эксплуатация)
                if int(r['status']) == 200 and kill_chain_stage == "Разведка":
                    kill_chain_stage = "Доставка/Подготовка"
                
                # Оцениваем воздействие
                impact_found = False
                payload_to_check = unquote(r['path']).lower()
                high_risk = any(x in payload_to_check for x in ['rm ', 'format', 'shutdown', 'mkfs', 'dd ', 'chmod', 'chown', 'wget', 'curl', 'nc '])
                
                start_line = r['line']
                crash_detected = False
                for next_r in all_reqs_sorted:
                    if next_r['line'] <= start_line: continue
                    if (next_r['ts'] - r['ts']).total_seconds() > 5: break
                    if int(next_r['status']) >= 500:
                        crash_detected = True
                        break
                
                if crash_detected:
                    consequence = "КРИТИЧЕСКИЙ: Дестабилизация сервера" if high_risk else "ПОДОЗРИТЕЛЬНО: Сбой после запроса"
                    kill_chain_stage = "Действия на объекте"
                    impact_found = True
                
                if not impact_found:
                    if int(r['status']) == 200 and r_threat:
                        consequence = f"УСПЕХ: {r_threat} выполнен"
                    elif r['is_blocked']:
                        consequence = "ОТРАЖЕНО: Заблокировано IPS"
                    elif int(r['status']) >= 400:
                        consequence = f"ПОПЫТКА: {r_threat or 'Атака'} отклонена"
                    else:
                        consequence = "Разведка (Reconnaissance)"

            if is_suspicious:
                r['consequence'] = consequence
                r['kc_stage'] = kill_chain_stage
                attack_chain.append(r)

        ip_score = min(ip_score, 100)
        if ip_score > 0:
            threats.append({
                "ip": ip, "score": ip_score, "reasons": list(ip_threats),
                "chain": attack_chain, "total_reqs": len(reqs)
            })

    threats.sort(key=lambda x: x['score'], reverse=True)
    report_path_html = os.path.join(project_root, "logs/security_report.html")
    report_path_csv = os.path.join(project_root, "logs/security_report.csv")
    
    # --- HTML Report Generation (Template-based) ---
    try:
        template_path = os.path.join(os.path.dirname(__file__), "report_template.html")
        if not os.path.exists(template_path):
            print(f"[red][!] Ошибка: Шаблон заглавия не найден по пути {template_path}[/red]")
            return

        with open(template_path, "r", encoding="utf-8") as tf:
            html_content = tf.read()

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Prepare Sidebar
        sidebar_html = ""
        for i, t in enumerate(threats):
            badge = "badge-red" if t['score'] >= 70 else "badge-yellow"
            sidebar_html += f"<div class='sidebar-item' id='sidebar-{t['ip']}' onclick=\"showIP('{t['ip']}', this)\">\n"
            sidebar_html += f"  <span class='ip-addr'>{t['ip']}</span>\n"
            sidebar_html += f"  <div style='display:flex; justify-content:space-between; align-items:center;'>\n"
            sidebar_html += f"    <span class='badge {badge}'>{t['score']}%</span>\n"
            sidebar_html += f"    <span class='ip-meta'>{t['total_reqs']} запр.</span>\n"
            sidebar_html += f"  </div>\n</div>\n"

        # Prepare Host Contents
        hosts_html = ""
        for t in threats:
            hosts_html += f"<div class='host-content' id='content-{t['ip']}' style='display:none;'>\n"
            hosts_html += f"  <h1>Расследование: {t['ip']}</h1>\n"
            hosts_html += f"  <div class='card'>\n"
            hosts_html += f"    <h3>Оценка рисков</h3>\n"
            hosts_html += f"    <p>Уровень риска: <span class='badge {'badge-red' if t['score']>=70 else 'badge-yellow'}' style='font-size:1.2em;'>{t['score']}%</span></p>\n"
            hosts_html += f"    <p>Выявленные паттерны: <code>{', '.join(t['reasons'])}</code></p>\n"
            hosts_html += f"  </div>\n"
            
            if t['chain']:
                hosts_html += "<div class='card'>\n"
                hosts_html += "<h3>Визуализация цепочки атаки <small style='font-size:12px; color:#64748b; font-weight:normal; margin-left:10px;'>(Нажмите на узел для перехода к событию)</small></h3>\n"
                hosts_html += f"<div class='mermaid' data-ip='{t['ip']}'>\n"
                hosts_html += "graph LR\n"
                hosts_html += f"  START((Начало)) --> R{t['chain'][0]['line']}\n"
                max_display = 40
                for idx in range(min(len(t['chain']), max_display)):
                    curr = t['chain'][idx]
                    p = curr['path'].replace('"', "'").replace('[', '(').replace(']', ')').replace('(', ' ').replace(')', ' ').replace('{', ' ').replace('}', ' ')
                    if len(p) > 50: p = p[:47] + "..."
                    label = f"\"{curr['method']} {p} ({curr['status']})\""
                    node_id = f"R{curr['line']}"
                    hosts_html += f"  {node_id}[{label}]\n"
                    if idx < len(t['chain']) - 1:
                        next_node = f"R{t['chain'][idx+1]['line']}"
                        if idx == max_display - 1:
                            hosts_html += f"  {node_id} --> TRUNCATED((...))\n"
                        else:
                            hosts_html += f"  {node_id} --> {next_node}\n"
                hosts_html += "</div>\n</div>\n"

            hosts_html += "<div class='card'>\n"
            hosts_html += "<h3>Таблица подозрительных событий и анализ Cyber Kill Chain</h3>\n"
            hosts_html += "<table>\n<tr><th>Стр.</th><th>Этап</th><th>Запрос</th><th>Статус</th><th>Последствие</th></tr>\n"
            for r in t['chain'][:30]:
                row_class = ""
                cons = r.get('consequence', 'Разведка')
                kc = r.get('kc_stage', 'Разведка')
                if "КРИТИЧЕСКИЙ" in cons: row_class = "class='row-critical'"
                elif "УСПЕХ" in cons: row_class = "class='row-warning'"
                
                kc_badge = "badge-gray"
                if "Эксплуатация" in kc: kc_badge = "badge-purple"
                elif "Доставка" in kc: kc_badge = "badge-blue"
                elif "Действия" in kc: kc_badge = "badge-red"
                
                hosts_html += f"<tr id='row-{r['line']}' {row_class}>"
                hosts_html += f"<td>{r['line']}</td>"
                hosts_html += f"<td><span class='badge {kc_badge}' style='font-size:10px;'>{kc}</span></td>"
                hosts_html += f"<td><code>{r['path']}</code></td>"
                hosts_html += f"<td><code>{r['status']}</code></td>"
                hosts_html += f"<td style='color:var(--critical); font-size:0.85em; font-weight:bold;'>{cons}</td></tr>\n"
            if not t['chain']: hosts_html += "<tr><td colspan='5' style='text-align:center;'>Прямых совпадений с сигнатурами не найдено</td></tr>\n"
            hosts_html += "</table>\n</div>\n</div>\n"

        # Data map
        labels = [t['ip'] for t in threats[:10]]
        scores = [t['score'] for t in threats[:10]]
        req_counts = [t['total_reqs'] for t in threats[:10]]

        replacements = {
            "{{LOG_PATH}}": log_path,
            "{{REPORT_DATE}}": now,
            "<!-- SIDEBAR_ITEMS -->": sidebar_html,
            "<!-- HOST_CONTENTS -->": hosts_html,
            "{{CHART_LABELS}}": json.dumps(labels),
            "{{CHART_SCORES}}": json.dumps(scores),
            "{{CHART_REQS}}": json.dumps(req_counts)
        }

        for k, v in replacements.items():
            html_content = html_content.replace(k, str(v))

        with open(report_path_html, "w", encoding="utf-8") as html:
            html.write(html_content)

        print(f"[green][+] HTML Отчет: [cyan]{report_path_html}[/cyan][/green]")
    except Exception as e:
        print(f"[red][!] Ошибка записи HTML отчета: {e}[/red]")
        import traceback
        traceback.print_exc()

    # --- Excel (CSV with BOM) Export ---
    try:
        import csv
        with open(report_path_csv, "w", newline='', encoding="utf-8-sig") as csvfile:
            writer = csv.writer(csvfile, delimiter=';')
            writer.writerow(["IP Адрес", "Уровень Угрозы (%)", "Количество Запросов", "Обнаруженные Поведенческие/Сигнатурные Угрозы"])
            for t in threats:
                writer.writerow([t['ip'], t['score'], t['total_reqs'], ', '.join(t['reasons'])])
        print(f"[green][+] Отчет для Excel: [cyan]{report_path_csv}[/cyan][/green]")
    except Exception as e:
        print(f"[red][!] Ошибка записи CSV отчета (возможно файл открыт в Excel): {e}[/red]")

    print(f"[green][+] Анализ завершен. Найдено объектов с риском: {len(threats)}[/green]")

def run(base_dir, gconf_path="", args=None):
    """Точка входа для apm sec logs"""
    project_root = os.getcwd()
    if not args:
        print("[yellow]Использование: apm sec logs [init|analyze] [-path PATH] [-pattern PATTERN][/yellow]")
        return

    command = args[0]
    if command == "init":
        init(project_root)
    elif command == "analyze":
        log_file = "logs/app.log"
        pattern = None
        for i in range(len(args)):
            if args[i] == "-path" and i+1 < len(args): log_file = args[i+1]
            if args[i] == "-pattern" and i+1 < len(args): pattern = args[i+1]
        analyze(project_root, log_file=log_file, custom_pattern=pattern)
    else:
        print(f"[red][!] Неизвестная команда: {command}[/red]")
