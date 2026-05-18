import datetime
import json
import logging
import os
import re
from logging import FileHandler, StreamHandler
from urllib.parse import unquote

from flask import Response, request
from rich import print


class RemoveAnsiAndRichMarkupFormatter(logging.Formatter):
    ANSI_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    RICH_TAGS_PATTERN = re.compile(r"\[/?[^\]]+\]")

    def format(self, record):
        rendered = super().format(record)
        rendered = self.ANSI_PATTERN.sub("", rendered)
        rendered = self.RICH_TAGS_PATTERN.sub("", rendered)
        return rendered


class Logger:
    def __init__(self, app):
        self.app = app.flask
        self.app.logger.propagate = False
        self.app.logger.handlers.clear()

        logs_dir = os.path.join(app.project_root, "logs")
        os.makedirs(logs_dir, exist_ok=True)

        file_handler = FileHandler(os.path.join(logs_dir, "app.log"))
        file_handler.setLevel(logging.INFO)
        console_handler = StreamHandler()
        console_handler.setLevel(logging.INFO)

        log_format = "%(asctime)s - %(levelname)s - %(message)s"
        file_handler.setFormatter(RemoveAnsiAndRichMarkupFormatter(log_format))
        console_handler.setFormatter(logging.Formatter(log_format))

        self.app.logger.setLevel(logging.INFO)
        self.app.logger.addHandler(file_handler)
        self.app.logger.addHandler(console_handler)

        werkzeug_logger = logging.getLogger("werkzeug")
        werkzeug_logger.setLevel(logging.WARNING)
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)

        self.register_hooks()

    def register_hooks(self):
        @self.app.after_request
        def log_ip(response: Response):
            ip = request.remote_addr or "Unknown IP"
            method = request.method
            user_agent = request.headers.get("User-Agent", "Unknown User-Agent")
            path = request.full_path
            self.app.logger.info(f"{ip} {method} {path} - {user_agent} - {response.status_code}")
            return response


def init(project_root):
    logs_dir = os.path.join(project_root, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    print(f"[green][+] Директория {logs_dir} готова.[/green]")


def template_to_regex(template):
    variables = re.findall(r"\$?\{([a-z0-9_]+)\}", template.lower())
    regex_parts = []

    for var in variables:
        if var == "ip":
            regex_parts.append(r"(?<!\d)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?!\d)")
        elif var == "status":
            regex_parts.append(r"(?<!\d)(?P<status>[1-5]\d{2})(?!\d)")
        elif var == "method":
            regex_parts.append(r"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)")
        elif var == "path" or var == "endpoint":
            regex_parts.append(r"(?P<path>/(?:[^\s\"'|<>]+)?)")
        elif var in ("ts", "time", "date"):
            regex_parts.append(r"(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)")

    return ".*?".join(regex_parts) if regex_parts else r".*"


def analyze(log_path, custom_pattern=None):
    if not os.path.exists(log_path):
        print(f"[red][-] Лог-файл не найден: {log_path}[/red]")
        return

    if custom_pattern:
        pattern_str = template_to_regex(custom_pattern) if "{" in custom_pattern else custom_pattern
        try:
            log_regex = re.compile(pattern_str)
        except re.error as exc:
            print(f"[red][-] Неверный шаблон анализа: {exc}[/red]")
            return
    else:
        log_regex = re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - \w+ - "
            r"(?P<ip>[\d.]+) (?P<method>[A-Z]+) (?P<path>/[^ ]*) - .* - (?P<status>\d{3})"
        )

    suspicious_patterns = [
        ("SQLi", r"(union|select|drop|insert|or\s+1=1|--)", "Эксплуатация"),
        ("XSS", r"(<script|javascript:|onerror=|onload=)", "Эксплуатация"),
        ("RCE", r"(;|\|\||&&|`.*`|\$\(.*\)|cmd\.exe|powershell|/bin/sh)", "Эксплуатация"),
        ("Traversal", r"(\.\./|/etc/passwd|win\.ini|%00)", "Эксплуатация"),
        ("Scanner", r"(sqlmap|nikto|nmap|acunetix|gobuster)", "Разведка"),
    ]

    findings = []
    with open(log_path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            match = log_regex.search(line)
            if not match:
                continue
            data = match.groupdict()
            ip = data.get("ip", "0.0.0.0")
            path = unquote(data.get("path", "/"))
            status = data.get("status", "000")
            ts = data.get("ts", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            for category, pattern, stage in suspicious_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    findings.append(
                        {
                            "line": line_no,
                            "time": ts,
                            "ip": ip,
                            "path": path,
                            "status": status,
                            "category": category,
                            "stage": stage,
                        }
                    )

    print(f"[cyan][*] Найдено подозрительных записей: {len(findings)}[/cyan]")
    for finding in findings[:50]:
        print(
            f"[yellow]{finding['category']}[/yellow] "
            f"{finding['ip']} {finding['path']} "
            f"(строка {finding['line']}, код {finding['status']})"
        )

    report_template = os.path.join(os.path.dirname(__file__), "report_template.html")
    if os.path.exists(report_template):
        output_path = os.path.join(os.path.dirname(log_path), "sec_report.json")
        with open(output_path, "w", encoding="utf-8") as report:
            json.dump(findings, report, indent=2, ensure_ascii=False)
        print(f"[green][+] JSON-отчет сохранен: {output_path}[/green]")


def run(base_dir, gconf_path="", args=None):
    args = args or []
    project_root = os.getcwd()

    if not args or args[0] in {"-h", "--help"}:
        print("Usage: apm sec logs init | analyze [--template TEMPLATE]")
        return

    command = args[0]
    if command == "init":
        init(project_root)
        return

    if command == "analyze":
        template = None
        if "--template" in args:
            try:
                template = args[args.index("--template") + 1]
            except IndexError:
                print("[red][-] Не указан шаблон после --template[/red]")
                return

        log_path = os.path.join(project_root, "logs", "app.log")
        analyze(log_path, custom_pattern=template)
        return

    print(f"[red][-] Неизвестная команда logs: {command}[/red]")
