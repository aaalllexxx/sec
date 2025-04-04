from rich import print
from datetime import datetime
from urllib.parse import unquote
import shutil
import os
import re
import sys
from abc import ABC, abstractmethod

__help__ = "Устанавливает логирование"

BRUTE_TIMEOUT_TARGET = 2
MIN_REQUESTS_FOR_BRUTE = 10

DEFAULT_LOG_TEMPLATE = "%{Y}-%{m}-%{D} %{H}:%{M}:%{S},%{MS} - %{level} - %{ip} %{method} %{endpoint} - %{user_agent} - %{code}"


base = os.sep.join(__file__.split(os.sep)[:-1])
with open(base + os.sep + "__RCE.list", "r", encoding="utf-8") as file:
    rce_list = file.read().split("\n")


########################################################################
# 1) Помощники для работы с шаблонами вида: "%{D}.%{M}.%{Y} ... %{ip} ..."
########################################################################

# Шаблон для каждой переменной. При желании расширяйте/уточняйте.
PLACEHOLDER_PATTERNS = {
    "D": r"\d{1,2}",         # День
    "m": r"\d{1,2}",         # Месяц
    "M": r"\d{1,2}",         # Минуты
    "Y": r"\d{4}",           # Год
    "H": r"\d{1,2}",         # Часы
    "S": r"\d{1,2}",         # Секунды (или что-то еще)
    "MS": r"\d{1,4}",        # Миллисекунды
    "ip": r"[0-9a-fA-F:\.]+",# IPv4/IPv6 упрощённо
    "endpoint": r".+?",      # Любое содержимое (не жадно)
    "method": r"[A-Z]+",     # Методы типа GET, POST и т.п.
    "level": r"[A-Z]+",      # Уровень (INFO, ERROR, WARN ...)
    "proto": r"[A-Za-z0-9/\.]+",
    "code": r"\d{3}",        # Код ответа (обычно 3 цифры)
    "user_agent": r".+?",  # всё до конца строки
}

def compile_log_template(template: str) -> re.Pattern:
    """
    Превращает шаблон вида:
        "%{D}.%{m}.%{Y} %{H}:%{M}:%{S}.%{MS} - %{ip} - "%{endpoint} %{method} - %{level} - %{proto} - %{code}"
    в строгую регулярку с named-groups.
    Неизменяемая часть экранируется, %{...} превращается в (?P<имя>паттерн).
    """
    # 1) Найдём все участки %{...}
    placeholder_regex = re.compile(r'%\{([^}]+)\}')  # ищем %{имя}
    
    # Для хранения фрагментов:
    regex_parts = []
    last_idx = 0
    
    # Список всех имён, чтобы различать дубли (например M, M)
    used_placeholders_count = {}
    
    for match in placeholder_regex.finditer(template):
        start, end = match.span()
        # Неизменяемый кусочек до placeholder'a
        literal_text = template[last_idx:start]
        regex_parts.append(re.escape(literal_text))  # экранируем, чтобы точка/скобки и т.п. совпадали буквально
        
        placeholder_name = match.group(1)  # например "D", "M", "ip" и т.д.
        
        # Если это имя уже использовали, добавим суффикс вида _2, _3 и т.д.
        used_placeholders_count.setdefault(placeholder_name, 0)
        used_placeholders_count[placeholder_name] += 1
        current_count = used_placeholders_count[placeholder_name]
        
        # Для уникальности:
        unique_group_name = f"{placeholder_name}_{current_count}" if current_count > 1 else placeholder_name
        
        # Берём паттерн из словаря или общий шаблон
        if placeholder_name in PLACEHOLDER_PATTERNS:
            pat = PLACEHOLDER_PATTERNS[placeholder_name]
        else:
            # Для неизвестных placeholder'ов — любой непустой текст
            pat = r".+?"
        
        # Добавим в итоговую регулярку именованную группу
        regex_parts.append(f"(?P<{unique_group_name}>{pat})")
        
        last_idx = end
    
    # Добавим "хвост" шаблона после последнего placeholder
    if last_idx < len(template):
        literal_text = template[last_idx:]
        regex_parts.append(re.escape(literal_text))
    
    # Склеиваем куски в одно регулярное выражение с ^ $ (строгое совпадение)
    full_pattern = "^" + "".join(regex_parts) + "$"
    return re.compile(full_pattern)


########################################################################
# 2) Класс Record, который теперь парсит строку через compile_log_template
########################################################################

class Record:
    def __init__(self, line: str, log_template: str, compiled_pattern: re.Pattern = None):
        self.line = line.rstrip("\n\r")
        self.template = log_template or DEFAULT_LOG_TEMPLATE

        # Если уже есть скомпилированный паттерн, используем его
        self.compiled_pattern = compiled_pattern or compile_log_template(self.template)
        
        # В этот словарь сложим значения, извлечённые из группы
        self.values = {}
        # Попытка распарсить строку:
        if not self._parse_line():
            print(f"Строка не соответствует шаблону:\n{self.line}\n{self.template}")
            # Если не подходит под шаблон, выбрасываем ошибку, чтобы верхний код пропустил эту строку
            raise ValueError("Строка лога не соответствует шаблону")
        
        # Попробуем заполнить "стандартные" поля (date, time, ip, endpoint и т.п.)
        self._fill_standard_fields()


    def _parse_line(self) -> bool:
        """
        Пытается сопоставить self.line с self.compiled_pattern.
        Если успешно, сохраняет группы в self.values и возвращает True, иначе False
        """
        match = self.compiled_pattern.match(self.line)
        if not match:
            return False
        
        # Собираем все группы
        self.values = match.groupdict()
        return True

    def _fill_standard_fields(self):
        """
        Часть логики, которая пытается интерпретировать некоторые имена групп
        (например, если есть D, M, Y, H, M, S, MS — собираем дату; если есть ip — сохраняем как address; code => int и т.п.)
        """
        # По умолчанию
        self.date = None
        self.type = "INFO"
        self.address = "-"
        self.method = "GET"
        self.endpoint = "/"
        self.protocol = "HTTP/1.1"
        self.code = 200
        self.user_agent = "-"
        
        # Для удобства возьмём все группы:
        g = self.values
        
        # Пробуем собрать дату и время, если есть D, M, Y, H, S, MS
        # Заметьте, что M может означать "месяц" и "минуты", если шаблон повторяется, но в примере считаем,
        # что M_1 — месяц, M_2 — минуты (либо наоборот — на ваше усмотрение).
        D = g.get("D", None) or g.get("D_1", None)
        M = g.get("m", None)
        Y = g.get("Y", None) or g.get("Y_1", None)
        
        H = g.get("H", None) or g.get("H_1", None)
        M2 = g.get("M", None)  # вдруг второе появление M — минуты
        S = g.get("S", None) or g.get("S_1", None)
        MS = g.get("MS", None) or g.get("MS_1", None)

        
        if D and M and Y and H and (M2 or M) and S:
            # Попробуем понять, где месяц, где минуты
            # Упростим: предположим, что первое M — это месяц, а M_2 (если есть) — это минуты
            day = int(D)
            month = int(M)
            hour = int(H)
            minute = int(M2) if M2 else 0
            second = int(S)
            micro = 0
            
            if MS:
                # MS — это миллисекунды, переведём в микросекунды
                micro = int(MS) * 1000 if MS.isdigit() else 0
            
            # Собираем datetime
            try:
                self.date = datetime(year=int(Y), month=month, day=day,
                                     hour=hour, minute=minute, second=second, microsecond=micro)
            except ValueError:
                # вдруг неправильная дата
                pass
        
        if "ip" in g:
            self.address = g["ip"] or "-"
        if "endpoint" in g:
            # декодируем, как раньше
            self.endpoint = unquote(g["endpoint"])
        if "method" in g:
            self.method = g["method"]
        if "level" in g:
            self.type = g["level"]
        if "proto" in g:
            self.protocol = g["proto"]
        if "code" in g:
            try:
                self.code = int(g["code"])
            except ValueError:
                pass
        if "user_agent" in g:
            self.user_agent = g["user_agent"]

    def __str__(self):
        return self.line

    def __repr__(self):
        return str(self)


########################################################################
# 3) Базовый класс и детекторы
########################################################################

class BaseLogDetector(ABC):
    def __init__(self, log_template):
        self.log_template = log_template
        # Чтобы не перекомпилировать шаблон на каждую строку, скомпилируем один раз
        self._compiled_pattern = compile_log_template(log_template)
        self.potential = []
        self.vulnerable = []

    @abstractmethod
    def analyze(self, records: list[Record]) -> None:
        pass

    def summary(self):
        return self.potential, self.vulnerable

class UserAgentDetector(BaseLogDetector):
    xss_patterns = [
        "<", ">", "\"", "'", "script", "javascript", "alert", "onerror", "onload", "src=", "href="
    ]

    rce_keywords = [
        "curl", "wget", "python", "perl", "java", "powershell", "nc", "bash", "sh",
        "cmd.exe", "system32", "os.system", "subprocess", "eval", "exec"
    ]

    sqli_keywords = [
        "UNION", "SELECT", "SLEEP", "AND", "OR", "WHERE", "DROP", "--", "/*", "*/", "#"
    ]

    scanner_keywords = [
        "sqlmap", "nikto", "acunetix", "nessus", "nmap", "whatweb", "wafw00f", "fuzz"
    ]

    def analyze(self, records):
        for rec in records:
            ua = rec.user_agent.lower()
            xss_detected = any(x in ua for x in self.xss_patterns)
            rce_detected = any(k in ua for k in self.rce_keywords)
            sqli_detected = any(k.lower() in ua for k in self.sqli_keywords)
            scanner_detected = any(k in ua for k in self.scanner_keywords)

            if xss_detected or rce_detected or sqli_detected or scanner_detected:
                if rec.code < 400:
                    self.vulnerable.append(rec)
                else:
                    self.potential.append(rec)

class FuzzDetector(BaseLogDetector):
    def __init__(self, log_template):
        super().__init__(log_template)
        self.summary_data = {}
        self.records_by_ip = {}

    def analyze(self, batch):
        for rec in batch:
            ip = rec.address
            self.records_by_ip.setdefault(ip, {"error": [], "success": []})
            if rec.code > 400:
                self.records_by_ip[ip]["error"].append(rec)
            elif rec.code == 200:
                self.records_by_ip[ip]["success"].append(rec)

        for ip, data in self.records_by_ip.items():
            errors = len(data["error"])
            success = len(data["success"])
            total = errors + success
            if total > MIN_REQUESTS_FOR_BRUTE:
                acc = round(errors / total * 100, 1) if total else 0
                self.summary_data[ip] = acc
                self.vulnerable.extend(data["success"])

    def get_fuzz_summary(self):
        return self.summary_data, self.vulnerable


class XSSDetector(BaseLogDetector):
    patterns = ["<", ">",  "/*", "*/", "'", '"', "script", " src=", " href=", "javascript", "://", "cookie", "document."]
    
    def analyze(self, records):
        for rec in records:
            if "?" in rec.endpoint:
                args = rec.endpoint.split("?", 1)[1].split("&")
                for arg in args:
                    data = arg.split("=", 1)
                    if len(data) > 1:
                        if any(ch in data[1].lower() for ch in self.patterns):
                            if rec.code < 400:
                                self.vulnerable.append(rec)
                            else:
                                self.potential.append(rec)


class LFIDetector(BaseLogDetector):
    def analyze(self, records):
        for rec in records:
            if "?" in rec.endpoint:
                args = rec.endpoint.split("?", 1)[1].split("&")
                for arg in args:
                    data = arg.split("=", 1)
                    if len(data) > 1:
                        # Поиск последовательностей вроде ../../, //, \\. и т.п.
                        if re.findall(r"(?:\.\./|//|\\|%2f%2f)", data[1], flags=re.IGNORECASE):
                            self.potential.append(rec)
                            if rec.code == 200:
                                self.vulnerable.append(rec)


class RCEDetector(BaseLogDetector):
    def analyze(self, records):
        for rec in records:
            if "?" in rec.endpoint:
                args = rec.endpoint.split("?", 1)[1].split("&")
                for arg in args:
                    parts = arg.split("=", 1)
                    if len(parts) > 1:
                        commands = parts[1].split()
                        cmd = commands[0] if commands else ""
                        # Смотрим в __RCE.list или проверяем, что shutil.which находит исполняемый файл
                        if shutil.which(parts[1]) or cmd in rce_list:
                            if rec.code < 400:
                                self.vulnerable.append(rec)
                            else:
                                self.potential.append(rec)
                            break


class SQLiDetector(BaseLogDetector):
    import re

class SQLiDetector(BaseLogDetector):
    # Список (или множество) опасных ключевых слов и символов,
    # которые часто встречаются в SQL-инъекциях
    patterns = {
        "SELECT", "UNION", "SLEEP", "RLIKE", "AND", "OR", "WHERE",
        "ORDER", "--", "/*", "*/", "#", "AS", "@VARIABLE", "DROP",
        "INSERT", "UPDATE", "DELETE"
    }

    def analyze(self, records):
        for rec in records:
            # Если в запросе нет вопросительного знака, значит параметров нет
            if "?" not in rec.endpoint:
                continue
            
            # Пример: /search?query=SELECT%20id%20FROM%20users&sort=asc
            # Берём всё после '?': query=SELECT%20id%20FROM%20users&sort=asc
            query_string = rec.endpoint.split("?", 1)[1]

            # Делим строку по & — получаем список "query=..." и "sort=asc"
            params = query_string.split("&")

            for param in params:
                # Делим по '=', чтобы взять имя параметра и значение
                parts = param.split("=", 1)
                if len(parts) < 2:
                    continue  # нет значения
                
                # value — всё, что после =
                # Приводим к верхнему регистру, чтобы сравнивать без учёта регистра
                value = parts[1].upper()

                # Разделяем значение параметра на «слова»:
                # \W означает любой не буквенно-цифровой символ; добавляем _ к этому набору
                # Если нужно, можно расширить регулярку.
                words = re.split(r"[\W_]+", value)
                # Удалим пустые строки (если были несколько небуквенных символов подряд)
                words = [w for w in words if w]

                # Проверяем, есть ли среди разбитых слов «опасное»
                # Если хотя бы одно из слов входит в patterns → подозрение на SQLi
                if any(word in self.patterns for word in words):
                    if rec.code < 400:
                        self.vulnerable.append(rec)
                    else:
                        self.potential.append(rec)



########################################################################
# 4) Основной класс-анализатор
########################################################################

class LogAnalyzer:
    def __init__(self, log_template="default"):
        # При создании сохраняем скомпилированный паттерн, чтобы не компилить много раз
        self._compiled_pattern = compile_log_template(log_template) if log_template != "default" else None
        
        self.fuzz_detector = FuzzDetector(log_template)
        self.detectors = [
            self.fuzz_detector,
            XSSDetector(log_template),
            LFIDetector(log_template),
            RCEDetector(log_template),
            SQLiDetector(log_template),
            UserAgentDetector(log_template)
        ]
        self.log_template = log_template
    
    def __read_next_n(self, stream, n):
        """
        Читает до n строк (или меньше, если достигнут конец файла).
        Возвращает:
        - None, если мы вообще не смогли прочитать ни одной новой строки (EOF).
        - Список распарсенных Record, даже если он пуст (но в этом случае файл еще не закончился).
        """
        records = []
        lines_read = 0

        for _ in range(n):
            line = next(stream, None)  # Читаем следующую строку
            if line is None:
                # Точно достигнут конец файла.
                break
            lines_read += 1
            line = line.strip()
            if not line:
                # Пустая строка — пропустим
                continue

            try:
                rec = Record(line, self.log_template, compiled_pattern=self._compiled_pattern)
                records.append(rec)
            except ValueError:
                # Строка не соответствует шаблону — пропускаем
                pass

        # Если мы не прочитали ни одной строки из файла, значит EOF
        if lines_read == 0:
            return None

        # Иначе возвращаем список распарсенных Record — даже если он пуст
        return records



    def __write_report(self, title, potential, vulnerable, report):
        if vulnerable:
            print(f"\n[green bold][red bold][!][/red bold] Эксплуатация {title}[/green bold]:")
        report.write(f"\n[!] Эксплуатация {title}: \n")
        for rec in set(vulnerable):
            print("    - [red]" + rec.line + "[/red]")
            report.write("    - " + str(rec) + "\n")
        if potential:
            report.write(f"\n[!] Попытки {title}:\n")
            for rec in set(potential):
                report.write("    - " + str(rec) + "\n")

    def run(self, log_path="logs/app.log", report_path="report.txt", lines=1000):
        with open(log_path, encoding="utf-8") as file, open(report_path, "w", encoding="utf-8") as report:
            while True:
                batch = self.__read_next_n(file, lines)
                if batch is None:
                    break

                for detector in self.detectors:
                    detector.analyze(batch)

            # Выводим результаты
            fuzz_summary, fuzz_records = self.fuzz_detector.get_fuzz_summary()
            for ip, acc in fuzz_summary.items():
                if acc > 1:
                    print(f"[yellow][!][/yellow] [blue]Вероятность фаззинга от[/blue] [green]{ip}[/green]: [red]{acc}[/red]")
                    report.write(f"[!] Вероятность фаззинга от {ip}: {acc}\n")

            for detector in self.detectors[1:]:
                potential, vulnerable = detector.summary()
                self.__write_report(detector.__class__.__name__, potential, vulnerable, report)


########################################################################
# 5) Вспомогательные функции init / run
########################################################################

def __init(*args):
    if os.path.exists("AEngineApps"):
        if not os.path.exists("AEngineApps/logging.py"):
            open(os.path.join("AEngineApps/logging.py"), "w", encoding="utf-8").close()
        with open(os.path.join(base, "__logging.py"), encoding="utf-8") as file, \
             open(os.path.join("AEngineApps/logging.py"), "w", encoding="utf-8") as file_to:
            file_to.write(file.read())

def run(*args, **kwargs):
    arg = kwargs["args"]
    log_template = DEFAULT_LOG_TEMPLATE

    if "init" in arg:
        __init(arg)
    if "analyze" in arg:
        if "--template" in arg:
            try:
                log_template = arg[arg.index("--template") + 1]
            except IndexError:
                print("[red]Ошибка: не указан шаблон после --template[/red]")
                sys.exit(1)
        analyzer = LogAnalyzer(log_template=log_template)
        lines = int(arg[arg.index("-l") + 1]) if "-l" in arg else 1000
        analyzer.run(lines=lines)

if __name__ == "__main__":
    run(args=sys.argv)
