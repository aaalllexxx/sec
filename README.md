# Модуль sec (AEngine v2.2)

Комплексный модуль информационной безопасности для AEngineApps. Включает защиту веб-приложения (IDS/IPS), защиту операционной системы, анализ сетевого трафика, кластеризацию и визуальный дашборд.

## 🚀 Установка

Установка в текущий проект:
```sh
apm install https://github.com/aaalllexxx/sec
```

Глобальная установка:
```sh
apm install -g https://github.com/aaalllexxx/sec
```

Зависимости:
```sh
pip install psutil
```

---

## ⚙️ Быстрая инициализация (`apm sec init`)

Установить **все** модули безопасности в проект одной командой:
```sh
apm sec init
```

Установить только **конкретные** модули:
```sh
apm sec init --modules intrusion logs sys_protect dashboard
```

Посмотреть список доступных модулей:
```sh
apm sec init --list
```

| Модуль | Описание |
|---|---|
| `intrusion` | IDS/IPS и детекторы атак (SQLi, XSS, RCE, LFI, RateLimiter) |
| `logs` | Логирование запросов (Logger) |
| `os_protect` | Защита ОС: контроль CPU/RAM, проверка привилегий |
| `net_analyzer` | Анализ сетевого трафика: SYN Flood, аномальные IP |
| `sys_protect` | Продвинутая защита: сканер процессов, конфигураций, пользователей |
| `dashboard` | Админ-панель безопасности с авторизацией и AJAX-сканированием |
| `cluster` | Active-Passive кластеризация (межсерверная) |
| `auto_cluster` | Локальная кластеризация (один сервер, multiprocessing) |

---

## 🛡️ IDS / IPS и Ограничения (`__intrusions.py`)

Модуль позволяет обнаруживать (IDS) и предотвращать (IPS) атаки. Все детекторы **глубоко сканируют** `GET`-параметры, `POST`-формы и `JSON`-тела (с рекурсивной проверкой вложенностей).

### Инициализация
Чтобы создать базовые файлы в проекте, выполните:
```sh
apm sec intrusion init
```

### RateLimiter (Ограничение запросов)
> Блокирует IP-адрес, если он отправляет слишком много запросов за определённое время (DDoS, брутфорс). При превышении лимита возвращает HTTP `429 Too Many Requests`.

```python
from AEngineApps.app import App
from AEngineApps.intrusions import RateLimiter

app = App()

# Максимум 100 запросов за 60 секунд (1 минута) с одного IP
limit = RateLimiter(app, max_requests=100, window=60)
```

### IDS (Intrusion Detection System)
> Только **обнаруживает** атаки и логирует их, но не прерывает запрос.

**Методы IDS:**
- `__init__(app)` — привязка к приложению.
- `add_detector(DetectorClass)` — добавление детектора атак.
- `on_trigger(func)` — регистрация коллбэка (срабатывает при обнаружении). Отрабатывает как декоратор или прямой метод.

```python
from AEngineApps.app import App
from AEngineApps.intrusions import IDS, XSSDetector

app = App()
ids = IDS(app)

# Подключение детекторов
ids.add_detector(XSSDetector)

# Коллбэк при атаке
@ids.on_trigger
def on_attack():
    print("Обнаружена подозрительная активность!")
```

### IPS (Intrusion Prevention System)
> Наследуется от `IDS`. Не только логирует, но и **прерывает** запрос (возвращает HTTP `400 Bad Request`).

**Методы IPS:**
- Все методы `IDS`.
- `block_request()` — метод прерывания запроса (регистрируется автоматически).

```python
from AEngineApps.intrusions import IPS, SQLiDetector, RCEDetector

ips = IPS(app)
ips.add_detector(SQLiDetector)
ips.add_detector(RCEDetector)
```

---

## 🔍 Доступные Детекторы

1. **`RCEDetector`** — Обнаруживает Remote Code Execution (запуск системных команд: `eval`, `exec`, `system`, `bash`).
2. **`LFIDetector`** — Обнаруживает Local/Remote File Inclusion (чтение файловой системы: `../`, `/etc/passwd`, `%00`).
3. **`SQLiDetector`** — Обнаруживает SQL-иньекции (ключевые слова и спецсимволы: `OR`, `SELECT`, `DROP`, `'--`, `/*`).
4. **`XSSDetector`** — Обнаруживает межсайтовый скриптинг (теги и эвенты: `<script>`, `javascript:`, `onerror=`, `onload=`).

### Создание собственных детекторов (BaseDetector)

Вы можете создать свой собственный детектор, унаследовав его от `BaseDetector`.
Обязательно нужно реализовать метод `run()`.

**Вспомогательные методы BaseDetector:**
- `self.log(message)` — отправляет лог с уровнем `CRITICAL`.
- `self.trigger_response()` — обязательный вызов для активации коллбэков `IDS/IPS`.
- `_get_all_input_values()` — глобальная функция модуля для извлечения всех входных данных.

```python
from AEngineApps.intrusions import BaseDetector, _get_all_input_values
from flask import request
from urllib.parse import unquote

class MyCustomDetector(BaseDetector):
    def run(self):
        # Получаем GET, POST и JSON
        for arg in _get_all_input_values():
            if "bad_word" in unquote(arg).lower():
                self.log(f"DETECTED BAD WORD: {request.full_path}")
                self.trigger_response() # Активируем триггеры IDS/IPS
```

---

## 📝 Анализатор логов (`logs.py`)

### Инициализация
Создает в проекте файл логирования:
```sh
apm sec logs init
```

### Logger (Класс логирования)
После инициализации, класс `Logger` автоматически настраивает базовое логирование для AEngine.
```python
from AEngineApps.app import App
from AEngineApps.logging import Logger

app = App()
logger = Logger(app)
```

### `apm sec logs analyze`
Инструмент статического анализа. Парсит текстовые логи сервера и ищет в них паттерны успешных атак (SQLi, XSS, RCE, LFI) по сохранённым URL и телам запросов.

```sh
apm sec logs analyze
```

Вы можете задать собственный формат парсинга логов с помощью флага `--template`:

```sh
apm sec logs analyze --template "[%{Y}-%{m}-%{D} %{H}:%{M}:%{S}] %{level} in %{ip}: %{method} %{endpoint}"
```

**Доступные переменные парсера:**
- Даты: `%{Y}`, `%{m}`, `%{D}`
- Время: `%{H}`, `%{M}`, `%{S}`, `%{MS}`
- Сеть: `%{ip}`, `%{method}`, `%{endpoint}`, `%{proto}`, `%{code}`
- Уровни: `%{level}`

---

## 🖥️ Защита ОС (`os_protect.py`)

Кроссплатформенный контроль за потреблением ресурсов (CPU/RAM) и проверка привилегий. Использует `psutil`.

**Автоматический режим** — передайте `app`, защита включится сама:
```python
from sec.os_protect import get_os_protection_module

# Автоматическая проверка перед каждым HTTP-запросом.
# При перегрузке CPU/RAM сервер вернёт 503.
os_protect = get_os_protection_module(app, max_cpu_percent=90.0, max_ram_percent=90.0)
```

**Ручной режим** — без привязки к приложению:
```python
os_protect = get_os_protection_module()
health = os_protect.run_health_check()

if health["status"] == "danger":
    print("Сервер под нагрузкой!")
```

---

## 🌐 Анализ сетевого трафика (`net_analyzer.py`)

Выявление SYN Flood атак и подозрительных скоплений соединений с одного IP. Использует `psutil`.

**Автоматический режим:**
```python
from sec.net_analyzer import get_network_analyzer

# Автоматическая проверка SYN Flood перед каждым HTTP-запросом.
net_analyzer = get_network_analyzer(app, max_syn_requests=100, max_connections_per_ip=50)
```

**Ручной режим:**
```python
net_analyzer = get_network_analyzer()
result = net_analyzer.run_analysis()

if result["syn_flood"]["status"] == "danger":
    print("SYN Flood обнаружен!")
```

---

## 🔒 Продвинутая Защита Системы (`sys_protect.py`) — Новое в v2.2

Единый модуль глубокого сканирования хоста. Подключается **одной строкой** и работает в фоне.

### Что сканирует

| Категория | Что проверяет | Примеры |
|---|---|---|
| **Процессы** | Поиск известных вредоносных программ | `xmrig`, `mimikatz`, `nmap`, `hydra`, `netcat` |
| **Пути запуска** | Процессы из временных директорий | `/tmp/`, `/dev/shm/`, `%TEMP%`, `%APPDATA%` |
| **Конфигурации** | Небезопасные настройки приложения | `debug=True`, слабый `secret_key`, CORS `*` |
| **Привилегии** | Запуск от имени суперпользователя | root / Administrator |
| **Пользователи** | Аномальные терминальные сессии | > 5 сессий, один юзер с разных хостов |
| **Ресурсы** | Перегрузка хоста | CPU > 90%, RAM > 90%, Disk > 95% |

### Подключение (одна строка)
```python
from sec.sys_protect import AdvancedSystemProtection

# Всё! Фоновый сканер запустится автоматически.
protection = AdvancedSystemProtection(app)
```

### Расширенная настройка
```python
protection = AdvancedSystemProtection(
    app,
    scan_interval=15,     # Сканировать каждые 15 секунд (по умолчанию 30)
    max_cpu=85.0,         # Порог CPU
    max_ram=85.0,         # Порог RAM
    max_users=3,          # Максимум терминальных сессий
)

# Колбэк при обнаружении угрозы
@protection.on_alert
def handle_alert(report):
    print(f"🚨 Обнаружено {len(report['alerts'])} угроз!")
    for alert in report["alerts"]:
        print(f"  - {alert}")
```

### Ручной запуск сканирования
```python
# Без привязки к приложению (без фонового потока)
scanner = AdvancedSystemProtection(scan_interval=0, auto_start=False)
report = scanner.scan()

print(report["status"])       # "ok" | "danger"
print(report["alerts"])       # Список строк-предупреждений
print(report["processes"])    # Подозрительные процессы
print(report["users"])        # Активные пользователи ОС
print(report["config"])       # Проблемы конфигурации
print(report["resources"])    # CPU/RAM/Disk
```

---

## 🔄 Кластеризация

### Active-Passive на разных серверах (`cluster.py`)

Отказоустойчивость через Heartbeat (UDP) и автоматическую синхронизацию файлов проекта по TCP.

```python
from sec.cluster import create_cluster_node

def on_failover():
    print("Master нода упала! Запускаем резервное приложение...")

node = create_cluster_node(
    node_id="slave_1",
    role="slave", 
    master_ip="192.168.1.100",
    master_port=8888,
    sync_dir="."
)

node.on_failover = on_failover
node.start()
```

### Локальный кластер на одном сервере (`auto_cluster.py`) — Новое в v2.2

Запускает несколько копий приложения на разных портах через `multiprocessing`. Первый порт = Master, остальные = Slave. При падении Master'а автоматический failover.

```python
from sec.auto_cluster import LocalCluster

app = ShowcaseApp()

# Вместо app.run() — запускаем кластер:
cluster = LocalCluster(app, ports=[5000, 5001, 5002])
cluster.run()
```

**Что происходит:**
1. Порт `5000` — Master (Active), обрабатывает трафик.
2. Порты `5001`, `5002` — Slave (Passive), горячий резерв.
3. Watchdog мониторит все ноды.
4. Если Master падает — первый живой Slave автоматически становится Master.
5. Упавшие Slave-ноды автоматически перезапускаются.

```python
# Получить текущее состояние кластера:
status = cluster.get_status()
print(status["master_port"])  # 5000
print(status["alive"])        # 3
```

---

## 📊 Админ-Панель Безопасности (`dashboard.py`)

Микросервис-дашборд с сессионной авторизацией. Визуально отображает здоровье ОС, сети, логи инцидентов и позволяет запускать сканирование в интерактивном режиме.

### Подключение
```python
from sec.dashboard import SecDashboardService

admin = SecDashboardService(
    prefix="/admin",           # URL-адрес панели
    admin_login="superadmin",  # Логин
    admin_pass="strongpass"    # Пароль
)

# Регистрация в приложении:
app.register_service(admin)
```

После запуска: `http://localhost:5000/admin`

### Возможности дашборда

| Кнопка | API | Описание |
|---|---|---|
| **Запустить сканирование** | `GET /admin/api/scan` | CPU, RAM, SYN Flood, соединения |
| **Обновить логи** | `GET /admin/api/logs` | Последние 50 записей из `sec_logs.txt` |
| **Глубокое сканирование** | `GET /admin/api/sys_scan` | Процессы, пользователи, конфигурации |

---

## 🧩 Полный пример интеграции

```python
from AEngineApps.app import App
from AEngineApps.intrusions import IPS, SQLiDetector, XSSDetector, RateLimiter
from sec.os_protect import get_os_protection_module
from sec.net_analyzer import get_network_analyzer
from sec.sys_protect import AdvancedSystemProtection
from sec.dashboard import SecDashboardService

app = App("MySecureApp")

# 1. Ограничение запросов (анти-DDoS L7)
RateLimiter(app, max_requests=100, window=60)

# 2. Предотвращение вторжений (IPS)
ips = IPS(app)
ips.add_detector(SQLiDetector)
ips.add_detector(XSSDetector)

# 3. Защита ОС (автоматический хук)
get_os_protection_module(app)

# 4. Анализ сети (автоматический хук)
get_network_analyzer(app)

# 5. Глубокая защита системы (фоновый сканер)
AdvancedSystemProtection(app)

# 6. Админ-панель
admin = SecDashboardService(prefix="/admin", admin_login="admin", admin_pass="password")
app.register_service(admin)

app.run()
```

**Результат:** Приложение автоматически защищено на уровнях L3-L7 + хоста, с визуальным мониторингом по адресу `/admin`.