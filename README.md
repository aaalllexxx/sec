# Модуль sec (AEngine v2.0)

Этот модуль содержит инструменты для обеспечения информационной безопасности приложений AEngineApps (IDS/IPS, Rate Limiting, Logging).

## 🚀 Установка

Установка в текущий проект:
```sh
apm install https://github.com/aaalllexxx/sec
```

Глобальная установка:
```sh
apm install -g https://github.com/aaalllexxx/sec
```

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

1. **`RCEDetector`** — Обнаруживает Remote Code Execution (запуск системных команд: *eval, exec, system, bash*).
2. **`LFIDetector`** — Обнаруживает Local/Remote File Inclusion (чтение файловой системы: *../, /etc/passwd, %00*).
3. **`SQLiDetector`** — Обнаруживает SQL-иньекции (ключевые слова и спецсимволы: *OR, SELECT, DROP, '--, /* *).
4. **`XSSDetector`** — Обнаруживает межсайтовый скриптинг (теги и эвенты: *<script>, javascript:, onerror=, onload=*).

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