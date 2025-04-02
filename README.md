# Пакет sec для AEngineApps

Этот модуль содержит скрипты для обеспечения информационной безопасности приложений AEngineApps

## Установка

Локальная установка в проект:
```sh
$ apm install https://github.com/aaalllexxx/sec
```

Глобальная установка:
```sh
$ apm install -g https://github.com/aaalllexxx/sec
```

## Модули

> logs

> intrusion

## Модуль logs
```sh
$ apm sec logs
```
> Модуль logs позволяет облегчить работу с логами проекта.

### logs init
```sh
$ apm sec logs init
```

Скрипт, позволяющий инициализировать файл loggging в модуле AEngineApps.

Должен запускаться в корневой директрии проекта.

После выполнения создаёт в директории AEngineApps файл logging.py, который содержит класс Logger.

#### Logger
Logger - класс модуля AEngineApps.logging

При инициализации требует объекта приложения AEngine

Пример

```py
from AEngineApps.app import App
from AEngineApps.logging import Logger

app = App()
logger = Logger(app)
```

На этом этапе класс автоматически настраивает логирование приложения (только для формата web)

### logs analyze
```sh
$ apm sec logs analyze
```

Скрипт, позволяющий проанализировать логи приложения на наличие известных уязвимостей:

1) XSS
2) RCE
3) LFI
4) SQL injection

Запускать необходимо из корневой директории проекта.

Чтобы указать свой формат логов используйте ключ --template, после чего укажите формат логов со всеми знаками.
Переменные параметры:

    Дата:
        %{Y} - Год
        %{m} - Месяц
        %{D} - День

    Время:
        %{H} - Часы
        %{M} - Минуты
        %{S} - Секунды
        %{MS} - Миллисекунды
    
    Запрос:
        %{level} - Тип логов (Info, Warning, Critical и т.д.)
        %{ip} - IP адрес
        %{method} - HTTP метод
        %{endpoint} - Путь запроса
        %{proto} - Протокол запроса
        %{code} - Код ответа



## Модуль intrusion
```sh
$ apm sec intrusion
```
> Позволяет интегрировать IDS/IPS в веб-приложение

### intrusion init
```sh
$ apm sec intrusion init
```
Скрит, позволяющий инициализировать файл intrusions.py в модуле AEngineApps. 

Должен запускаться в корневой директрии проекта.

После выполнения создаёт в директории AEngineApps файл intrusions.py, который содержит классы IDS и IPS, а также классы детекторов.

#### IDS
IDS - класс модуля AEngineApps.intrusions, который позволяет определять попытки вторжения и выполнять действия при их обнаружение.

Позволяет определять 4 известных типа атак:

1) XSS
2) RCE
3) LFI
4) SQL injection

Чтобы добавить IDS в приложение:

```py
from AEngineApps.app import App
from AEngineApps.intrusion import IDS, XSSDetector

app = App()
ids = IDS(app)
ids.add_detector(XSSDetector)
```
На этом этапе добавляется IDS с единственным детектором XSSDetector

Чтобы добавить действие при срабатывании:

```py
...

def on_detection():
    print("detected intrusion")

ids.on_trigger(on_detection)
```

#### IPS
IPS - класс модуля AEngineApps.intrusions, который позволяет определять попытки вторжения и прерывать их при обнаружении.

Позволяет определять 4 известных типа атак:

1) XSS
2) RCE
3) LFI
4) SQL injection

Чтобы добавить IPS в приложение:

```py
from AEngineApps.app import App
from AEngineApps.intrusion import IDS, XSSDetector

app = App()
ips = IPS(app)
ips.add_detector(XSSDetector)
```
На этом этапе добавляется IPS с единственным детектором XSSDetector

### Классы детекторов

Доступные детекторы:

> RCEDetector

> LFIDetector

> SQLiDetector

> XSSDetector

А также для создания собственных детекторов доступна абстракция:

> BaseDetector

Детектор должен наследоваться от BaseDetector и обязательно содержать в себе метод run. 

Дополнительные методы:

> detector.log(message) - отправка критического лога в приложение

> detector.trigger_response() - метод, который выполняется при срабатывании детектора. Если нужно персональное поведение под каждый вид атаки - можно переопределить этот метод

#### Пример

```py
from AEngineApps.intrusions import BaseDetector
from urllib.parse import unquote

class HWDetector(BaseDetector):
    def run(self):
        for arg in request.args.values():
            if "hello world" in unquote(arg):
                self.log(f"DETECTED HW: {request.full_path}")
                self.trigger_response()

    def trigger_response(self):
        print("О боже, какой ужас")
```