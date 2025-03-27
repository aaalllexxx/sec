# Пакет sec для AEngineApps

Этот модуль содержит скрипты для обеспечения информационной безопасности приложений AEngineApps

## Модули

> logs

---

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

запускать необходимо из корневой директории проекта

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
from AEngineApps.intrusion import IDS,  XSSDetector
app = App()
ids = IDS(app)
ids.add_detector(XSSDetector)
```
На этом этапе добавляется IDS с единственным детектором XSSDetector
