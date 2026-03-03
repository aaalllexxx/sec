# Changelog — sec v2.0

## [2.0.2] — 2026-03-03
### Исправления
- В `RateLimiter` (`__intrusions.py`) добавлена легковесная очистка устаревших IP-адресов из словаря для предотвращения утечек памяти при длительной работе

## [2.0.0] — 2026-03-03

### IDS/IPS (__intrusions.py)
- Все детекторы проверяют GET + POST form + JSON body (рекурсивный flatten)
- Новый класс `RateLimiter` — ограничение запросов по IP (HTTP 429)
- `on_trigger()` работает как обычный метод
- Расширены паттерны детекторов:
  - **RCE**: добавлены `eval`, `exec`, `system`, `popen`, `subprocess`
  - **XSS**: добавлены `onerror=`, `onload=`, `onclick=`, `eval(`, `alert(`
  - **SQLi**: добавлены `DROP`, `INSERT`, `UPDATE`, `DELETE`, `CONCAT`, `BENCHMARK`
  - **LFI**: скомпилированный regex, добавлены `%2e%2e`, `%252e`, `%00`, `/etc/`, `/proc/`
- Логирование: HTTP-метод + обрезанный ввод в каждом алерте
- Type hints и docstrings

### Анализатор логов (logs.py)
- Удалён дублирующийся пустой класс `SQLiDetector`
