# Changelog (sec)

## [2.6.0] - 2026-03-10
### Added
- **Cross-Platform Protection**: Unified `auth.py` with `lock_file`/`unlock_file` supporting `attrib` (Windows) and `chmod` (POSIX).
- **Advanced Attributes**: `sec_admin.json` is now protected with Hidden and System attributes on Windows.
- **Improved CLI**: Switched all commands to underscored names (`add_admin`, `sign`, `unsign`) for consistency.
- **Interactive Mode**: Fixed `add_admin` initialization when called without direct arguments via APM.

### Changed
- **Unified Security Base**: All auth checks, key management, and file protection concentrated in `sec/auth.py`.
- **Enhanced Deployment**: `apm sec init` now correctly manages permissions during template installation.
- **Dashboard Support**: Added CSP headers documentation and automated configuration for Chart.js and Fonts.

## [2.5.0] - 2026-03-03
### Added
- **Advanced Traffic Analysis**: Signature-based detection for known CVEs (Log4Shell, etc.) and Rule-based custom blocking via `SignatureDetector` and `RuleDetector`.
- **Anomaly Detection**: Traffic baselining with spike detection to catch DoS/DDoS behavior in `NetworkAnalyzer`.
- **Stored XSS Protection**: Background scanner (`_check_stored_xss` in `AdvancedSystemProtection`) to find persistent payloads in databases.
- **Security Headers Integration**: `enable_cors` and `enable_csp` were migrated from the core AEngineApps into `sec.__sys_protect` for centralized security policies.

## [2.4.0] - 2026-03-03
### Added
- **Major Dashboard Overhaul**: Switched to a premium sidebar-based layout with deep Glassmorphism effects.
- **Protection Gauge**: Integrated a real-time SVG health gauge on the Overview page.
- **Interactive Metrics**: Added tooltips and trend indicators for CPU, RAM, and Security status.
- **Global Settings**: Refresh rate control is now persistent in the sidebar.

### Fixed
- **Dashboard Freeze**: Fixed critical JavaScript error when accessing Network API properties (`TypeError: data.network.issues`).
- **Data Robustness**: Added defensive checks for all API responses to ensure UI stability.
- **Scanner UI**: Fixed broken property access in "Deep Scan" results visualization.

## [2.3.0] - 2026-03-03
### Added
- **Credentials Management**: `apm sec init` now prompts for `admin_login` and `admin_password`.
- **Global Config**: Credentials saved to `AEngineApps/sec_config.py`, accessible across modules.
- **Uninstaller**: New `apm sec remove` command to cleanly delete security components.
- **Selective Removal**: Support for `--modules` flag in removal command.

### Changed
- **Architecture Refactoring**: Dashboard HTML templates moved from Python code to separate `.html` files (`templates/sec/`).
- **Improved Initializer**: Automated template deployment to the project's `templates` directory.
- **Dashboard Logic**: Switched to `render_template` for better maintainability and cleaner code.

## [2.2.0] — 2026-03-03

### CLI Инициализатор (`init.py`)
- Новая команда `apm sec init` — устанавливает все модули безопасности в проект одной командой.
- `apm sec init --modules intrusion logs` — установка только выбранных модулей.
- `apm sec init --list` — вывод списка доступных модулей с описаниями.

### Продвинутая Защита Системы (`sys_protect.py`)
- Новый класс `AdvancedSystemProtection(app)` — подключается одной строкой и автоматически запускает фоновое сканирование:
  - **Процессы**: поиск майнеров (`xmrig`, `cpuminer`), reverse-shell утилит (`nc`, `ncat`, `socat`), инструментов взлома (`mimikatz`, `hydra`, `sqlmap`, `nmap`) и процессов из временных директорий (`/tmp/`, `%TEMP%`).
  - **Конфигурации**: оповещение о `debug=True`, слабых `secret_key`, CORS `*`, запуске от имени Administrator/root.
  - **Пользователи ОС**: мониторинг терминальных сессий и подключений одного пользователя с нескольких хостов.
  - **Ресурсы**: CPU/RAM/Disk отслеживание с настраиваемыми порогами.
- Колбэки `.on_alert(callback)` для реакции на угрозы.
- Фоновый daemon-поток с настраиваемым интервалом (по умолчанию 30 сек).

### Локальная Кластеризация (`auto_cluster.py`)
- Новый класс `LocalCluster(app, ports=[5000, 5001])` — кластер на одном сервере через `multiprocessing`.
- Первый порт = Active (Master), остальные = Passive (Slave).
- Встроенный Watchdog: при падении Master автоматический failover на первый живой Slave.
- Автоматический перезапуск упавших Slave-нод.

### Дашборд (`dashboard.py`)
- Новая карточка «Глубокое сканирование системы» с AJAX-кнопкой и эндпоинтом `/api/sys_scan`.

## [2.1.0] — 2026-03-03

### Глобальное обновление: Защита ОС и Сети, Отказоустойчивость
- Добавлен независимый модуль `os_protect.py` для кроссплатформенного логгирования ресурсоемкости системы и обнаружения запуска с повышенными привилегиями (root/Admin).
- Добавлен модуль `net_analyzer.py` для обнаружения SYN-flood атак и аномального количества подключений с одного IP-адреса на основе анализа сетевых таблиц.
- Добавлен подмодуль `cluster.py`, позволяющий создавать Active-Passive кластерные решения (master-slave роли с heartbeat пульсом) с функцией автоматической синхронизации исходного кода проекта по TCP при запуске Slave-нод.
- Добавлен микросервис-админка `dashboard.py` (`SecDashboardService`) для интерактивного просмотра системных логов, статуса ОС, сетевого анализатора и инцидентов безопасности.


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
