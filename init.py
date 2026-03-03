"""
sec/init.py — Инициализатор модулей безопасности.

Команды:
    apm sec init                          — установить все модули безопасности
    apm sec init --modules intrusion logs — установить только указанные модули
    apm sec init --list                   — показать доступные модули
"""
from rich import print
import os

base = os.sep.join(__file__.split(os.sep)[:-1])

# ─── Маппинг: имя модуля -> список файлов для объединения в один целевой ───
# "sources" — файлы из sec/, которые будут объединены в один self-contained файл
# "target"  — куда записать результат
MODULE_MAP = {
    "intrusion": {
        "sources": ["__intrusions.py"],
        "target": "AEngineApps/intrusions.py",
        "description": "IDS/IPS и детекторы атак (SQLi, XSS, RCE, LFI, RateLimiter)",
    },
    "logs": {
        "sources": ["__logging.py"],
        "target": "AEngineApps/logging.py",
        "description": "Логирование запросов (Logger)",
    },
    "os_protect": {
        "sources": ["__os_protect.py", "os_protect.py"],
        "target": "AEngineApps/os_protect.py",
        "description": "Защита ОС: контроль CPU/RAM, проверка привилегий",
    },
    "net_analyzer": {
        "sources": ["__net_analyzer.py", "net_analyzer.py"],
        "target": "AEngineApps/net_analyzer.py",
        "description": "Анализ сетевого трафика: SYN Flood, аномальные IP",
    },
    "sys_protect": {
        "sources": ["__sys_protect.py", "sys_protect.py"],
        "target": "AEngineApps/sys_protect.py",
        "description": "Продвинутая защита: сканер процессов, конфигураций, пользователей",
    },
    "dashboard": {
        "sources": ["dashboard.py"],
        "target": "AEngineApps/dashboard.py",
        "description": "Админ-панель безопасности с авторизацией и AJAX-сканированием",
    },
    "cluster": {
        "sources": ["__cluster.py", "cluster.py"],
        "target": "AEngineApps/cluster.py",
        "description": "Active-Passive кластеризация (межсерверная, Heartbeat + File Sync)",
    },
    "auto_cluster": {
        "sources": ["__auto_cluster.py", "auto_cluster.py"],
        "target": "AEngineApps/auto_cluster.py",
        "description": "Локальная кластеризация (один сервер, multiprocessing)",
    },
}

ALL_MODULES = list(MODULE_MAP.keys())

# Строки-импорты из фасадных файлов, которые ссылаются на приватные __файлы.
# Их нужно убрать при слиянии, т.к. класс уже будет в том же файле.
INTERNAL_IMPORT_PREFIXES = [
    "from .__",
    "from __",
]


def _read_source(filename: str) -> str:
    """Читает исходный файл из папки sec/."""
    path = os.path.join(base, filename)
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _merge_sources(sources: list) -> str:
    """
    Объединяет несколько файлов в один self-contained модуль.
    Из фасадных файлов убираются строки `from .__xxx import ...`,
    т.к. реализация уже включена выше.
    """
    parts = []
    for i, src_file in enumerate(sources):
        content = _read_source(src_file)
        if not content:
            continue

        if i > 0:
            # Это фасадный файл — убираем внутренние импорты
            lines = content.split("\n")
            filtered = []
            for line in lines:
                stripped = line.strip()
                if any(stripped.startswith(prefix) for prefix in INTERNAL_IMPORT_PREFIXES):
                    continue  # Пропускаем `from .__os_protect import OSProtection`
                filtered.append(line)
            content = "\n".join(filtered)

        parts.append(content.rstrip())

    return "\n\n".join(parts) + "\n"


def _install_module(name: str) -> bool:
    """Устанавливает один модуль. Возвращает True если успешно."""
    if name not in MODULE_MAP:
        print(f"  [red]✗[/red] Неизвестный модуль: [bold]{name}[/bold]")
        print(f"    Доступные: {', '.join(ALL_MODULES)}")
        return False

    info = MODULE_MAP[name]
    target_path = info["target"]

    # Проверяем директорию назначения
    target_dir = os.path.dirname(target_path)
    if target_dir and not os.path.exists(target_dir):
        print(f"  [yellow]![/yellow] Директория {target_dir} не найдена, пропускаем {name}")
        return False

    # Объединяем исходные файлы
    merged = _merge_sources(info["sources"])
    if not merged.strip():
        print(f"  [red]✗[/red] Не удалось прочитать исходные файлы для {name}")
        return False

    # Записываем
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(merged)

    print(f"  [green]✓[/green] [bold]{name}[/bold] -> {target_path}")
    print(f"    {info['description']}")
    return True


def _init_all():
    """Устанавливает все модули безопасности."""
    print("\n[bold cyan]🛡️  Инициализация всех модулей безопасности sec[/bold cyan]\n")
    installed = 0
    for name in ALL_MODULES:
        if _install_module(name):
            installed += 1
    print(f"\n[green bold]Готово![/green bold] Установлено модулей: {installed}/{len(ALL_MODULES)}")
    _print_usage_hint()


def _init_selected(modules: list):
    """Устанавливает только выбранные модули."""
    print(f"\n[bold cyan]🛡️  Инициализация модулей: {', '.join(modules)}[/bold cyan]\n")
    installed = 0
    for name in modules:
        if _install_module(name):
            installed += 1
    print(f"\n[green bold]Готово![/green bold] Установлено модулей: {installed}/{len(modules)}")
    _print_usage_hint()


def _print_usage_hint():
    """Выводит подсказку по использованию."""
    print("""
[dim]Пример подключения в main.py:

  from AEngineApps.intrusions import IPS, SQLiDetector
  from AEngineApps.os_protect import get_os_protection_module
  from AEngineApps.net_analyzer import get_network_analyzer
  from AEngineApps.sys_protect import AdvancedSystemProtection

  app = App()
  IPS(app).add_detector(SQLiDetector)
  get_os_protection_module(app)
  get_network_analyzer(app)
  AdvancedSystemProtection(app)
[/dim]""")


def _print_help():
    """Справка."""
    print("""
[bold cyan]🛡️  sec init — Инициализатор модулей безопасности[/bold cyan]

[bold]Использование:[/bold]
  apm sec init                                  Установить все модули
  apm sec init --modules intrusion logs         Установить только указанные
  apm sec init --list                           Показать список доступных модулей

[bold]Доступные модули:[/bold]""")
    for name, info in MODULE_MAP.items():
        print(f"  [green]{name:15s}[/green] {info['description']}")


def run(*args, **kwargs):
    """Точка входа для apm CLI."""
    arg = kwargs.get("args", [])

    if "--help" in arg or "-h" in arg:
        _print_help()
        return

    if "--list" in arg:
        print("\n[bold]Доступные модули:[/bold]")
        for name, info in MODULE_MAP.items():
            print(f"  [green]{name:15s}[/green] {info['description']}")
        return

    if "--modules" in arg:
        idx = arg.index("--modules")
        modules = []
        for item in arg[idx + 1:]:
            if item.startswith("--"):
                break
            modules.append(item)
        if not modules:
            print("[red]Ошибка: после --modules не указаны модули[/red]")
            _print_help()
            return
        _init_selected(modules)
    else:
        _init_all()
