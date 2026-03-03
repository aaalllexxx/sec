"""
sec/init.py — Инициализатор модулей безопасности.

Команды:
    apm sec init                          — установить все модули безопасности
    apm sec init --modules intrusion logs — установить только указанные модули

Доступные модули:
    intrusion   — IDS/IPS и детекторы атак
    logs        — Логирование и анализатор логов
    os_protect  — Защита ОС (CPU/RAM/привилегии)
    net_analyzer— Анализ сетевого трафика (SYN Flood)
    sys_protect — Продвинутая защита системы (процессы, конфиги, пользователи)
    dashboard   — Админ-панель безопасности (SecDashboardService)
    cluster     — Active-Passive кластеризация (межсерверная)
    auto_cluster— Локальная кластеризация на одном сервере
"""
from rich import print
import os
import shutil

base = os.sep.join(__file__.split(os.sep)[:-1])

# ─── Маппинг модулей: имя -> (исходный файл внутри sec, целевой файл в AEngineApps или корне) ───
MODULE_MAP = {
    "intrusion": {
        "source": "__intrusions.py",
        "target": "AEngineApps/intrusions.py",
        "description": "IDS/IPS и детекторы атак (SQLi, XSS, RCE, LFI, RateLimiter)",
    },
    "logs": {
        "source": "__logging.py",
        "target": "AEngineApps/logging.py",
        "description": "Логирование запросов (Logger)",
    },
    "os_protect": {
        "source": "__os_protect.py",
        "target": "AEngineApps/os_protect.py",
        "facade": "os_protect.py",
        "facade_target": "AEngineApps/os_protect_facade.py",
        "description": "Защита ОС: контроль CPU/RAM, проверка привилегий",
    },
    "net_analyzer": {
        "source": "__net_analyzer.py",
        "target": "AEngineApps/net_analyzer.py",
        "facade": "net_analyzer.py",
        "facade_target": "AEngineApps/net_analyzer_facade.py",
        "description": "Анализ сетевого трафика: SYN Flood, аномальные IP",
    },
    "sys_protect": {
        "source": "__sys_protect.py",
        "target": "AEngineApps/sys_protect.py",
        "facade": "sys_protect.py",
        "facade_target": "AEngineApps/sys_protect_facade.py",
        "description": "Продвинутая защита: сканер процессов, конфигураций, пользователей",
    },
    "dashboard": {
        "source": "dashboard.py",
        "target": "AEngineApps/sec_dashboard.py",
        "description": "Админ-панель безопасности с авторизацией и AJAX-сканированием",
    },
    "cluster": {
        "source": "__cluster.py",
        "target": "AEngineApps/cluster.py",
        "facade": "cluster.py",
        "facade_target": "AEngineApps/cluster_facade.py",
        "description": "Active-Passive кластеризация (межсерверная, Heartbeat + File Sync)",
    },
    "auto_cluster": {
        "source": "__auto_cluster.py",
        "target": "AEngineApps/auto_cluster.py",
        "facade": "auto_cluster.py",
        "facade_target": "AEngineApps/auto_cluster_facade.py",
        "description": "Локальная кластеризация (один сервер, multiprocessing)",
    },
}

ALL_MODULES = list(MODULE_MAP.keys())


def _install_module(name: str) -> bool:
    """Устанавливает один модуль. Возвращает True если успешно."""
    if name not in MODULE_MAP:
        print(f"  [red]✗[/red] Неизвестный модуль: [bold]{name}[/bold]")
        print(f"    Доступные: {', '.join(ALL_MODULES)}")
        return False

    info = MODULE_MAP[name]
    source_path = os.path.join(base, info["source"])
    target_path = info["target"]

    if not os.path.exists(source_path):
        print(f"  [red]✗[/red] Исходный файл не найден: {source_path}")
        return False

    # Создаём директорию назначения если нужно
    target_dir = os.path.dirname(target_path)
    if target_dir and not os.path.exists(target_dir):
        print(f"  [yellow]![/yellow] Директория {target_dir} не найдена, пропускаем {name}")
        return False

    # Копируем основной файл
    shutil.copy2(source_path, target_path)
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
    """Выводит подсказку по использованию установленных модулей."""
    print("""
[dim]Пример подключения в main.py:

  from AEngineApps.app import App
  from AEngineApps.intrusions import IPS, SQLiDetector
  from sec.os_protect import get_os_protection_module
  from sec.net_analyzer import get_network_analyzer
  from sec.sys_protect import AdvancedSystemProtection

  app = App()
  IPS(app).add_detector(SQLiDetector)        # IDS/IPS
  get_os_protection_module(app)              # Защита ОС
  get_network_analyzer(app)                  # Анализ сети
  AdvancedSystemProtection(app)              # Глубокая защита
[/dim]""")


def _print_help():
    """Выводит справку по команде."""
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
        # Все аргументы после --modules (до следующего флага) = имена модулей
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
