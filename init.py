from rich import print
from rich.prompt import Prompt
import os
import shutil

base = os.sep.join(__file__.split(os.sep)[:-1])

# ─── Маппинг: имя модуля -> список файлов для объединения в один целевой ───
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
        "description": "Админ-панель безопасности с авторизацией (требует шаблоны и конфиг)",
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

INTERNAL_IMPORT_PREFIXES = [
    "from .__",
    "from __",
]


def _read_source(filename: str) -> str:
    path = os.path.join(base, filename)
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _merge_sources(sources: list) -> str:
    parts = []
    for i, src_file in enumerate(sources):
        content = _read_source(src_file)
        if not content:
            continue

        if i > 0:
            lines = content.split("\n")
            filtered = []
            for line in lines:
                stripped = line.strip()
                if any(stripped.startswith(prefix) for prefix in INTERNAL_IMPORT_PREFIXES):
                    continue
                filtered.append(line)
            content = "\n".join(filtered)

        parts.append(content.rstrip())

    return "\n\n".join(parts) + "\n"


def _setup_credentials(base_dir):
    """Запрашивает логин/пароль и создает AEngineApps/sec_config.py"""
    print("\n[bold yellow]🔐 Настройка учетных данных администратора безопасности[/bold yellow]")
    login = Prompt.ask("Введите логиn админа", default="admin")
    password = Prompt.ask("Введите пароль админа", default="admin", password=True)
    
    config_content = f"""# Автоматически сгенерированный конфиг безопасности sec
ADMIN_LOGIN = "{login}"
ADMIN_PASS = "{password}"
"""
    config_path = os.path.join(base_dir, "AEngineApps", "sec_config.py")
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(config_content)
    print(f"  [green]✓[/green] Конфигурация сохранена в {config_path}")


def _copy_templates(base_dir):
    """Копирует шаблоны в директорию проекта templates/sec/"""
    src_templates = os.path.join(base, "templates")
    if not os.path.exists(src_templates):
        return
        
    target_templates = os.path.join(base_dir, "templates", "sec")
    if not os.path.exists(target_templates):
        os.makedirs(target_templates, exist_ok=True)
        
    for item in os.listdir(src_templates):
        s = os.path.join(src_templates, item)
        d = os.path.join(target_templates, item)
        shutil.copy2(s, d)
        print(f"  [green]✓[/green] Шаблон {item} -> {d}")


def _install_module(base_dir, name: str) -> bool:
    if name not in MODULE_MAP:
        return False

    info = MODULE_MAP[name]
    target_path = os.path.join(base_dir, info["target"])

    target_dir = os.path.dirname(target_path)
    if target_dir and not os.path.exists(target_dir):
        print(f"  [yellow]![/yellow] Директория {target_dir} не найдена, пропускаем {name}")
        return False

    merged = _merge_sources(info["sources"])
    if not merged.strip():
        return False

    with open(target_path, "w", encoding="utf-8") as f:
        f.write(merged)

    print(f"  [green]✓[/green] [bold]{name}[/bold] -> {info['target']}")
    return True


def run(*args, **kwargs):
    arg = kwargs.get("args", [])
    # Приоритет за CWD, так как apm может передавать свой путь установки
    base_dir = kwargs.get("base_dir")
    cwd = os.getcwd()
    
    if os.path.exists(os.path.join(cwd, "AEngineApps")):
        base_dir = cwd
    elif not base_dir or not os.path.exists(os.path.join(base_dir, "AEngineApps")):
        base_dir = cwd

    if "--help" in arg or "-h" in arg:
        _print_help()
        return

    print(f"\n[bold cyan]🛡️  Инициализация модулей безопасности sec (в {base_dir})[/bold cyan]\n")

    # Настройка общих параметров (всегда при полной установке или если выбран dashboard)
    if "--modules" not in arg or "dashboard" in arg:
        _setup_credentials(base_dir)
        _copy_templates(base_dir)

    target_modules = ALL_MODULES
    if "--modules" in arg:
        idx = arg.index("--modules")
        target_modules = []
        for item in arg[idx + 1:]:
            if item.startswith("--"):
                break
            target_modules.append(item)

    installed = 0
    for name in target_modules:
        if _install_module(base_dir, name):
            installed += 1
            
    print(f"\n[green bold]Готово![/green bold] Установлено модулей: {installed}")


def _print_help():
    print("""
[bold cyan]🛡️  sec init — Инициализатор модулей безопасности[/bold cyan]

[bold]Использование:[/bold]
  apm sec init                                  Установить все модули
  apm sec init --modules intrusion logs         Установить только указанные
  apm sec init --list                           Показать список доступных модулей

[bold]Доступные модули:[/bold]""")
    for name, info in MODULE_MAP.items():
        print(f"  [green]{name:15s}[/green] {info['description']}")
