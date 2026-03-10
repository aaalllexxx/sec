from rich import print
from rich.prompt import Prompt
import os
import shutil
import sys
try:
    from . import auth
except ImportError:
    import auth

base = os.sep.join(__file__.split(os.sep)[:-1])

# ─── Маппинг: имя модуля -> список файлов для объединения в один целевой ───
MODULE_MAP = {
    "intrusion": {
        "sources": ["intrusions.py"],
        "target": "AEngineApps/intrusions.py",
        "extra_files": [
            {"src": "signatures_db.json", "dst": "AEngineApps/signatures_db.json"}
        ],
        "description": "IDS/IPS и детекторы атак (SQLi, XSS, RCE, LFI, RateLimiter, открытая база сигнатур)",
    },
    "logs": {
        "sources": ["logging.py"],
        "target": "AEngineApps/logging.py",
        "description": "Логирование запросов (Logger)",
    },
    "code_signer": {
        "sources": ["code_signer.py"],
        "target": "AEngineApps/code_signer.py",
        "description": "Проверка целостности кода и защита от инъекций",
    },
    "os_protect": {
        "sources": ["os_protect.py"],
        "target": "AEngineApps/os_protect.py",
        "description": "Защита ОС: контроль CPU/RAM, проверка привилегий",
    },
    "net_analyzer": {
        "sources": ["net_analyzer.py"],
        "target": "AEngineApps/net_analyzer.py",
        "description": "Анализ сетевого трафика: SYN Flood, аномальные IP",
    },
    "sys_protect": {
        "sources": ["sys_protect.py"],
        "target": "AEngineApps/sys_protect.py",
        "description": "Продвинутая защита: сканер процессов, конфигураций, пользователей",
    },
    "dashboard": {
        "sources": ["dashboard.py"],
        "target": "AEngineApps/dashboard.py",
        "description": "Админ-панель безопасности с авторизацией (требует шаблоны и конфиг)",
    },
    "cluster": {
        "sources": ["cluster.py"],
        "target": "AEngineApps/cluster.py",
        "description": "Active-Passive кластеризация (межсерверная, Heartbeat + File Sync)",
    },
    "auto_cluster": {
        "sources": ["auto_cluster.py"],
        "target": "AEngineApps/auto_cluster.py",
        "description": "Локальная кластеризация (один сервер, multiprocessing)",
    },
    "unsign": {
        "sources": ["unsign.py"],
        "target": "AEngineApps/unsign.py",
        "description": "Снятие электронной подписи и разблокировка файлов",
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


def _setup_credentials(base_dir, login=None, password=None):
    """Запрашивает логин/пароль и создает AEngineApps/sec_config.py (Кроссплатформенно)"""
    if not login or not password:
        print("\n[bold yellow]🔐 Настройка учетных данных администратора безопасности[/bold yellow]")
        login = Prompt.ask("Введите логин админа", default="admin")
        
        # Кроссплатформенный ввод пароля без эха (рекомендуется rich.prompt или getpass)
        password = Prompt.ask("Введите пароль админа", password=True)
    
    if not password:
        password = "admin"
    
    config_content = f"""# Автоматически сгенерированный конфиг безопасности sec
# Этот файл защищен подписью и атрибутом Read-Only
ADMIN_LOGIN = "{login}"
ADMIN_PASS = "{password}"
"""
    config_path = os.path.join(base_dir, "AEngineApps", "sec_config.py")
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    # Снимаем защиту если файл существует (атрибут +R)
    if os.path.exists(config_path):
        auth.unlock_file(config_path)

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
        if os.path.isfile(s):
            shutil.copy2(s, d)
            print(f"  [green]✓[/green] Шаблон {item} -> {d}")
        elif os.path.isdir(s) and item != "sec":
            # Если есть вложенные папки (кроме самой 'sec'), копируем их рекурсивно
            if not os.path.exists(d):
                os.makedirs(d, exist_ok=True)
            for subitem in os.listdir(s):
                shutil.copy2(os.path.join(s, subitem), os.path.join(d, subitem))
            print(f"  [green]✓[/green] Папка шаблонов {item} скопирована")


def _install_module(base_dir, name: str) -> bool:
    if name not in MODULE_MAP:
        return False

    info = MODULE_MAP[name]
    target_path = os.path.join(base_dir, info["target"])

    target_dir = os.path.dirname(target_path)
    if target_dir and not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)

    merged = _merge_sources(info["sources"])
    if not merged.strip():
        return False

    # Снимаем защиту если файл существует и защищен (Read-Only)
    if os.path.exists(target_path):
        auth.unlock_file(target_path)

    with open(target_path, "w", encoding="utf-8") as f:
        f.write(merged)

    # Копируем дополнительные файлы
    for extra in info.get("extra_files", []):
        src_path = os.path.join(base, extra["src"])
        dst_path = os.path.join(base_dir, extra["dst"])
        if os.path.exists(src_path):
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            # Снимаем защиту и здесь
            if os.path.exists(dst_path):
                auth.unlock_file(dst_path)
            shutil.copy2(src_path, dst_path)

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

    # 1. Проверка/Создание администратора безопасности
    admin_file = auth.get_sec_admin_file(base_dir)
    admin_creds = None
    
    if os.path.exists(admin_file):
        print("[bold cyan][*] Для изменения конфигурации требуется авторизация администратора.[/bold cyan]")
        if not auth.verify_admin(base_dir):
            print("[bold red]Ошибка: Авторизация не удалась. Прерывание.[/bold red]")
            return
    else:
        print("[bold yellow][*] Администратор безопасности не найден. Пожалуйста, настройте новый аккаунт.[/bold yellow]")
        admin_creds = auth.create_admin(base_dir)
        if not admin_creds:
            return

    # Настройка общих параметров (всегда при полной установке или если выбран dashboard)
    if "--modules" not in arg or "dashboard" in arg:
        if admin_creds:
             print("[bold green][*] Автоматическое применение учетных данных администратора для панели Dashboard.[/bold green]")
             _setup_credentials(base_dir, login=admin_creds[0], password=admin_creds[1])
        else:
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
  apm sec add_admin                             Добавить администратора безопасности
  apm sec sign                                  Подписать проект
  apm sec unsign                                Снять подпись

[bold]Доступные модули:[/bold]""")
    for name, info in MODULE_MAP.items():
        # Используем os.path.basename для корректного отображения
        target_name = os.path.basename(info['target'])
        print(f"  [green]{name:15s}[/green] {info['description']} (-> {target_name})")
