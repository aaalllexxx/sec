import os
import json
import hashlib
import getpass
import secrets
import sys
import stat
import subprocess

def get_sec_admin_file(project_root):
    """Возвращает путь к файлу данных администратора."""
    sec_dir = os.path.join(os.path.abspath(project_root), ".apm", "sec")
    os.makedirs(sec_dir, exist_ok=True)
    return os.path.join(sec_dir, "sec_admin.json")


try:
    from rich import print
    from rich.prompt import Prompt
except ImportError:
    class Prompt:
        @staticmethod
        def ask(text, default=None, password=False):
            import getpass
            if password:
                return getpass.getpass(f"{text}: ")
            return input(f"{text} [{default}]: ") or default


def is_admin():
    """Проверяет, запущен ли скрипт с правами администратора/root."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False


def _request_elevation():
    """
    Перезапускает текущий скрипт с повышенными привилегиями.
    Windows: UAC через ShellExecute(runas)
    Linux: sudo
    Возвращает True если удалось запустить, False если нет.
    """
    try:
        if os.name == 'nt':
            import ctypes
            # Перезапуск через UAC
            params = ' '.join(f'"{a}"' for a in sys.argv)
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            # ShellExecuteW возвращает > 32 при успехе
            return result > 32
        else:
            # Linux: перезапуск через sudo
            args = ['sudo', sys.executable] + sys.argv
            os.execvp('sudo', args)
            return True  # не дойдёт сюда при успешном execvp
    except Exception as e:
        print(f"[yellow][!] Не удалось запросить повышение привилегий: {e}[/yellow]")
        return False


def _run_as_admin(command, shell=True):
    """
    Выполняет команду с правами администратора.
    Если уже запущены от имени администратора — выполняет напрямую.
    Если нет — использует sudo (Linux) или powershell Start-Process (Windows).
    """
    if is_admin():
        return subprocess.run(command, shell=shell, capture_output=True)
    
    if os.name == 'nt':
        # Windows: через powershell с RunAs 
        if isinstance(command, list):
            cmd_str = ' '.join(command)
        else:
            cmd_str = command
        # Используем powershell Start-Process -Verb RunAs для выполнения команды
        ps_cmd = f'powershell -Command "Start-Process cmd -ArgumentList \'/c {cmd_str}\' -Verb RunAs -Wait"'
        return subprocess.run(ps_cmd, shell=True, capture_output=True)
    else:
        # Linux: через sudo
        if isinstance(command, str):
            return subprocess.run(f'sudo {command}', shell=True, capture_output=True)
        else:
            return subprocess.run(['sudo'] + command, capture_output=True)


def ensure_admin(silent=False):
    """
    Проверяет наличие прав администратора.
    Если прав нет — запрашивает повышение привилегий.
    Возвращает True если права есть или были получены.
    """
    if is_admin():
        return True
    
    if not silent:
        print("[yellow][!] Для полной защиты файлов требуются права администратора.[/yellow]")
    
    if os.name == 'nt':
        print("[yellow][*] Запрос повышения привилегий через UAC...[/yellow]")
    else:
        print("[yellow][*] Запрос прав суперпользователя через sudo...[/yellow]")
    
    return False  # Вызывающий код должен использовать _run_as_admin для отдельных команд


def lock_file(filepath, intense=False):
    """
    Устанавливает расширенную защиту файла:
    - Смена владельца на администратора (root/Administrators)
    - Read-Only (Запрет изменения)
    - Anti-Delete (Запрет удаления) 
    - Hidden/System (На Windows, если intense=True)
    
    Если нет прав администратора — запрашивает через sudo/UAC.
    """
    if not os.path.exists(filepath):
        return
    
    try:
        if os.name == 'nt':
            # Windows: полная защита через ACL
            # 1. Смена владельца на Administrators
            _run_as_admin(f'takeown /f "{filepath}" /a', shell=True)
            
            # 2. Сброс наследования, выдаём полный доступ только Administrators и SYSTEM
            _run_as_admin(
                f'icacls "{filepath}" /inheritance:r '
                f'/grant:r "Administrators":(F) '
                f'/grant:r "SYSTEM":(F)',
                shell=True
            )
            
            # 3. Текущему пользователю — только чтение
            username = os.environ.get("USERNAME", "")
            if username:
                _run_as_admin(
                    f'icacls "{filepath}" /grant:r "{username}":(R)',
                    shell=True
                )
            
            # 4. Атрибуты: Read-Only обязательно, Hidden+System для intense
            flags = "+R"
            if intense:
                flags += " +H +S"
            _run_as_admin(f'attrib {flags} "{filepath}"', shell=True)
            
            # 5. Запрет удаления для Everyone
            _run_as_admin(f'icacls "{filepath}" /deny Everyone:(D,DC)', shell=True)
        
        else:
            # Linux: полная защита через chown + chmod + chattr
            # 1. Смена владельца на root
            _run_as_admin(['chown', 'root:root', filepath], shell=False)
            
            # 2. Права только на чтение (444)
            _run_as_admin(['chmod', '444', filepath], shell=False)
            
            # 3. Immutable bit — запрет удаления и изменения даже для root
            _run_as_admin(['chattr', '+i', filepath], shell=False)
                
    except Exception as e:
        print(f"[yellow][!] Не удалось заблокировать {os.path.basename(filepath)}: {e}[/yellow]")


def unlock_file(filepath):
    """
    Полностью снимает защиту файла:
    - Снимает immutable bit (Linux) / deny ACE (Windows)
    - Восстанавливает стандартные права
    - Возвращает владельца текущему пользователю
    - Файл можно изменять и удалять после этого
    """
    if not os.path.exists(filepath):
        return
    
    try:
        if os.name == 'nt':
            # Windows: полное снятие защиты
            # 1. Забираем владение на текущего пользователя (чтобы можно было менять ACL)
            _run_as_admin(f'takeown /f "{filepath}"', shell=True)
            
            # 2. Снимаем все deny-записи
            _run_as_admin(f'icacls "{filepath}" /remove:d Everyone', shell=True)
            _run_as_admin(f'icacls "{filepath}" /remove:d "Все"', shell=True)
            
            # 3. Выдаём полный доступ текущему пользователю и Everyone(M)
            username = os.environ.get("USERNAME", "")
            if username:
                _run_as_admin(f'icacls "{filepath}" /grant:r "{username}":(F)', shell=True)
            _run_as_admin(f'icacls "{filepath}" /grant:r Everyone:(M)', shell=True)
            
            # 4. Восстанавливаем наследование
            _run_as_admin(f'icacls "{filepath}" /inheritance:e', shell=True)
            
            # 5. Снимаем все атрибуты (Read-Only, Hidden, System)
            _run_as_admin(f'attrib -R -H -S "{filepath}"', shell=True)
        
        else:
            # Linux: полное снятие защиты
            # 1. Снимаем immutable bit (иначе нельзя ничего менять)
            _run_as_admin(['chattr', '-i', filepath], shell=False)
            
            # 2. Возвращаем владельца текущему пользователю
            current_user = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
            if current_user:
                _run_as_admin(['chown', f'{current_user}:{current_user}', filepath], shell=False)
            
            # 3. Стандартные права 644 (rw-r--r--)
            _run_as_admin(['chmod', '644', filepath], shell=False)
                
    except Exception as e:
        print(f"[yellow][!] Не удалось разблокировать {os.path.basename(filepath)}: {e}[/yellow]")


def verify_admin(project_root):
    """Проверяет пароль администратора безопасности."""
    admin_file = get_sec_admin_file(project_root)
    if not os.path.exists(admin_file):
        print("[!] Администратор безопасности не настроен.")
        return False
        
    with open(admin_file, "r") as f:
        data = json.load(f)
        
    # Печатаем через rich если он есть
    print("\n[bold yellow]🔐 Авторизация администратора безопасности[/bold yellow]")
    password = getpass.getpass("Введите пароль администратора: ")
    
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        data["salt"].encode('utf-8'), 
        100000
    )
    
    if key.hex() != data["admin_hash"]:
        print("[bold red][!] Неверный пароль. Доступ запрещен.[/bold red]")
        return False
        
    return True


def create_admin(project_root, password=None):
    """Создает нового администратора безопасности. Возвращает (login, password) или None."""
    admin_file = get_sec_admin_file(project_root)
    
    if os.path.exists(admin_file):
        print("[bold red][!] Администратор безопасности уже существует.[/bold red]")
        overwrite = Prompt.ask("Удалить старого администратора и создать нового? (y/n)", default="n")
        if overwrite.lower() != 'y':
            print("Отмена.")
            return None

    login = "admin"
    if not password:
        print("\n[bold cyan]🔐 Создание администратора безопасности (AEngine sec)[/bold cyan]")
        login = Prompt.ask("Введите логин администратора", default="admin")
        password = getpass.getpass("Введите новый пароль администратора: ")
        confirm = getpass.getpass("Повторите пароль: ")
        
        if password != confirm:
            print("[bold red][!] Пароли не совпадают. Отмена.[/bold red]")
            return None
            
    if len(password) < 8:
        print("[yellow][!] Внимание: пароль слишком короткий. Рекомендуется минимум 8 символов.[/yellow]")
        
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    )
    
    data = {
        "login": login,
        "admin_hash": key.hex(),
        "salt": salt
    }
    
    # Снимаем защиту если файл существует (чтобы перезаписать)
    if os.path.exists(admin_file):
        unlock_file(admin_file)

    with open(admin_file, "w") as f:
        json.dump(data, f)
        
    # Сразу блокируем файл (Read-Only + Hidden + System)
    lock_file(admin_file, intense=True)
    
    print(f"[green][+] Администратор безопасности [bold]{login}[/bold] успешно создан и защищен.[/green]")
    return (login, password)


def check_password(provided_password, stored_hash, salt):
    """Низкоуровневая проверка пароля (без побочных эффектов)."""
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        provided_password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    )
    return key.hex() == stored_hash


def get_or_create_sign_key(project_root):
    """Генерирует или считывает ключ подписи проекта."""
    key_path = os.path.join(project_root, "sec_sign.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
            
    # Генерируем новый 256-битный ключ
    print("[*] Генерация нового случайного ключа подписи sec_sign.key...")
    new_key = secrets.token_bytes(32)
    with open(key_path, "wb") as f:
        f.write(new_key)
        
    print("[green][+] Ключ подписи создан. Будет защищён при подписании проекта.[/green]")
    return new_key
