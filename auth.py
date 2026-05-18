import os
import json
import hashlib
import getpass
import secrets
import sys

def get_sec_admin_file(project_root):
    """Возвращает путь к файлу данных администратора."""
    sec_dir = os.path.join(os.path.abspath(project_root), ".apm", "sec")
    os.makedirs(sec_dir, exist_ok=True)
    return os.path.join(sec_dir, "sec_admin.json")

import stat
import subprocess

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

def lock_file(filepath, intense=False):
    """
    Устанавливает расширенную защиту:
    - Смена владельца на администратора (root/Admin)
    - Read-Only (Запрет изменения)
    - Anti-Delete (Запрет удаления)
    - Hidden/System (На Windows)
    """
    if not os.path.exists(filepath):
        return
    try:
        if os.name == 'nt':
            # Windows: Смена владельца на Администраторов и настройка ACL
            subprocess.run(f'icacls "{filepath}" /setowner "Administrators"', shell=True, capture_output=True)
            subprocess.run(f'icacls "{filepath}" /inheritance:r /grant:r "Administrators":(F) /grant:r "SYSTEM":(F)', shell=True, capture_output=True)
            
            flags = "+R"
            if intense:
                flags += " +H +S"
            subprocess.run(f'attrib {flags} "{filepath}"', shell=True, capture_output=True)
            subprocess.run(f'icacls "{filepath}" /deny Everyone:(D)', shell=True, capture_output=True)
        
        else:
            # Linux: Смена владельца на root и установка прав
            if is_admin():
                subprocess.run(['chown', 'root:root', filepath], capture_output=True)
            
            os.chmod(filepath, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH) # 444
            
            try:
                subprocess.run(['chattr', '+i', filepath], capture_output=True)
            except Exception:
                pass
                
    except Exception as e:
        print(f"[yellow]![/yellow] Не удалось заблокировать {os.path.basename(filepath)}: {e}")

def unlock_file(filepath):
    """Снимает расширенную защиту файла."""
    if not os.path.exists(filepath):
        return
    try:
        if os.name == 'nt':
            # Windows
            subprocess.run(f'icacls "{filepath}" /remove:d Everyone', shell=True, capture_output=True)
            subprocess.run(f'icacls "{filepath}" /grant:r Everyone:(M)', shell=True, capture_output=True)
            subprocess.run(f'attrib -R -H -S "{filepath}"', shell=True, capture_output=True)
        else:
            # Linux
            try:
                subprocess.run(['chattr', '-i', filepath], capture_output=True)
            except Exception:
                pass
            
            if is_admin():
                os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH) # 644
            else:
                subprocess.run(['chmod', '644', filepath], capture_output=True)
                
    except Exception as e:
        print(f"[yellow]![/yellow] Не удалось разблокировать {os.path.basename(filepath)}: {e}")

def verify_admin(project_root):
    """Проверяет пароль администратора безопасности (интерактивно)."""
    password = getpass.getpass("Введите пароль администратора: ")
    return verify_password(project_root, password)

def verify_password(project_root, password):
    """Проверяет пароль администратора безопасности (неинтерактивно)."""
    admin_file = get_sec_admin_file(project_root)
    if not os.path.exists(admin_file):
        return False
        
    try:
        with open(admin_file, "r") as f:
            data = json.load(f)
            
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            data["salt"].encode('utf-8'), 
            100000
        )
        
        return key.hex() == data["admin_hash"]
    except Exception:
        return False

def create_admin(project_root, password=None):
    """Создает нового администратора безопасности. Возвращает (login, password) или None."""
    admin_file = get_sec_admin_file(project_root)
    
    if os.path.exists(admin_file):
        print("[bold red][!] Администратор безопасности уже существует.[/bold red]")
        overwrite = input("Удалить старого администратора и создать нового? (y/n): ")
        if overwrite.lower() != 'y':
            print("Отмена.")
            return None

    login = "admin" # Дефолтный логин для security admin (он не используется в hash, но для конфига пригодится)
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
    
    print(f"[green][+] Администратор безопасности успешно создан и защищен.[/green]")
    return (login, password)

def update_admin_credentials(project_root, new_login, new_password):
    """Обновляет учетные данные администратора (неинтерактивно)."""
    admin_file = get_sec_admin_file(project_root)
    
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        new_password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    )
    
    data = {
        "admin_hash": key.hex(),
        "salt": salt
    }
    
    # Обновляем sec_admin.json
    if os.path.exists(admin_file):
        unlock_file(admin_file)
    with open(admin_file, "w") as f:
        json.dump(data, f)
    lock_file(admin_file, intense=True)
    
    # Обновляем sec_config.py (только логин, убираем пароль)
    config_path = os.path.join(project_root, "AEngineApps", "sec_config.py")
    if os.path.exists(config_path):
        try:
            import re
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Обновляем логин
            content = re.sub(r'ADMIN_LOGIN = ".*"', f'ADMIN_LOGIN = "{new_login}"', content)
            # Убираем пароль если он там был
            content = re.sub(r'ADMIN_PASS = ".*"', 'ADMIN_PASS = "********"', content)
            
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass
            
    return True

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
        
    print("[WAIT] ВНИМАНИЕ: убедитесь что у файла sec_sign.key будут права 'только для чтения'!")
    return new_key
