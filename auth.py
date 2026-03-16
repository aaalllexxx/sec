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

def lock_file(filepath, intense=False):
    """
    Устанавливает расширенную защиту:
    - Read-Only (Запрет изменения)
    - Anti-Delete/Anti-Move (Запрет удаления и перемещения)
    - Hidden/System (Для критичных файлов на Windows)
    """
    if not os.path.exists(filepath):
        return
    try:
        # 1. POSIX (Linux/macOS)
        if os.name != 'nt':
            # Убираем права на запись (W) для всех
            current_mode = os.stat(filepath).st_mode
            os.chmod(filepath, current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
            
            # Попытка установить атрибут "immutable" (требует root, но стоит попробовать)
            # Это предотвращает удаление и переименование
            try:
                subprocess.run(['chattr', '+i', filepath], capture_output=True)
            except Exception:
                pass
        
        # 2. Windows (NT)
        else:
            # Атрибуты: Только чтение (+R), Скрытый (+H), Системный (+S)
            flags = "+R"
            if intense:
                flags += " +H +S"
            subprocess.run(f'attrib {flags} "{filepath}"', shell=True, capture_output=True)
            
            # Запрет удаления через ACL (icacls)
            # D - Delete permission
            subprocess.run(f'icacls "{filepath}" /deny Everyone:(D)', shell=True, capture_output=True)
            
    except Exception as e:
        print(f"[yellow]![/yellow] Не удалось заблокировать {os.path.basename(filepath)}: {e}")

def unlock_file(filepath):
    """Снимает расширенную защиту файла."""
    if not os.path.exists(filepath):
        return
    try:
        # 1. POSIX (Linux/macOS)
        if os.name != 'nt':
            # Снимаем атрибут "immutable"
            try:
                subprocess.run(['chattr', '-i', filepath], capture_output=True)
            except Exception:
                pass
                
            # Добавляем права на запись владельцу
            current_mode = os.stat(filepath).st_mode
            os.chmod(filepath, current_mode | stat.S_IWUSR)
            
        # 2. Windows (NT)
        else:
            # Снимаем запрет на удаление в ACL
            subprocess.run(f'icacls "{filepath}" /remove:d Everyone', shell=True, capture_output=True)
            
            # Снимаем атрибуты
            subprocess.run(f'attrib -R -H -S "{filepath}"', shell=True, capture_output=True)
            
    except Exception as e:
        print(f"[yellow]![/yellow] Не удалось разблокировать {os.path.basename(filepath)}: {e}")

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
