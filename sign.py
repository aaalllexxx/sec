import os
import sys
import json
import hashlib
import hmac
import getpass
import secrets

def get_sec_admin_file(project_root):
    return os.path.join(project_root, ".apm", "sec", "sec_admin.json")

def verify_admin(project_root):
    admin_file = get_sec_admin_file(project_root)
    if not os.path.exists(admin_file):
        print("[!] Администратор безопасности не настроен.")
        print("[!] Выполните команду 'apm sec add-admin' перед подписью проекта.")
        return False
        
    with open(admin_file, "r") as f:
        data = json.load(f)
        
    password = getpass.getpass("Введите пароль администратора безопасности: ")
    
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        data["salt"].encode('utf-8'), 
        100000
    )
    
    if key.hex() != data["admin_hash"]:
        print("[!] Неверный пароль. Доступ запрещен.")
        return False
        
    return True

def get_or_create_sign_key(project_root):
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

def scan_files(directory):
    """Рекурсивно сканирует директорию на наличие python и html файлов, игнорируя служебные."""
    ignore_dirs = {'.git', '.apm', '__pycache__', 'venv', 'env', 'logs'}
    # Защита от инъекций библиотек: мы сканируем AEngineApps, sec, и сам проект. 
    # (venv/env игнорируются для скорости, но в идеале библиотеки тоже стоит подписывать)
    
    valid_ext = {'.py', '.html', '.json', '.js', '.css'}
    result = {}
    
    for root, dirs, files in os.walk(directory):
        # Удаляем игнорируемые директории из обхода
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in valid_ext:
                filepath = os.path.join(root, file)
                # Вычисляем относительный путь для универсальности
                rel_path = os.path.relpath(filepath, directory)
                
                # Не подписываем саму подпись и ключ!
                if file in ("security.sig", "sec_sign.key", "sec_admin.json", "signatures_db.json"):
                    continue
                    
                with open(filepath, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Используем прямые слеши для кроссплатформенности
                rel_path = rel_path.replace("\\", "/")
                result[rel_path] = file_hash
                
    return result

def run(base_dir, gconf_path="", args=None):
    project_root = os.getcwd()
    print("=== AEngine: Подпись проекта (Code Signing) ===")
    
    if not verify_admin(project_root):
        sys.exit(1)
        
    print("[+] Авторизация успешна. Сканирование файлов проекта...")
    
    file_hashes = scan_files(project_root)
    print(f"[*] Найдено файлов для подписи: {len(file_hashes)}")
    
    sign_key = get_or_create_sign_key(project_root)
    
    # Создаем данные для подписи
    sig_data = {
        "files": file_hashes,
        "version": "1.0"
    }
    
    # Сериализуем детерминированно
    payload = json.dumps(sig_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    # Вычисляем HMAC-SHA256
    signature = hmac.new(sign_key, payload, hashlib.sha256).hexdigest()
    
    final_sig = {
        "signature": signature,
        "payload": sig_data
    }
    
    sig_path = os.path.join(project_root, "security.sig")
    with open(sig_path, "w") as f:
        json.dump(final_sig, f, indent=4)
        
    print(f"[+] Проект успешно подписан! Файл подписи создан: {sig_path}")
    
    # Автоматическая установка прав (Read-Only) для критичных файлов
    print("[*] Установка прав Read-Only на критичные файлы (Защита от перезаписи)...")
    critical_files = [
        "sec_sign.key",
        "main.py",
        os.path.join("AEngineApps", "code_signer.py")
    ]
    
    import stat
    import subprocess
    
    for relative_file in critical_files:
        filepath = os.path.join(project_root, relative_file)
        if os.path.exists(filepath):
            try:
                print(f"[*] Обработка {relative_file}...")
                # Базовый UNIX/Windows chmod: S_IREAD
                os.chmod(filepath, stat.S_IREAD)
                # Проверим атрибут сразу
                current_mode = os.stat(filepath).st_mode
                if not (current_mode & stat.S_IWRITE):
                    print(f"  [green]✓[/green] Атрибут Read-Only установлен.")
                else:
                    print(f"  [red]![/red] Атрибут Read-Only НЕ УСТАНОВЛЕН через chmod.")

                # Для надежности в Windows используем команду attrib +R
                if os.name == 'nt':
                    res = subprocess.run(
                        f'attrib +R "{filepath}"', 
                        shell=True, capture_output=True, text=True
                    )
                    if res.returncode == 0:
                        print(f"  [green]✓[/green] Атрибут +R (Win) установлен.")
                    else:
                        print(f"  [red]![/red] Ошибка attrib ({res.returncode}): {res.stderr.strip()}")
                
                print(f"  [green]✓[/green] Файл {relative_file} защищен.")
            except Exception as e:
                print(f"  [yellow]![/yellow] Не удалось заблокировать {relative_file}: {e}")
                
    print("[!!] ЗАЩИТА АКТИВИРОВАНА. Чтобы внести изменения в код, потребуется вернуть права на запись.")
