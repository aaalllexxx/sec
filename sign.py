import os
import sys
import json
import hashlib
import hmac
import secrets
try:
    from rich import print
except ImportError:
    pass

try:
    from . import auth
except ImportError:
    import auth

# Helper functions moved to auth.py

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
    
    if not auth.verify_admin(project_root):
        sys.exit(1)
        
    print("[+] Авторизация успешна. Сканирование файлов проекта...")
    
    file_hashes = scan_files(project_root)
    print(f"[*] Найдено файлов для подписи: {len(file_hashes)}")
    
    sign_key = auth.get_or_create_sign_key(project_root)
    
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
    # Снимаем защиту если файл существует
    if os.path.exists(sig_path):
        auth.unlock_file(sig_path)
        
    with open(sig_path, "w") as f:
        json.dump(final_sig, f, indent=4)
        
    print(f"[+] Проект успешно подписан! Файл подписи создан: {sig_path}")
    
    # Автоматическая установка прав (Read-Only) для критичных файлов
    print("[*] Установка прав Read-Only на критичные файлы (Защита от перезаписи)...")
    critical_files = [
        "sec_sign.key",
        "security.sig",
        "main.py",
        os.path.join(".apm", "sec", "sec_admin.json"),
        os.path.join("AEngineApps", "code_signer.py")
    ]
    
    import stat
    import subprocess
    
    for relative_file in critical_files:
        filepath = os.path.join(project_root, relative_file)
        if os.path.exists(filepath):
            print(f"[*] Обработка {relative_file}...")
            # Для критичных конфигов используем интенсивную блокировку (+R +H +S)
            intense = "sec_admin.json" in relative_file or "sec_sign.key" in relative_file
            auth.lock_file(filepath, intense=intense)
            print(f"  [green]✓[/green] Файл {relative_file} защищен.")
                
    print("[!!] ЗАЩИТА АКТИВИРОВАНА. Чтобы внести изменения в код, потребуется вернуть права на запись.")
