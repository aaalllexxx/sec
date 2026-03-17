import os
import sys
import json
import hashlib
import hmac
import secrets
try:
    from . import auth
except ImportError:
    import auth

# Helper functions moved to auth.py

def scan_files(directory):
    """Рекурсивно сканирует директорию на наличие python и html файлов, игнорируя служебные."""
    ignore_dirs = {'.git', '.apm', '__pycache__', 'venv', 'env', 'logs'}
    valid_ext = {'.py', '.html', '.json', '.js', '.css'}
    result = {}
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in valid_ext:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, directory)
                
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
    
    # Проверяем права администратора ОС и запрашиваем если нужно
    if not auth.is_admin():
        print("[yellow][!] Для полной защиты файлов требуются права администратора ОС.[/yellow]")
        if os.name == 'nt':
            print("[yellow][*] Команды защиты будут запрашивать повышение привилегий (UAC).[/yellow]")
        else:
            print("[yellow][*] Команды защиты будут выполняться через sudo.[/yellow]")
    
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
    # Снимаем защиту если файл заблокирован
    if os.path.exists(sig_path):
        auth.unlock_file(sig_path)

    with open(sig_path, "w") as f:
        json.dump(final_sig, f, indent=4)
        
    print(f"[green][+] Проект успешно подписан! Файл подписи: {sig_path}[/green]")
    
    # Установка защиты на критичные файлы
    print("[*] Установка защиты на критичные файлы...")
    critical_files = [
        "sec_sign.key",
        "security.sig",
        "main.py",
        os.path.join(".apm", "sec", "sec_admin.json"),
        os.path.join("AEngineApps", "code_signer.py")
    ]
    
    for relative_file in critical_files:
        filepath = os.path.join(project_root, relative_file)
        if os.path.exists(filepath):
            # Для критичных конфигов используем интенсивную блокировку (+H +S на Windows)
            intense = "sec_admin.json" in relative_file or "sec_sign.key" in relative_file
            auth.lock_file(filepath, intense=intense)
            print(f"  [green]✓[/green] {relative_file} — защищён (владелец: администратор, запрет удаления)")
                
    print("\n[bold green]✓ ЗАЩИТА АКТИВИРОВАНА.[/bold green]")
    print("[dim]  Файлы принадлежат администратору ОС и защищены от удаления.[/dim]")
    print("[dim]  Для внесения изменений выполните: apm sec unsign[/dim]")
