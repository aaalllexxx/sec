import os
import sys
import stat
import subprocess
try:
    from rich import print
except ImportError:
    pass

try:
    from . import auth
except ImportError:
    import auth

# Helper functions moved to auth.py

def run(base_dir, gconf_path="", args=None):
    project_root = os.getcwd()
    print("=== AEngine: Снятие подписи (Unsigning) ===")
    
    if not auth.verify_admin(project_root):
        sys.exit(1)
        
    print("[+] Авторизация успешна. Снятие защиты с файлов...")
    
    critical_files = [
        "sec_sign.key",
        "security.sig",
        "main.py",
        os.path.join(".apm", "sec", "sec_admin.json"),
        os.path.join("AEngineApps", "code_signer.py")
    ]
    
    # 1. Снимаем атрибуты Read-Only
    for relative_file in critical_files:
        filepath = os.path.join(project_root, relative_file)
        if os.path.exists(filepath):
            print(f"[*] Снятие защиты с {relative_file}...")
            auth.unlock_file(filepath)
            print(f"  [green]✓[/green] Файл {relative_file} доступен для записи.")
 
    # 2. Удаляем файл подписи
    sig_path = os.path.join(project_root, "security.sig")
    if os.path.exists(sig_path):
        try:
            os.remove(sig_path)
            print(f"[+] Файл подписи {os.path.basename(sig_path)} удален.")
        except Exception as e:
            print(f"[!] Не удалось удалить файл подписи: {e}")
    else:
        print("[*] Файл подписи не найден.")
 
    print("\n[SUCCESS] Проект успешно переведен в режим разработки. Подпись снята.")
