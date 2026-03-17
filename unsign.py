import os
import sys

try:
    from rich import print
except ImportError:
    pass

try:
    from . import auth
except ImportError:
    import auth


def run(base_dir, gconf_path="", args=None):
    project_root = os.getcwd()
    print("=== AEngine: Снятие подписи (Unsigning) ===")
    
    if not auth.verify_admin(project_root):
        sys.exit(1)
        
    print("[+] Авторизация успешна. Снятие защиты с файлов...")
    
    # Проверяем права администратора ОС
    if not auth.is_admin():
        print("[yellow][!] Для полного снятия защиты требуются права администратора ОС.[/yellow]")
        if os.name == 'nt':
            print("[yellow][*] Команды будут запрашивать повышение привилегий (UAC).[/yellow]")
        else:
            print("[yellow][*] Команды будут выполняться через sudo.[/yellow]")
    
    critical_files = [
        "sec_sign.key",
        "security.sig",
        "main.py",
        os.path.join(".apm", "sec", "sec_admin.json"),
        os.path.join("AEngineApps", "code_signer.py")
    ]
    
    # 1. Снимаем всю защиту: ACL, атрибуты, immutable bit, владелец
    for relative_file in critical_files:
        filepath = os.path.join(project_root, relative_file)
        if os.path.exists(filepath):
            print(f"[*] Снятие защиты с {relative_file}...")
            auth.unlock_file(filepath)
            print(f"  [green]✓[/green] {relative_file} — доступен для записи и удаления")
 
    # 2. Удаляем файл подписи
    sig_path = os.path.join(project_root, "security.sig")
    if os.path.exists(sig_path):
        try:
            os.remove(sig_path)
            print(f"[+] Файл подписи {os.path.basename(sig_path)} удалён.")
        except Exception as e:
            print(f"[!] Не удалось удалить файл подписи: {e}")
    else:
        print("[*] Файл подписи не найден.")
 
    print("\n[bold green]✓ ЗАЩИТА СНЯТА.[/bold green]")
    print("[dim]  Все файлы возвращены текущему пользователю.[/dim]")
    print("[dim]  Файлы можно изменять и удалять.[/dim]")
    print("[dim]  Для повторной защиты выполните: apm sec sign[/dim]")
