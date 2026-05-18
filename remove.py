import os
import shutil

MODULE_MAP = {
    "intrusion": "intrusions.py",
    "logs": "logging.py",
    "os_protect": "os_protect.py",
    "net_analyzer": "net_analyzer.py",
    "sys_protect": "sys_protect.py",
    "dashboard": "dashboard.py",
    "cluster": "cluster.py",
    "auto_cluster": "auto_cluster.py"
}

def run(*args, **kwargs):
    """
    Удаляет модули безопасности sec из проекта.
    """
    arg = kwargs.get("args", [])
    # Приоритет за CWD, так как apm может передавать свой путь установки
    base_dir = kwargs.get("base_dir")
    cwd = os.getcwd()
    
    if os.path.exists(os.path.join(cwd, "AEngineApps")):
        base_dir = cwd
    elif not base_dir or not os.path.exists(os.path.join(base_dir, "AEngineApps")):
        base_dir = cwd

    print(f"\n🗑️  Удаление модулей безопасности sec (в {base_dir})\n")
    
    apps_dir = os.path.join(base_dir, "AEngineApps")
    if not os.path.exists(apps_dir):
        print(f"[-] Директория {apps_dir} не найдена. Нечего удалять.")
        return

    # Определяем список модулей для удаления
    if args and "--modules" in args:
        try:
            target_modules = args[args.index("--modules") + 1:]
        except IndexError:
            target_modules = []
    else:
        target_modules = list(MODULE_MAP.keys())
        target_modules.append("sec_config") # Удаляем конфиг по умолчанию при полной очистке

    count = 0
    for mod in target_modules:
        filename = MODULE_MAP.get(mod)
        if mod == "sec_config":
            filename = "sec_config.py"
            
        if not filename:
            print(f"  ! Неизвестный модуль: {mod}")
            continue
            
        target_path = os.path.join(apps_dir, filename)
        if os.path.exists(target_path):
            try:
                os.remove(target_path)
                print(f"  ✓ {mod} удален ({filename})")
                count += 1
            except Exception as e:
                print(f"  × Ошибка при удалении {mod}: {e}")
        else:
            print(f"  - {mod} уже отсутствует")

    # Удаляем шаблоны если они были созданы
    templates_dir = os.path.join(base_dir, "templates", "sec")
    if os.path.exists(templates_dir):
        try:
            shutil.rmtree(templates_dir)
            print(f"  ✓ Шаблоны удалены ({templates_dir})")
        except Exception as e:
            print(f"  × Ошибка при удалении шаблонов: {e}")

    print(f"\nГотово! Удалено компонентов: {count}")
