import os
import json
import hashlib
import getpass
import secrets

def get_sec_admin_file(project_root):
    # Храним данные администратора локально в конфиг-директории .apm
    sec_dir = os.path.join(project_root, ".apm", "sec")
    os.makedirs(sec_dir, exist_ok=True)
    return os.path.join(sec_dir, "sec_admin.json")

def create_admin(project_root):
    admin_file = get_sec_admin_file(project_root)
    
    if os.path.exists(admin_file):
        print("[!] Администратор безопасности уже существует.")
        overwrite = input("Удалить старого администратора и создать нового? (y/n): ")
        if overwrite.lower() != 'y':
            print("Отмена.")
            return

    print("Создание администратора безопасности для подписи кода (AEngine sec).")
    password = getpass.getpass("Введите новый пароль администратора: ")
    confirm = getpass.getpass("Повторите пароль: ")
    
    if password != confirm:
        print("[!] Пароли не совпадают. Отмена.")
        return
        
    if len(password) < 8:
        print("[!] Внимание: пароль слишком короткий. Используйте более надежный.")
        
    salt = secrets.token_hex(16)
    # Хэшируем пароль 100000 итерациями PBKDF2
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
    
    with open(admin_file, "w") as f:
        json.dump(data, f)
        
    print(f"[+] Администратор безопасности успешно создан. Файл: {admin_file}")
    print("[*] Храните этот пароль в безопасности! Он необходим для подписи кода (apm sec sign).")

def run(base_dir, gconf_path="", args=None):
    if not args:
        return
    
    project_root = os.getcwd()
    create_admin(project_root)
