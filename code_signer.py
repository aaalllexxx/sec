import os
import sys
import json
import hashlib
import hmac
import logging

def scan_files(directory):
    """(Копия части алгоритма обхода файлов из sign.py)"""
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
                
                rel_path = rel_path.replace("\\", "/")
                result[rel_path] = file_hash
                
    return result

def verify_project_signature(project_root: str):
    """
    Верифицирует целостность кода проекта перед запуском (Code Signing).
    Если хэш файлов изменен или отсутствует подпись - экстренно останавливает приложение.
    """
    logger = logging.getLogger("sec.code_signer")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    sig_path = os.path.join(project_root, "security.sig")
    key_path = os.path.join(project_root, "sec_sign.key")
    
    if not os.path.exists(sig_path):
        logger.warning("[CodeSigner] Файл security.sig НЕ НАЙДЕН. Запуск приложения разрешен, но КОД ПРОЕКТА НЕ ЗАЩИЩЕН ОТ ИНЪЕКЦИЙ!")
        logger.warning("[CodeSigner] Запустите 'apm sec sign' для генерации подписи.")
        return
        
    if not os.path.exists(key_path):
        logger.critical("[CodeSigner] Файл ключа подписи sec_sign.key УТЕРЯН! Невозможно верифицировать код.")
        sys.exit(1)

    print("[CodeSigner] Анализ целостности файлов и библиотек...")

    # 1. Читаем ключ
    with open(key_path, "rb") as f:
        sign_key = f.read()
        
    # 2. Читаем подпись
    try:
        with open(sig_path, "r") as f:
            sig_file = json.load(f)
            expected_signature = sig_file.get("signature")
            payload = sig_file.get("payload")
    except Exception as e:
        logger.critical(f"[CodeSigner] Ошибка чтения security.sig: {e}")
        sys.exit(1)
        
    # 3. Верифицируем HMAC (Защита от подмены самого списка хэшей)
    payload_dump = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    actual_signature = hmac.new(sign_key, payload_dump, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(str(expected_signature), str(actual_signature)):
        logger.critical(">>> [SECURITY ALERT] <<<")
        logger.critical("[CodeSigner] ПОДПИСЬ HMAC НЕДЕЙСТВИТЕЛЬНА! Файл security.sig был скомпрометирован.")
        logger.critical("[CodeSigner] ЗАПУСК ПРИЛОЖЕНИЯ ОТМЕНЕН ВО ИЗБЕЖАНИЕ ИСПОЛНЕНИЯ ВРЕДОНОСНОГО КОДА.")
        sys.exit(1)
        
    # 4. Проверяем реальные хэши (Защита от внедрения / инъекций питон-кода)
    expected_files = payload.get("files", {})
    actual_files = scan_files(project_root)
    
    anomalies = []
    
    for relative_path, actual_hash in actual_files.items():
        if relative_path not in expected_files:
            anomalies.append(f"INJECTED (НОВЫЙ ФАЙЛ): {relative_path}")
        elif expected_files[relative_path] != actual_hash:
            anomalies.append(f"MODIFIED (ИЗМЕНЕН): {relative_path}")
            
    # Проверка на удаление файлов
    for expected_path in expected_files:
        if expected_path not in actual_files:
            anomalies.append(f"DELETED (УДАЛЕН): {expected_path}")
            
    if anomalies:
        logger.critical(">>> [SECURITY ALERT] <<<")
        logger.critical("[CodeSigner] ОБНАРУЖЕНО НАРУШЕНИЕ ЦЕЛОСТНОСТИ ФАЙЛОВ И/ИЛИ БИБЛИОТЕК!")
        for anomaly in anomalies[:15]:
            logger.critical(f"   -> {anomaly}")
        if len(anomalies) > 15:
            logger.critical(f"   -> ... и еще {len(anomalies)-15} файлов!")
        logger.critical("[CodeSigner] ЗАПУСК СЕРВЕРА ЗАБЛОКИРОВАН. Восстановите исходники или переподпишите проект 'apm sec sign'.")
        sys.exit(1)
        
    logger.info("[CodeSigner] Подпись действительна. Модификаций и инъекций не обнаружено.")

