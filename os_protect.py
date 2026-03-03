import os
import ctypes
import platform
import psutil
from typing import Optional, Dict

class OSProtection:
    """
    Модуль защиты операционной системы хоста.
    Контролирует потребление ресурсов (анти-DoS хоста) и отслеживает
    рискованные привилегии (запуск от имени root/Administrator).
    
    Может быть привязан к AEngineApp для циклического сканирования при запросах.
    """
    
    def __init__(self, app=None, max_cpu_percent: float = 90.0, max_ram_percent: float = 90.0):
        self.max_cpu_percent = max_cpu_percent
        self.max_ram_percent = max_ram_percent
        
        if app:
            self.attach(app)

    def attach(self, app):
        """Автоматическая интеграция с приложением."""
        app.before_request(self._auto_scan_hook)
        
    def _auto_scan_hook(self):
        """Хук, вызываемый перед каждым запросом."""
        # Для высоконагруженных систем можно добавить throttling проверок (например раз в 5 сек)
        # но для базовой защиты проверяем всегда
        res = self.check_resources()
        if res["status"] == "danger":
            import logging
            logging.critical(f"[OS Protect] Автоматическая блокировка из-за перегрузки ОС! {res['warnings']}")
            from flask import abort
            abort(503, description="Service Unavailable: High Server Load")
        
    def check_privileges(self) -> dict:
        """
        Проверят, запущено ли приложение от имени суперпользователя (root/Admin).
        Рекомендуется запускать веб-сервисы с минимальными правами (Least Privilege).
        """
        is_admin = False
        os_name = platform.system().lower()
        
        if os_name == "windows":
            try:
                is_admin = os.getuid() == 0 # На всякий случай (Cygwin/MSYS)
            except AttributeError:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Linux/Unix/Mac
            is_admin = os.getuid() == 0
            
        return {
            "status": "warning" if is_admin else "ok",
            "is_admin": is_admin,
            "message": "Приложение запущено с административными (root) правами. Это может быть опасно в случае RCE-уязвимостей." if is_admin else "Привилегии в норме."
        }

    def check_resources(self) -> dict:
        """
        Проверяет текущую загрузку CPU и памяти на хосте.
        Возвращает warning, если обнаруживается возможный отказ в обслуживании (Denial of Service) на уровне ОС.
        """
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        
        status = "ok"
        warnings = []
        
        if cpu > self.max_cpu_percent:
            status = "danger"
            warnings.append(f"Критическая загрузка CPU: {cpu}%")
            
        if mem > self.max_ram_percent:
            status = "danger"
            warnings.append(f"Критическое потребление ОЗУ: {mem}%")
            
        return {
            "status": status,
            "cpu_percent": cpu,
            "ram_percent": mem,
            "warnings": warnings
        }

    def run_health_check(self) -> dict:
        """Запускает полную проверку здоровья ОС."""
        priv_check = self.check_privileges()
        res_check = self.check_resources()
        
        overall_status = "ok"
        if priv_check["status"] != "ok" or res_check["status"] != "ok":
            overall_status = "warning"
        if res_check["status"] == "danger":
            overall_status = "danger"
            
        return {
            "status": overall_status,
            "privileges": priv_check,
            "resources": res_check
        }
