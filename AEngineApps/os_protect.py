"""
Тонкая обёртка: реэкспортирует OSProtection из sec.os_protect.
Вся логика находится в sec/os_protect.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.os_protect import get_os_protection_module`.

Корневая версия содержит проверку sec_config в attach().
"""

from sec.os_protect import OSProtection, get_os_protection_module

__all__ = ['OSProtection', 'get_os_protection_module']
