"""
Тонкая обёртка: реэкспортирует AdvancedSystemProtection и утилиты из sec.sys_protect.
Вся логика находится в sec/sys_protect.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.sys_protect import AdvancedSystemProtection`.

Корневая версия содержит проверку sec_config в __init__() и расширенную CSP-политику
с CDN/fonts URL.
"""

from sec.sys_protect import AdvancedSystemProtection, enable_cors, enable_csp

__all__ = ['AdvancedSystemProtection', 'enable_cors', 'enable_csp']
