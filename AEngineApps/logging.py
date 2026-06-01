"""
Тонкая обёртка: реэкспортирует Logger из sec.logging.
Вся логика находится в sec/logging.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.logging import Logger`.

Корневая версия содержит проверку sec_config в __init__().
"""

from sec.logging import Logger, RemoveAnsiAndRichMarkupFormatter

__all__ = ['Logger', 'RemoveAnsiAndRichMarkupFormatter']
