"""
Тонкая обёртка: реэкспортирует NetworkAnalyzer из sec.net_analyzer.
Вся логика находится в sec/net_analyzer.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.net_analyzer import get_network_analyzer`.

Корневая версия содержит проверку sec_config в attach().
"""

from sec.net_analyzer import NetworkAnalyzer, get_network_analyzer

__all__ = ['NetworkAnalyzer', 'get_network_analyzer']
