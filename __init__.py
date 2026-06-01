"""
sec — модуль безопасности для AEngine.

Включает:
- IDS/IPS (обнаружение и предотвращение вторжений)
- DLP (предотвращение утечек данных)
- Защита ОС (контроль ресурсов, привилегий)
- Сетевой анализатор (SYN flood, аномалии трафика)
- Системная защита (сканирование процессов, конфигурации)
- Кластеризация (Active-Passive с Heartbeat)
- Логирование запросов
- Дашборд безопасности
"""

from sec.intrusions import (
    IDS, IPS, BaseDetector,
    SQLiDetector, XSSDetector, LFIDetector, RCEDetector,
    SignatureDetector, RuleDetector, RateLimiter,
)
from sec.dlp import DLP, DLPMode, BasicFilter
from sec.os_protect import OSProtection, get_os_protection_module
from sec.net_analyzer import NetworkAnalyzer, get_network_analyzer
from sec.sys_protect import AdvancedSystemProtection, enable_cors, enable_csp
from sec.cluster import ClusterNode
from sec.logging import Logger
from sec.dashboard import SecDashboardService

__all__ = [
    # IDS/IPS
    "IDS", "IPS", "BaseDetector",
    "SQLiDetector", "XSSDetector", "LFIDetector", "RCEDetector",
    "SignatureDetector", "RuleDetector", "RateLimiter",
    # DLP
    "DLP", "DLPMode", "BasicFilter",
    # OS Protection
    "OSProtection", "get_os_protection_module",
    # Network Analyzer
    "NetworkAnalyzer", "get_network_analyzer",
    # System Protection
    "AdvancedSystemProtection", "enable_cors", "enable_csp",
    # Cluster
    "ClusterNode",
    # Logging
    "Logger",
    # Dashboard
    "SecDashboardService",
]
