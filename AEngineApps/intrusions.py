"""
Тонкая обёртка: реэкспортирует IDS/IPS и детекторы из sec.intrusions.
Вся логика находится в sec/intrusions.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.intrusions import IPS`.

Корневая версия содержит улучшенный XSSDetector (critical_patterns + suspicious_patterns
с порогом >= 3 совпадений вместо >= 1), загрузку сигнатур из JSON-базы,
проверку только пользовательского ввода (без заголовков) для RCE/LFI,
и проверку sec_config для IPS.
"""

from sec.intrusions import (
    IDS, IPS, BaseDetector,
    SQLiDetector, XSSDetector, LFIDetector, RCEDetector,
    SignatureDetector, RuleDetector, RateLimiter,
)

__all__ = [
    "IDS", "IPS", "BaseDetector",
    "SQLiDetector", "XSSDetector", "LFIDetector", "RCEDetector",
    "SignatureDetector", "RuleDetector", "RateLimiter"
]
