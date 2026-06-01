"""
Тонкая обёртка: реэкспортирует SecDashboardService из sec.dashboard.
Вся логика находится в sec/dashboard.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.dashboard import SecDashboardService`.
"""

from sec.dashboard import SecDashboardService

__all__ = ['SecDashboardService']
