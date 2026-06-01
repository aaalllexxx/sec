"""
Тонкая обёртка: реэкспортирует ClusterNode из sec.cluster.
Вся логика находится в sec/cluster.py — этот файл существует
для обратной совместимости импортов вида `from AEngineApps.cluster import ClusterNode`.
"""

from sec.cluster import ClusterNode

__all__ = ['ClusterNode']
