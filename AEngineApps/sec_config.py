# Автоматически сгенерированный конфиг безопасности sec
import os

ADMIN_LOGIN = os.environ.get('SEC_ADMIN_LOGIN', 'admin')
ADMIN_PASS = os.environ.get('SEC_ADMIN_PASS')

if not ADMIN_PASS:
    import warnings
    warnings.warn(
        "SEC_ADMIN_PASS не задан в переменных окружения! "
        "Установите переменную окружения SEC_ADMIN_PASS для безопасной работы.",
        RuntimeWarning,
        stacklevel=1
    )
    ADMIN_PASS = None
