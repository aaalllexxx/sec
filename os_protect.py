from .__os_protect import OSProtection

def get_os_protection_module(app=None, max_cpu_percent: float = 90.0, max_ram_percent: float = 90.0) -> OSProtection:
    """
    Возвращает экземпляр модуля OS Protection для отслеживания ресурсов хоста и проверки привилегий.
    """
    return OSProtection(app=app, max_cpu_percent=max_cpu_percent, max_ram_percent=max_ram_percent)
