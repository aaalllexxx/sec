import os
try:
    from . import sec_logging as log_mod
except (ImportError, ValueError):
    import sec_logging as log_mod

def run(base_dir, *args, **kwargs):
    """Обертка для запуска функционала логирования через apm sec logs"""
    gconf_path = kwargs.get("gconf_path", "")
    args_list = kwargs.get("args", [])
    log_mod.run(base_dir, gconf_path, args=args_list)
