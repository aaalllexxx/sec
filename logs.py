__help__ = "Подкоманды логирования и анализа журналов безопасности"

try:
    from . import sec_logging as log_mod
except ImportError:
    import sec_logging as log_mod


def run(base_dir, *args, **kwargs):
    """Wrapper for `apm sec logs ...` commands."""
    gconf_path = kwargs.get("gconf_path", "")
    args_list = kwargs.get("args", [])
    log_mod.run(base_dir, gconf_path, args=args_list)
