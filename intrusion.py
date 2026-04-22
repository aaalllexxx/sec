__help__ = "Установка только модуля intrusion через alias-команду"

try:
    from . import init as sec_init
except ImportError:
    import init as sec_init


def run(base_dir, *args, **kwargs):
    """Support `apm sec intrusion init` as documented alias."""
    args_list = kwargs.get("args", [])
    if args_list and args_list[0] not in {"init", "-h", "--help"}:
        print("Usage: apm sec intrusion init")
        return

    sec_init.run(base_dir=base_dir, args=["--modules", "intrusion"])
