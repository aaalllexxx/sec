__help__ = "Устанавливает логирование"
from rich import print
import os

base = os.sep.join(__file__.split(os.sep)[:-1])

def run(*args, **kwargs):
	arg = kwargs["args"]
	if "init" in arg:
		if os.path.exists("AEngineApps"):
			if not os.path.exists("AEngineApps/logging.py"):
				open(os.path.join("AEngineApps/logging.py"),"w", encoding="utf-8").close()
            with open(os.path.join(base, "__logs.py"), encoding="utf-8") as file, \
            open(os.path.join("AEngineApps/logging.py"),"w", encoding="utf-8") as file_to:
                file_to.write(file.read())


