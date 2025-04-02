from rich import print
import os

base = os.sep.join(__file__.split(os.sep)[:-1])

def __init(*args):
	if os.path.exists("AEngineApps"):
			if not os.path.exists("AEngineApps/dlp.py"):
				open(os.path.join("AEngineApps/dlp.py"),"w", encoding="utf-8").close()
			with open(os.path.join(base, "__dlp.py"), encoding="utf-8") as file, open(os.path.join("AEngineApps/dlp.py"),"w", encoding="utf-8") as file_to:
				file_to.write(file.read())

def run(*args, **kwargs):
    arg = kwargs["args"]
    if "init" in arg:
        __init()