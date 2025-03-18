__help__ = "Устанавливает логирование"
from rich import print
from datetime import datetime
import os
import re
from urllib.parse import unquote

base = os.sep.join(__file__.split(os.sep)[:-1])

BRUTE_TIMEOUT_TARGET=2
MIN_REQUESTS_FOR_BRUTE = 10

class Record:
	def __init__(self, line:str):
		self.line = re.sub(r" +", " ", line.replace(" -", " ")).strip()
		self.parts = self.line.split()
		# ----
		self.date = datetime.strptime(self.parts[0] + " " + self.parts[1], "%Y-%m-%d %H:%M:%S,%f")
		self.type = self.parts[2]
		self.address = self.parts[3]
		self.method = self.parts[4].strip('"')
		self.endpoint = unquote(self.parts[5])
		self.protocol = self.parts[6].strip('"')
		self.code = int(self.parts[7])
	
	def __str__(self):
		return self.line
	
	def __repr__(self):
		return str(self)
		

def __init(*args):
	if os.path.exists("AEngineApps"):
			if not os.path.exists("AEngineApps/logging.py"):
				open(os.path.join("AEngineApps/logging.py"),"w", encoding="utf-8").close()
			with open(os.path.join(base, "__logging.py"), encoding="utf-8") as file, open(os.path.join("AEngineApps/logging.py"),"w", encoding="utf-8") as file_to:
				file_to.write(file.read())

def __read_next_n(stream, n) -> list[Record]:
	batch = []
	for _ in range(n):
		line = stream.readline()
		if line:
			batch.append(Record(line))
		else: 
			break
	return batch

def __check_brute(batch: list[Record]):
	ips = {}
	for i, rec in enumerate(batch):
		if not rec.address in ips:
			ips[rec.address] = {}
			ips[rec.address]["last"] = rec.date.timestamp()
		if rec.code > 400:
			if not "error" in ips[rec.address]:
				ips[rec.address]["error"] = []

			ips[rec.address]["error"].append(rec.endpoint)
			ips[rec.address]["last"] = rec.date.timestamp()

		if rec.code == 200:
			if not "success" in ips[rec.address]:
				ips[rec.address]["success"] = []
			ips[rec.address]["success"].append(rec.endpoint)
	for ip in ips:
		try:
			if len(ips[ip].get("error") or []) + len(ips[ip].get("success") or []) > MIN_REQUESTS_FOR_BRUTE:
				ips[ip]["accuracy"] = (len(ips[ip].get("error") or [])) / (len(ips[ip].get("error") or []) + len(ips[ip].get("success") or [])) * 100
			else:
				ips[ip]["accuracy"] = 0
		except ZeroDivisionError:
			ips[ip]["accuracy"] = 0
	return ips

def __check_lfi_and_rfi(batch: list[Record]):
	res = {
		"potential": [],
		"vulnerable": []
	}
	for rec in batch:
		if "?" in rec.endpoint:
			args = rec.endpoint.split("?")[1].split("&")
			for arg in args:
				data = arg.split("=")
				if len(data) > 1:
					if ".." in data[1] or "/" in data[1] or "\\" in data[1]:
						res["potential"].append(rec.line)
						if rec.code == 200:
							res["vulnerable"].append(rec.line)
	return res

def __analyze(*args):
	batch = []
	args = args[0]
	lines = int(args[args.index("-l") + 1]) if "-l" in args else 300
	potential_lfi = []
	vulnerable_endpoints = []
	n = 1
	with open("logs/app.log", encoding="utf-8") as file, open("report.txt", "w", encoding="utf-8") as report:
		ip_report = {}
		batch = __read_next_n(file, lines)
		while batch:
			batch = __read_next_n(file, lines)
			brute_analysis_report = __check_brute(batch)
			for ip in brute_analysis_report:
				if ip not in ip_report:
					ip_report[ip] = {}
					ip_report[ip]["brute"] = brute_analysis_report[ip]["accuracy"]
				else:
					ip_report[ip]["brute"] += brute_analysis_report[ip]["accuracy"]
					ip_report[ip]["brute"] /= 2
			lfi_analysis_report = __check_lfi_and_rfi(batch)
			potential_lfi += lfi_analysis_report["potential"]
			vulnerable_endpoints += lfi_analysis_report["vulnerable"]
		for ip in ip_report:
			if ip_report[ip]["brute"] != 0:
				print(f"[yellow][!][/yellow] [blue]Вероятность брутфорса от[/blue] [green]{ip}[/green]: [red]{ip_report[ip]["brute"]}[/red]")
				report.write(f"[!] Вероятность брутфорса от {ip}: {ip_report[ip]["brute"]}" + "\n")

		print("\n[green bold][red bold][!][/red bold] Эксплуатация LFI и RFI: [/green bold]")
		report.write("\n")
		report.write("[+] Эксплуатация LFI и RFI: " + "\n")
		potential_lfi = list(set(potential_lfi))
		vulnerable_endpoints = list(set(vulnerable_endpoints))
		for rec in vulnerable_endpoints:
			print("    - [red]" + rec +"[/red]")
			report.write("    - " + rec + "\n")
		report.write("\n")
		report.write("[+] Попытки LFI и RFI:")
		for rec in potential_lfi:
			report.write("    - " + rec + "\n")


def run(*args, **kwargs):
	arg = kwargs["args"]
	if "init" in arg:
		__init(arg)
	if "analyze" in arg:
		__analyze(arg)


if __name__ == "__main__":
	import sys
	run(args=sys.argv)
