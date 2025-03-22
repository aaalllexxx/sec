__help__ = "Устанавливает логирование"
from rich import print
from datetime import datetime
import os
import re
from urllib.parse import unquote
import shutil


base = os.sep.join(__file__.split(os.sep)[:-1])
with open(base + os.sep + "__RCE.list", "r", encoding="utf-8") as file:
	rce_list = file.read().split("\n")

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
		return re.sub(r"\[/?[A-z]*]", "", self.line)
	
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
			try:
				batch.append(Record(line))
			except:
				continue
		else: 
			break
	return batch

def __check_fuzz(batch: list[Record]):
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
					lfi = re.findall(r"^(?!javascript)(.*://)*([%, ,A-z,0-9,\.\.]*[/,//,\\,\\\\]){1,}", data[1])
					if lfi:
						res["potential"].append(rec)
						if rec.code == 200:
							res["vulnerable"].append(rec)
	return res

def __check_XSS(batch: list[Record]):
	res = {
		"potential": [],
		"vulnerable": []
	}
	dangerous = ["<", ">",  "/*", "*/", "'", '"', "script", " src=", " href=", "javascript", "://", "cookie", "document."]
	for rec in batch:
		if "?" in rec.endpoint:
			args = rec.endpoint.split("?")[1].split("&")
			for arg in args:
				data = arg.split("=")
				potentiality = 0
				if len(data) > 1:
					for ch in dangerous:
						potentiality += 1 if ch in data[1] else 0
					if potentiality != 0:
						if rec.code < 400:
							res["vulnerable"].append(rec)
						elif rec.code >= 400:
							res["potential"].append(rec)
	return res

def __check_rce(batch: list[Record]):
	res = {
		"potential": [],
		"vulnerable": []
	}
	for rec in batch:
		if "?" in rec.endpoint:
			args = rec.endpoint.split("?")[1].split("&")
			for arg in args:
				arg = arg.split("=")
				if len(arg) > 1:
					parts = arg[1].split()
					command = parts[0] if parts else ""
					if shutil.which(arg[1]) or command in rce_list:
						if rec.code >= 400:
							res["potential"].append(rec)
						elif rec.code < 400:
							res["vulnerable"].append(rec)
						break
							
	return res

def __write_report(title, potential, vulnerable, report):
	if vulnerable:
		print(f"\n[green bold][red bold][!][/red bold] Эксплуатация {title}[/green bold]:")
	report.write("\n")
	report.write(f"[!] Эксплуатация {title}: " + "\n")
	potential = list(set(potential))
	vulnerable = list(set(vulnerable))
	for rec in vulnerable:
		print("    - [red]" + rec.line +"[/red]")
		report.write("    - " + str(rec) + "\n")
	if potential:
		report.write("\n")
		report.write(f"[!] Попытки {title}:\n")
		for rec in potential:
			report.write("    - " + str(rec) + "\n")
	
def __analyze(*args):
	batch = []
	args = args[0]
	lines = int(args[args.index("-l") + 1]) if "-l" in args else 1000
	potential_lfi = []
	vulnerable_lfi = []
	potential_xss = []
	vulnerable_xss = []
	potential_rce = []
	vulnerable_rce = []
	with open("logs/app.log", encoding="utf-8") as file, open("report.txt", "w", encoding="utf-8") as report:
		ip_report = {}
		batch = __read_next_n(file, lines)
		while batch:
			batch = __read_next_n(file, lines)
			brute_analysis_report = __check_fuzz(batch)
			for ip in brute_analysis_report:
				if ip not in ip_report:
					ip_report[ip] = {}
					ip_report[ip]["fuzz"] = brute_analysis_report[ip]["accuracy"]
				else:
					ip_report[ip]["fuzz"] += brute_analysis_report[ip]["accuracy"]
					ip_report[ip]["fuzz"] /= 2
			ip_report[ip]["fuzz"] = round(ip_report[ip]["fuzz"], 1)
			lfi_analysis_report = __check_lfi_and_rfi(batch)
			potential_lfi += lfi_analysis_report["potential"]
			vulnerable_lfi += lfi_analysis_report["vulnerable"]
			xss_analysis_report = __check_XSS(batch)
			potential_xss += xss_analysis_report["potential"]
			vulnerable_xss += xss_analysis_report["vulnerable"]
			rce_analysis_report = __check_rce(batch)
			potential_rce += rce_analysis_report["potential"]
			vulnerable_rce += rce_analysis_report["vulnerable"]

		for ip in ip_report:
			if ip_report[ip]["fuzz"] != 0:
				print(f"[yellow][!][/yellow] [blue]Вероятность фаззинга от[/blue] [green]{ip}[/green]: [red]{ip_report[ip]["fuzz"]}[/red]")
				report.write(f"[!] Вероятность фаззинга от {ip}: {ip_report[ip]["fuzz"]}" + "\n")


		__write_report("LFI и RFI", potential_lfi, vulnerable_lfi, report)
		__write_report("XSS", potential_xss, vulnerable_xss, report)
		__write_report("RCE", potential_rce, vulnerable_rce, report)


def run(*args, **kwargs):
	arg = kwargs["args"]
	if "init" in arg:
		__init(arg)
	if "analyze" in arg:
		__analyze(arg)


if __name__ == "__main__":
	import sys
	run(args=sys.argv)
