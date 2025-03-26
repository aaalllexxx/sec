from flask import request, Flask, abort
from urllib.parse import unquote
import shutil
import os
import re

class IDS:
    def __init__(self, app):
        self.app: Flask = app.flask
        self.app.before_request(self.detect)
        self.detect_func = []
        self.xss_dangerous = ["<", ">",  "/*", "*/", "script", " src=", " href=", "javascript", "://", "cookie", "document."]
        self.sql_dangerous = ["@variable", "AND", "OR", ",", "AS", "WHERE", "ORDER", "--", "/*", "#", "RLIKE", "SLEEP", "SELECT", "UNION", " * "]
        self.rce_dangerous = ["echo"]


    
    def __detect_RCE(self):
        args = request.args.values()
        if args:
            for arg in args:
                for el in unquote(arg).split():
                    if shutil.which(el) or el in self.rce_dangerous:
                        self.app.logger.critical(f"DETECTED RCE: {request.full_path}")
                        if self.detect_func:
                            for func in self.detect_func:
                                func()

    def __detect_LFI(self):
        args = request.args.values()
        if args:
            for arg in args:
                if os.path.exists("arg") or re.findall(r"^(?!javascript)(.*://)*([%, ,A-z,0-9,\.\.]*[/,//,\\,\\\\]){1,}", arg):
                    self.app.logger.critical(f"DETECTED LFI or RFI: {request.full_path}")
                    if self.detect_func:
                        for func in self.detect_func:
                            func()
    
    def __detect_SQLinj(self):
        args = request.args.values()
        if args:
            for arg in args:
                arg = arg.upper()
                if any([el in arg for el in self.sql_dangerous]) or arg.startswith("'") or arg.startswith('"'):
                    self.app.logger.critical(f"DETECTED SQL injection: {request.full_path}")
                    if self.detect_func:
                        for func in self.detect_func:
                            func()
    
    def __detect_XSS(self):
        args = request.args.values()
        if args:
            for arg in args:
                potentiality = 0
                if len(arg) > 1:
                    for ch in self.xss_dangerous:
                        potentiality += 1 if ch in arg else 0
                    if potentiality != 0:
                        self.app.logger.critical(f"DETECTED XSS: {request.full_path}")
                        if self.detect_func:
                            for func in self.detect_func:
                                func()
    

    
    @property
    def on_detection(self):
        return None
    
    @on_detection.setter
    def on_detection(self, value):
        self.detect_func.append(value)

    def detect(self):
        self.__detect_RCE()
        self.__detect_LFI()
        self.__detect_XSS()
        self.__detect_SQLinj()

class IPS(IDS):
    def __init__(self, app):
        super().__init__(app)
        self.on_detection = self.__on_detection

    def __on_detection(self):
        self.app.logger.info(f"ABORTING CONNECTION: {request.remote_addr}")
        return abort(400)


