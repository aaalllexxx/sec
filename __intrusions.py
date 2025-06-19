from flask import Flask, request, abort
from urllib.parse import unquote
import os
import re
import shutil
from abc import ABC, abstractmethod

# === Абстрактный класс детектора ===
class BaseDetector(ABC):
    def __init__(self, app: Flask):
        self.app = app

    @abstractmethod
    def run(self):
        pass

    def log(self, message):
        self.app.logger.critical(message)

    def trigger_response(self):
        pass


# === Конкретные реализации детекторов ===
class RCEDetector(BaseDetector):
    dangerous = ["echo"]

    def run(self):
        for arg in request.args.values():
            decoded = unquote(arg)
            for el in decoded.split():
                if shutil.which(el) or el in self.dangerous:
                    self.log(f"DETECTED RCE: {request.full_path}")
                    self.trigger_response()


class LFIDetector(BaseDetector):
    def run(self):
        for arg in request.args.values():
            decoded = unquote(arg)
            if os.path.exists(decoded) or re.findall(r"^(?!javascript)(.*://)*([%, ,A-z,0-9,\\.\\.]*[/,//,\\,\\\\]){1,}", decoded):
                self.log(f"DETECTED LFI or RFI: {request.full_path}")
                self.trigger_response()


class SQLiDetector(BaseDetector):
    dangerous = ["@variable", "AND", "OR", ",", "AS", "WHERE", "ORDER", "--", "/*", "#", "RLIKE", "SLEEP", "SELECT", "UNION", " * "]

    def run(self):
        for arg in request.args.values():
            upper = unquote(arg).upper()
            if any([el in upper for el in self.dangerous]) or upper.startswith("'") or upper.startswith('"'):
                self.log(f"DETECTED SQL injection: {request.full_path}")
                self.trigger_response()


class XSSDetector(BaseDetector):
    patterns = ["<", ">",  "/*", "*/", "script", " src=", " href=", "javascript", "cookie", "document."]

    def run(self):
        for arg in request.args.values():
            decoded = unquote(arg).lower()
            potentiality = 0
            if len(decoded) > 1:
                for ch in self.patterns:
                    potentiality += 1 if ch in decoded else 0
                if potentiality != 0:
                    self.log(f"DETECTED XSS: {request.full_path}")
                    self.trigger_response()


# === IDS / IPS основной класс ===
class IDS:
    def __init__(self, app):
        self.app: Flask = app.flask  # как ты и сказал — app имеет .flask
        self.detectors: list[BaseDetector] = []
        self.detect_funcs = []
        self.app.before_request(self.run_detectors)

    def add_detector(self, detector_cls):
        self.detectors.append(detector_cls(self.app))

    def run_detectors(self):
        for detector in self.detectors:
            detector.trigger_response = self.__on_detection_triggered
            detector.run()

    def __on_detection_triggered(self):
        for func in self.detect_funcs:
            func()


    def on_trigger(self, func):
        self.detect_funcs.append(func)


# === IPS класс ===
class IPS(IDS):
    def __init__(self, app):
        super().__init__(app)
        self.on_trigger(self.block_request)

    def block_request(self):
        self.app.logger.info(f"ABORTING CONNECTION: {request.remote_addr}")
        abort(400)