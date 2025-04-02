import re
from enum import Enum
from flask import Flask, Response, request

class DLPMode(Enum):
    Agressive = 0
    Passive = 1

class BasicFilter():
    regex = ""

    @classmethod
    def hide(cls, raw):
        data = cls.check(raw)
        while data:
            return re.sub(cls.regex, "#" * len(data.group(0)), raw)
        return raw

    @classmethod
    def check(cls, text):
        cls.regex = r"(?!\$DLPSAFE\{)" + cls.regex + r"(?!\})"
        data = re.search(cls.regex, text)
        return data if data else False
    
class MailFilter(BasicFilter):
    regex = r"[a-zA-Z0-9_\.]+\@[a-zA-Z0-9\._]+\.[a-zA-Z\.]{2,}"

class PhoneFilter(BasicFilter):
    regex = r"\+*\d{11}"

class DLP:
    allowed = []
    def __init__(self, app, mode = DLPMode.Agressive):
        self.app: Flask = app.flask
        self.protection_filters = []
        self.detect_funcs = []
        self.mode = mode
        self.app.after_request(self.protect)

    def protect(self, response: Response):
        response.direct_passthrough = False
        data = response.data.decode("utf-8")
        for filter in self.protection_filters:
            for function in self.detect_funcs:
                try:
                    function(response)
                except AttributeError:
                    function()
            if self.mode == DLPMode.Agressive:
                data = filter.hide(data)
                
        for finding in re.finditer(r"\$DLPSAFE\{([^}]+)\}", data):
            if finding:
                finding = finding.group(0).replace("$DLPSAFE{", "", count=1)[::-1].replace("}", "", count=1)[::-1]
                data = re.sub(r"\$DLPSAFE\{([^}]+)\}", finding, data, count=1)
        response.data = data.encode("utf-8")
        return response

    def add_filter(self, fltr):
        self.protection_filters.append(fltr)
        

    def on_trigger(self, func):
        self.detect_funcs.append(func)