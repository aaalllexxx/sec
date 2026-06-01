import re
from enum import Enum
from flask import Flask, Response, request

# Максимальная длина входных данных для DLP-проверки (защита от ReDoS)
_MAX_INPUT_LENGTH = 1_000_000  # 1 MB


class DLPMode(Enum):
    Agressive = 0
    Passive = 1

class BasicFilter():
    regex = ""
    # Скомпилированный regex с обёрткой DLPSAFE — кешируется на уровне класса
    _compiled_check = None
    _compiled_hide = None

    @classmethod
    def _get_check_pattern(cls):
        """Возвращает скомпилированный regex для check(), кешируя результат."""
        if cls._compiled_check is None:
            wrapped = r"(?!\$DLPSAFE\{)" + cls.regex + r"(?!\})"
            cls._compiled_check = re.compile(wrapped)
        return cls._compiled_check

    @classmethod
    def _get_hide_pattern(cls):
        """Возвращает скомпилированный regex для hide(), кешируя результат."""
        if cls._compiled_hide is None:
            wrapped = r"(?!\$DLPSAFE\{)" + cls.regex + r"(?!\})"
            cls._compiled_hide = re.compile(wrapped)
        return cls._compiled_hide

    @classmethod
    def hide(cls, raw):
        if cls.check(raw):
            return cls._get_hide_pattern().sub("", raw)
        return raw

    @classmethod
    def check(cls, text):
        if len(text) > _MAX_INPUT_LENGTH:
            return False
        pattern = cls._get_check_pattern()
        data = pattern.search(text)
        return data if data else False

class MailFilter(BasicFilter):
    regex = r"[a-zA-Z0-9_.]+@[a-zA-Z0-9._]+\.[a-zA-Z.]{2,}"

class PhoneFilter(BasicFilter):
    regex = r"\+?\d{11}"

class PassportFilter(BasicFilter):
    regex = r"[0-9]{4} ?[0-9]{6}(?![0-9]+)"

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
                finding = finding.group(0).replace("$DLPSAFE{", "", 1)[::-1].replace("}", "", 1)[::-1]
                data = re.sub(r"\$DLPSAFE\{([^}]+)\}", finding, data, count=1)
        response.data = data.encode("utf-8")
        return response

    def add_filter(self, fltr):
        self.protection_filters.append(fltr)
        

    def on_trigger(self, func):
        self.detect_funcs.append(func)
