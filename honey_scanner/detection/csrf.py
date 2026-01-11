import re
import math
import logging
from collections import Counter

class CSRFDetector:
    """Advanced CSRF detection helper."""

    SAFE_METHODS = {"get", "head", "options"}

    def __init__(self, scanner):
        self.scanner = scanner
        self.session = scanner.session
        self.framework_tokens = self._load_framework_patterns()
        self.min_token_entropy = 3.5
        self.min_token_length = 16

    def _load_framework_patterns(self):
        return {
            'django': ['csrfmiddlewaretoken'],
            'laravel': ['_token'],
            'spring': ['_csrf'],
            'aspnet': ['__RequestVerificationToken'],
            'rails': ['authenticity_token'],
            'express': ['_csrf'],
        }

    def analyze_form(self, form, page_html):
        result = {
            "vulnerable": False,
            "confidence": 0.0,
            "protections_found": [],
            "protections_missing": [],
            "tests": [],
            "evidence": {},
            "false_positive_reasons": [],
        }
        method = form.get("method", "get").lower()
        if method in self.SAFE_METHODS:
            result["false_positive_reasons"].append("Safe HTTP method")
            return result
        if self._is_public_form(form):
            result["false_positive_reasons"].append("Public form")
            return result
        
        token_info = self._detect_tokens(form)
        if token_info["found"]:
            result["protections_found"].append("token_based")
        else:
            result["protections_missing"].append("token_based")
        
        result["evidence"]["tokens"] = token_info
        if not token_info["found"]:
            result["vulnerable"] = True
            result["confidence"] = 0.7
        return result

    def _is_public_form(self, form):
        inputs = form.get("inputs", [])
        names = " ".join((i.get("name", "") or "").lower() for i in inputs)
        public_keywords = ["newsletter", "subscribe", "search", "contact"]
        return any(k in names for k in public_keywords)

    def _detect_tokens(self, form):
        result = {"found": False, "tokens": []}
        for inp in form.get("inputs", []):
            name = (inp.get("name") or "").lower()
            value = inp.get("value", "") or ""
            if any(k in name for k in ["csrf", "token", "xsrf"]):
                result["found"] = True
                result["tokens"].append({"name": name, "value": value})
        return result

    def _entropy(self, s):
        if not s: return 0.0
        counts = Counter(s)
        length = len(s)
        h = 0.0
        for c in counts.values():
            p = c / length
            h -= p * math.log2(p)
        return h
