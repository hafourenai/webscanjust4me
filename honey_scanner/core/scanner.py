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
import random
import re
import os
import ssl
from fake_useragent import UserAgent
import xml.etree.ElementTree as ET

# Modular imports
from ..antiban.proxy import ProxyRotator, TorManager
from ..antiban.limiter import RateLimiter, BlockDetector
from ..core.engine import WAFBypassEngine, MLFalsePositiveReducer
from ..core.fingerprint import AdvancedFingerprinting
from ..detection.analyzers import BehavioralAnalyzer, ContextAnalyzer
from ..detection.verifier import AutomatedVerifier
from ..detection.csrf import CSRFDetector
from ..reporting.reporter import EnhancedReporting
from .config import config

class VulnScanner:
    def __init__(self, target_url, max_threads=None, crawl_depth=None, stealth_mode=False, 
                 aggressive_mode=False, proxy_file=None, use_tor=False, rate_limit=None):
        self.target_url = target_url
        self.max_threads = max_threads or config.get('scanning.default_threads', 15)
        self.crawl_depth = crawl_depth or config.get('scanning.default_depth', 5)
        self.stealth_mode = stealth_mode
        self.aggressive_mode = aggressive_mode
        self.base_domain = urlparse(target_url).netloc
        
        # Requests configuration
        self.timeout = config.get('scanning.timeout', 10)
        
        # Components
        self.proxy_rotator = ProxyRotator()
        if proxy_file:
            self.proxy_rotator.load_proxies(proxy_file)
        
        self.tor_manager = TorManager() if use_tor else None
        self.rate_limit_val = rate_limit or config.get('scanning.default_rate_limit', 1.0)
        self.rate_limiter = RateLimiter(requests_per_second=self.rate_limit_val)
        self.block_detector = BlockDetector()
        self.use_proxies = bool(proxy_file) or use_tor
        
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        if self.use_proxies:
            self._setup_proxies(use_tor)

        self.behavioral_analyzer = BehavioralAnalyzer()
        self.context_analyzer = ContextAnalyzer()
        self.verifier = AutomatedVerifier(self.session)
        self.csrf_detector = CSRFDetector(self)
        self.waf_bypass = WAFBypassEngine()
        self.ml_reducer = MLFalsePositiveReducer()
        self.fingerprinter = AdvancedFingerprinting(self.session)
        
        self.ua = UserAgent()
        self.visited_urls = set()
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.forms = []
        self.visited_lock = threading.Lock()
        self.tech_stack = {}
        self.tech_stack_full = {}
        self.detected_waf = None
        
        self.init_payloads()
        
    def _setup_proxies(self, use_tor):
        if use_tor and self.tor_manager and self.tor_manager.tor_available:
            self.session.proxies = self.tor_manager.get_tor_proxy()
        elif self.proxy_rotator.proxies:
            self.session.proxies = self.proxy_rotator.get_proxy()

    def safe_request(self, method='get', url=None, **kwargs):
        self.rate_limiter.wait()
        retries = 3
        for i in range(retries):
            try:
                # Use timeout from config if not provided
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = self.timeout
                
                if method == 'get': response = self.session.get(url, **kwargs)
                elif method == 'post': response = self.session.post(url, **kwargs)
                else: response = self.session.get(url, **kwargs)
                
                is_blocked, _ = self.block_detector.is_blocked(response=response)
                if is_blocked:
                    self.rate_limiter.on_block_detected()
                    # If blocked, maybe wait longer or rotate proxy
                    time.sleep(config.get('antiban.retry_delay', 2) * (i + 1))
                    continue
                
                self.rate_limiter.on_success()
                return response
            except (requests.exceptions.RequestException, ssl.SSLError) as e:
                logging.debug(f"Request error (attempt {i+1}/{retries}): {e}")
                if i == retries - 1:
                    self.block_detector.is_blocked(exception=e)
                    return None
                time.sleep(config.get('antiban.retry_delay', 2))
        return None

    def init_payloads(self):
        """Load vulnerability payloads from files using config"""
        self.sqli_payloads = {}
        self.xss_payloads = []
        self.lfi_payloads = []
        
        # Get base directory for payloads
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        payload_base_name = config.get('payloads.base_path', 'Payloads')
        base_dir = os.path.join(project_root, payload_base_name)
        
        # Load SQLi payloads
        try:
            sqli_config = config.get('payloads.sqli', {})
            limit = sqli_config.get('limit_per_type', 50)
            
            for key in ['boolean', 'error', 'time', 'union']:
                filename = sqli_config.get(key)
                if not filename: continue
                
                file_path = os.path.join(base_dir, filename)
                full_key = f"{key}_based"
                
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        self.sqli_payloads[full_key] = [line.strip() for line in f if line.strip()][:limit]
                else:
                    logging.warning(f"SQLi payload file not found: {file_path}")
                    self.sqli_payloads[full_key] = []
                    
        except Exception as e:
            logging.error(f"Error loading SQLi payloads: {e}")
            self.sqli_payloads = {'error_based': ["' OR '1'='1"]}
        
        # Load XSS payloads
        try:
            xss_rel_path = config.get('payloads.xss.path', 'XSS/payload.txt')
            limit = config.get('payloads.xss.limit', 100)
            xss_file = os.path.join(base_dir, xss_rel_path)
            
            if os.path.exists(xss_file):
                with open(xss_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.xss_payloads = [line.strip() for line in f if line.strip()][:limit]
            else:
                logging.warning(f"XSS payload file not found: {xss_file}")
                self.xss_payloads = ["<script>alert(1)</script>"]
        except Exception as e:
            logging.error(f"Error loading XSS payloads: {e}")
            self.xss_payloads = ["<script>alert(1)</script>"]
        
        # Load LFI payloads
        try:
            lfi_rel_path = config.get('payloads.lfi.path', 'LFI/JHADDIX_LFI.txt')
            limit = config.get('payloads.lfi.limit', 50)
            lfi_file = os.path.join(base_dir, lfi_rel_path)
            
            if os.path.exists(lfi_file):
                with open(lfi_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.lfi_payloads = [line.strip() for line in f if line.strip()][:limit]
            else:
                logging.warning(f"LFI payload file not found: {lfi_file}")
                self.lfi_payloads = ["../../../../etc/passwd"]
        except Exception as e:
            logging.error(f"Error loading LFI payloads: {e}")
            self.lfi_payloads = ["../../../../etc/passwd"]
        
        logging.info(f"Loaded payloads properly from {base_dir}")

    def crawl(self, url=None):
        """Concurrent crawler to discover endpoints"""
        current_url = url or self.target_url
        print(f"[*] Starting crawl on {current_url} (depth: {self.crawl_depth})")
        
        # Initial fingerprinting
        self.tech_stack_full = self.fingerprinter.comprehensive_fingerprint(current_url)
        if self.tech_stack_full.get('waf'):
            self.detected_waf = self.tech_stack_full['waf'][0]
            logging.info(f"WAF detected: {self.detected_waf}")

        queue = [(current_url, 0)]
        self.discovered_urls.add(current_url)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while queue and len(self.visited_urls) < 100:  # Limit unique pages for safety
                # Process current level
                current_batch = queue[:self.max_threads * 2]
                queue = queue[self.max_threads * 2:]
                
                futures = []
                for url, depth in current_batch:
                    if url not in self.visited_urls and depth <= self.crawl_depth:
                        futures.append(executor.submit(self._crawl_worker, url, depth))
                
                for future in as_completed(futures):
                    new_links, depth = future.result()
                    if depth < self.crawl_depth:
                        for link in new_links:
                            with self.visited_lock:
                                if link not in self.discovered_urls:
                                    self.discovered_urls.add(link)
                                    queue.append((link, depth + 1))
        
        print(f"[+] Crawl complete. Discovered {len(self.discovered_urls)} URLs.")

    def _crawl_worker(self, url, depth):
        """Worker function for concurrent crawling"""
        with self.visited_lock:
            if url in self.visited_urls:
                return [], depth
            self.visited_urls.add(url)
            
        try:
            response = self.safe_request('get', url, timeout=10)
            if not response:
                return [], depth
            
            soup = BeautifulSoup(response.text, 'html.parser')
            self._extract_forms(soup, url)
            
            new_links = []
            for a in soup.find_all('a', href=True):
                full_url = urljoin(url, a['href']).split('#')[0].rstrip('/')
                parsed = urlparse(full_url)
                if parsed.netloc == self.base_domain:
                    new_links.append(full_url)
            
            return new_links, depth
            
        except Exception as e:
            logging.error(f"Crawl worker error for {url}: {e}")
            return [], depth

    def _extract_links(self, html_content, base_url):
        soup = BeautifulSoup(html_content, 'html.parser')
        for a in soup.find_all('a', href=True):
            full_url = urljoin(base_url, a['href'])
            if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                self.discovered_urls.add(full_url)
    
    def _extract_forms(self, soup, page_url):
        """Extract forms from HTML for testing"""
        for form in soup.find_all('form'):
            form_details = {
                'action': urljoin(page_url, form.get('action', page_url)),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    form_details['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_tag.get('value', '')
                    })
            
            if form_details['inputs']:
                self.forms.append(form_details)
                logging.debug(f"Found form: {form_details['action']} with {len(form_details['inputs'])} inputs")

    def test_sqli(self):
        """Test for SQL Injection vulnerabilities concurrently"""
        print("[*] Testing for SQL Injection...")
        tested_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            # Test URL parameters
            for url in self.discovered_urls:
                futures.append(executor.submit(self._test_sqli_url, url))
            
            # Test forms
            for form in self.forms:
                futures.append(executor.submit(self._test_sqli_form, form))
                
            for future in as_completed(futures):
                tested_count += future.result()
        
        print(f"[+] SQLi testing complete. Tested {tested_count} injection points.")

    def _test_sqli_url(self, url):
        points = 0
        parsed = urlparse(url)
        if not parsed.query: return 0
        
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for param in params.keys():
            points += 1
            for payload_type, payloads in self.sqli_payloads.items():
                if not payloads: continue
                for payload in payloads[:3]:
                    if self.detected_waf:
                        payload = self.waf_bypass.bypass_specific_waf(payload, self.detected_waf)
                    
                    test_params = params.copy()
                    test_params[param] = payload
                    try:
                        response = self.safe_request('get', f"{parsed.scheme}://{parsed.netloc}{parsed.path}", 
                                                    params=test_params, timeout=10)
                        if response and self._check_sqli_vuln(response, payload_type, url, param, params, payload, 'GET'):
                            return points # Stop testing this param if found
                    except: continue
        return points

    def _test_sqli_form(self, form):
        points = 0
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'reset']:
                points += 1
                param_name = input_field['name']
                for payload in self.sqli_payloads.get('error_based', [])[:3]:
                    form_data = {inp['name']: inp.get('value', '') for inp in form['inputs']}
                    form_data[param_name] = payload
                    try:
                        method = form['method'].lower()
                        response = self.safe_request(method, form['action'], 
                                                   data=form_data if method == 'post' else None,
                                                   params=form_data if method == 'get' else None, 
                                                   timeout=10)
                        if response and self._check_sqli_vuln(response, 'error_based', form['action'], param_name, form_data, payload, method.upper()):
                            return points
                    except: continue
        return points

    def _check_sqli_vuln(self, response, payload_type, url, param, params, payload, method):
        if payload_type == 'error_based' and re.search(r"SQL syntax|mysql_fetch|PostgreSQL.*?ERROR|OLE DB|SQLite", response.text, re.IGNORECASE):
            verification = self.verifier.verify_sqli_with_multiple_techniques(url, param, params)
            if verification['vulnerable']:
                confidence = self.ml_reducer.calculate_confidence({'vuln_type': 'sqli', 'proof': response.text, 'status_code': response.status_code, 'payload': payload, 'verified': True})
                if confidence > 0.6:
                    self.report_vulnerability(vuln_type='SQL Injection', url=url, parameter=param, payload=payload, method=method, confidence=confidence, severity='High', proof=response.text[:2000], verification_details=verification['details'])
                    return True
        return False

    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities concurrently"""
        print("[*] Testing for XSS...")
        tested_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for url in self.discovered_urls:
                futures.append(executor.submit(self._test_xss_url, url))
            for form in self.forms:
                futures.append(executor.submit(self._test_xss_form, form))
                
            for future in as_completed(futures):
                tested_count += future.result()
        
        print(f"[+] XSS testing complete. Tested {tested_count} injection points.")

    def _test_xss_url(self, url):
        points = 0
        parsed = urlparse(url)
        if not parsed.query: return 0
        
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for param in params.keys():
            points += 1
            for payload in self.xss_payloads[:10]:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    response = self.safe_request('get', f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                                params=test_params, timeout=10)
                    if response and (payload in response.text or html.unescape(payload) in response.text):
                        if self._check_xss_vuln(response, url, param, params, payload, 'GET'):
                            return points
                except: continue
        return points

    def _test_xss_form(self, form):
        points = 0
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'reset']:
                points += 1
                param_name = input_field['name']
                for payload in self.xss_payloads[:5]:
                    form_data = {inp['name']: inp.get('value', '') for inp in form['inputs']}
                    form_data[param_name] = payload
                    try:
                        method = form['method'].lower()
                        response = self.safe_request(method, form['action'], 
                                                   data=form_data if method == 'post' else None,
                                                   params=form_data if method == 'get' else None,
                                                   timeout=10)
                        if response and (payload in response.text or html.unescape(payload) in response.text):
                            if self._check_xss_vuln(response, form['action'], param_name, form_data, payload, method.upper()):
                                return points
                    except: continue
        return points

    def _check_xss_vuln(self, response, url, param, params, payload, method):
        verification = self.verifier.verify_xss_with_multiple_vectors(url, param, params, method=method)
        if verification['vulnerable']:
            confidence = self.ml_reducer.calculate_confidence({'vuln_type': 'xss', 'proof': response.text[:500], 'status_code': response.status_code, 'payload': payload, 'verified': True})
            if confidence > 0.6:
                self.report_vulnerability(vuln_type='Cross-Site Scripting (XSS)', url=url, parameter=param, payload=payload, method=method, confidence=confidence, severity='Medium', proof=response.text[:2000])
                return True
        return False

    def test_lfi(self):
        """Test for Local File Inclusion vulnerabilities concurrently"""
        print("[*] Testing for LFI...")
        tested_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for url in self.discovered_urls:
                futures.append(executor.submit(self._test_lfi_url, url))
            for future in as_completed(futures):
                tested_count += future.result()
        
        print(f"[+] LFI testing complete. Tested {tested_count} injection points.")

    def _test_lfi_url(self, url):
        points = 0
        file_params = ['file', 'page', 'path', 'doc', 'document', 'folder', 'root', 'pg', 'style', 
                      'pdf', 'template', 'php_path', 'document_root']
        parsed = urlparse(url)
        if not parsed.query: return 0
        
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for param in params.keys():
            if self.aggressive_mode or any(fp in param.lower() for fp in file_params):
                points += 1
                for payload in self.lfi_payloads[:10]:
                    test_params = params.copy()
                    test_params[param] = payload
                    try:
                        response = self.safe_request('get', f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                                    params=test_params, timeout=10)
                        if response and re.search(r'root:x:|bin/bash|\\[boot loader\\]|\\[operating systems\\]', 
                                               response.text, re.IGNORECASE):
                            verification = self.verifier.verify_lfi_with_multiple_files(url, param, params)
                            if verification['vulnerable']:
                                confidence = self.ml_reducer.calculate_confidence({'vuln_type': 'lfi', 'proof': response.text, 'status_code': response.status_code, 'payload': payload, 'verified': True})
                                if confidence > 0.7:
                                    self.report_vulnerability(vuln_type='Local File Inclusion (LFI)', url=url, parameter=param, payload=payload, method='GET', confidence=confidence, severity='High', proof=response.text[:2000])
                                    return points
                    except: continue
        return points

    def run_tests(self):
        """Main test orchestration method"""
        print("\n[*] Starting Vulnerability Testing Phase...")
        print(f"[*] Discovered {len(self.discovered_urls)} URLs and {len(self.forms)} forms\n")
        
        if not self.discovered_urls and not self.forms:
            print("[!] No testable endpoints found. Increase crawl depth or check target accessibility.")
            return
        
        # Run all tests
        self.test_sqli()
        self.test_xss()
        self.test_lfi()
        
        # Test CSRF if forms found
        if self.forms:
            print("[*] Testing for CSRF...")
            try:
                csrf_vulns = self.csrf_detector.detect_csrf_issues()
                print(f"[+] CSRF testing complete. Found {len(csrf_vulns)} potential issues.")
            except Exception as e:
                logging.error(f"CSRF testing error: {e}")
        
        print(f"\n[+] Testing complete. Found {len(self.vulnerabilities)} vulnerabilities.")

    def report_vulnerability(self, **kwargs):
        # Ensure level is consistent with severity/risk for reporting
        if 'level' not in kwargs and 'severity' in kwargs:
            kwargs['level'] = kwargs['severity']
        elif 'level' not in kwargs:
            kwargs['level'] = 'Medium'
            
        self.vulnerabilities.append(kwargs)
        logging.info(f"VULNERABILITY FOUND: {kwargs['vuln_type']} at {kwargs['url']} [Risk: {kwargs['level']}]")

    def generate_report(self):
        scan_info = {
            'target': self.target_url,
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'tech_stack': self.tech_stack_full
        }
        reporter = EnhancedReporting(self.vulnerabilities, scan_info)
        return reporter.generate_all_reports()
