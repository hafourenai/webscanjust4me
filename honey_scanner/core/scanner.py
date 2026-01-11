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

class VulnScanner:
    def __init__(self, target_url, max_threads=15, crawl_depth=5, stealth_mode=False, 
                 aggressive_mode=False, proxy_file=None, use_tor=False, rate_limit=1.0):
        self.target_url = target_url
        self.max_threads = max_threads
        self.crawl_depth = crawl_depth
        self.stealth_mode = stealth_mode
        self.aggressive_mode = aggressive_mode
        self.base_domain = urlparse(target_url).netloc
        
        # Components
        self.proxy_rotator = ProxyRotator()
        if proxy_file:
            self.proxy_rotator.load_proxies(proxy_file)
        
        self.tor_manager = TorManager() if use_tor else None
        self.rate_limiter = RateLimiter(requests_per_second=rate_limit)
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
        try:
            if method == 'get': response = self.session.get(url, **kwargs)
            elif method == 'post': response = self.session.post(url, **kwargs)
            else: response = self.session.get(url, **kwargs)
            
            is_blocked, _ = self.block_detector.is_blocked(response=response)
            if is_blocked:
                self.rate_limiter.on_block_detected()
                return None
            
            self.rate_limiter.on_success()
            return response
        except Exception as e:
            self.block_detector.is_blocked(exception=e)
            return None

    def init_payloads(self):
        # Implementation of payload loading (simplified for brevity, should follow original logic)
        self.sqli_payloads = {"boolean_based": ["' OR '1'='1", "' OR '1'='2"]}
        self.xss_payloads = {"basic": ["<script>alert(1)</script>"]}
        self.lfi_payloads = ["../../../../etc/passwd"]

    def crawl(self, url=None, depth=0):
        if depth > self.crawl_depth: return
        current_url = url or self.target_url
        if current_url in self.visited_urls: return
        
        if depth == 0:
            self.tech_stack_full = self.fingerprinter.comprehensive_fingerprint(self.target_url)
            if self.tech_stack_full.get('waf'):
                self.detected_waf = self.tech_stack_full['waf'][0]
        
        try:
            response = self.safe_request('get', current_url, timeout=10)
            if not response: return
            self.visited_urls.add(current_url)
            self._extract_links(response.text, current_url)
            # Add more analysis here...
        except Exception as e:
            logging.error(f"Crawl error: {e}")

    def _extract_links(self, html_content, base_url):
        soup = BeautifulSoup(html_content, 'html.parser')
        for a in soup.find_all('a', href=True):
            full_url = urljoin(base_url, a['href'])
            if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                self.discovered_urls.add(full_url)

    def report_vulnerability(self, **kwargs):
        self.vulnerabilities.append(kwargs)
        logging.info(f"VULNERABILITY FOUND: {kwargs['vuln_type']} at {kwargs['url']}")

    def generate_report(self):
        scan_info = {
            'target': self.target_url,
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'tech_stack': self.tech_stack_full
        }
        reporter = EnhancedReporting(self.vulnerabilities, scan_info)
        return reporter.generate_all_reports()
