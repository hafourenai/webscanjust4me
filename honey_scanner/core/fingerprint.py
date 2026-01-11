import re
import logging
import json

class AdvancedFingerprinting:
    """Advanced technology fingerprinting"""
    
    def __init__(self, session):
        self.session = session
        self.signatures = self.load_signatures()
        
    def load_signatures(self):
        return {
            'cms': {
                'wordpress': {
                    'headers': ['X-Powered-By: PHP', 'Link: .*wp-json'],
                    'body': ['wp-content', 'wp-includes', 'WordPress'],
                    'paths': ['/wp-admin/', '/wp-login.php'],
                    'meta': ['generator.*WordPress']
                },
                'drupal': {
                    'headers': ['X-Generator: Drupal'],
                    'body': ['Drupal.settings', '/sites/default/files'],
                    'paths': ['/user/login', '/node/'],
                    'meta': ['generator.*Drupal']
                },
                'joomla': {
                    'body': ['/components/com_', '/media/system/js/'],
                    'paths': ['/administrator/', '/index.php/component/'],
                    'meta': ['generator.*Joomla']
                },
                'magento': {
                    'body': ['/skin/frontend/', 'Mage.Cookies'],
                    'paths': ['/admin/', '/customer/account/'],
                    'cookies': ['frontend']
                }
            },
            'frameworks': {
                'laravel': {
                    'headers': ['Set-Cookie: laravel_session'],
                    'body': ['laravel', 'csrf-token'],
                    'errors': ['Illuminate\\', 'Laravel\\']
                },
                'django': {
                    'headers': ['Set-Cookie: csrftoken', 'Set-Cookie: sessionid'],
                    'body': ['csrfmiddlewaretoken'],
                    'errors': ['django.', 'DisallowedHost']
                },
                'rails': {
                    'headers': ['X-Runtime', 'Set-Cookie: _.*_session'],
                    'body': ['csrf-param', 'csrf-token'],
                    'errors': ['ActionController::', 'ActiveRecord::']
                },
                'express': {
                    'headers': ['X-Powered-By: Express'],
                    'errors': ['Error: Cannot GET']
                },
                'spring': {
                    'body': ['Whitelabel Error Page', 'Spring Framework'],
                    'errors': ['java.lang.', 'springframework']
                }
            },
            'waf': {
                'cloudflare': {
                    'headers': ['cf-ray', 'server: cloudflare'],
                    'body': ['cloudflare', 'cf-error-code'],
                    'cookies': ['__cflb', '__cfduid']
                },
                'akamai': {
                    'headers': ['server: AkamaiGHost'],
                    'body': ['Reference #'],
                    'cookies': ['ak_bmsc']
                },
                'aws_waf': {
                    'headers': ['x-amzn-RequestId', 'x-amz-cf-id'],
                    'body': ['Access Denied.*AWS']
                },
                'imperva': {
                    'body': ['Incapsula', '_Incapsula_Resource'],
                    'cookies': ['incap_ses', 'visid_incap']
                },
                'f5': {
                    'body': ['The requested URL was rejected'],
                    'cookies': ['TS', 'BIGipServer']
                },
                'modsecurity': {
                    'body': ['Mod_Security', 'ModSecurity'],
                    'errors': ['406 Not Acceptable']
                }
            },
            'cdn': {
                'cloudflare': {
                    'headers': ['cf-ray', 'server: cloudflare'],
                    'cookies': ['__cflb']
                },
                'cloudfront': {
                    'headers': ['x-amz-cf-id', 'via: .*CloudFront']
                },
                'fastly': {
                    'headers': ['x-fastly-request-id', 'x-served-by']
                },
                'maxcdn': {
                    'headers': ['server: NetDNA']
                }
            },
            'databases': {
                'mysql': {
                    'errors': ['mysql_fetch_array', 'MySQL.*Query', 'mysql_num_rows']
                },
                'postgresql': {
                    'errors': ['PostgreSQL.*ERROR', 'pg_query', 'pg_exec']
                },
                'mssql': {
                    'errors': ['Microsoft SQL', 'ODBC.*SQL Server', 'SQLServer JDBC']
                },
                'oracle': {
                    'errors': ['ORA-\\d{5}', 'Oracle.*Driver', 'java.sql.SQLException']
                },
                'mongodb': {
                    'errors': ['MongoError', 'MongoDB.*Exception']
                }
            },
            'languages': {
                'php': {
                    'headers': ['X-Powered-By: PHP'],
                    'extensions': ['.php'],
                    'errors': ['Parse error:', 'Fatal error:', 'Warning:']
                },
                'asp.net': {
                    'headers': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
                    'extensions': ['.aspx', '.asp'],
                    'errors': ['Server Error in.*Application', '__VIEWSTATE']
                },
                'java': {
                    'extensions': ['.jsp', '.do', '.action'],
                    'errors': ['java.lang.', 'javax.servlet']
                },
                'python': {
                    'errors': ['Traceback', 'File.*line', 'Python/']
                },
                'ruby': {
                    'headers': ['X-Runtime'],
                    'errors': ['Ruby on Rails', '.rb:', 'RubyGem']
                }
            }
        }
    
    def comprehensive_fingerprint(self, url):
        results = {
            'cms': None, 'framework': None, 'waf': [], 'cdn': None,
            'database': None, 'language': None, 'web_server': None,
            'os': None, 'additional_tech': []
        }
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            body = response.text
            cookies = response.cookies
            results['cms'] = self.detect_cms(headers, body, url)
            results['framework'] = self.detect_framework(headers, body)
            results['waf'] = self.detect_waf(headers, body, cookies)
            results['cdn'] = self.detect_cdn(headers, cookies)
            results['database'] = self.detect_database(body)
            results['language'] = self.detect_language(headers, body, url)
            results['web_server'] = self.detect_web_server(headers)
            results['os'] = self.detect_os(headers)
            results['additional_tech'] = self.detect_additional_tech(headers, body)
        except Exception as e:
            logging.error(f"Fingerprinting error: {e}")
        return results
    
    def _check_sigs(self, target_items, signatures, score_weight=2):
        score = 0
        for sig in signatures:
            if isinstance(target_items, dict): # Headers
                for k, v in target_items.items():
                    if re.search(sig, f"{k}: {v}", re.IGNORECASE): score += score_weight
            elif isinstance(target_items, str): # Body/URL
                if re.search(sig, target_items, re.IGNORECASE): score += score_weight
            else: # Cookies/Keys
                if any(re.search(sig, str(item), re.IGNORECASE) for item in target_items): score += score_weight
        return score

    def detect_cms(self, headers, body, url):
        for cms_name, sigs in self.signatures['cms'].items():
            score = 0
            score += self._check_sigs(headers, sigs.get('headers', []))
            score += self._check_sigs(body, sigs.get('body', []))
            score += self._check_sigs(body, sigs.get('meta', []), 3)
            if score >= 4: return cms_name
        return None

    def detect_framework(self, headers, body):
        for name, sigs in self.signatures['frameworks'].items():
            score = 0
            score += self._check_sigs(headers, sigs.get('headers', []))
            score += self._check_sigs(body, sigs.get('body', []))
            score += self._check_sigs(body, sigs.get('errors', []), 3)
            if score >= 3: return name
        return None

    def detect_waf(self, headers, body, cookies):
        detected = []
        for name, sigs in self.signatures['waf'].items():
            score = 0
            score += self._check_sigs(headers, sigs.get('headers', []), 3)
            score += self._check_sigs(body, sigs.get('body', []))
            score += self._check_sigs([c.name for c in cookies], sigs.get('cookies', []))
            if score >= 2: detected.append(name)
        return detected

    def detect_cdn(self, headers, cookies):
        for name, sigs in self.signatures['cdn'].items():
            score = 0
            score += self._check_sigs(headers, sigs.get('headers', []))
            score += self._check_sigs([c.name for c in cookies], sigs.get('cookies', []), 1)
            if score >= 2: return name
        return None

    def detect_database(self, body):
        for name, sigs in self.signatures['databases'].items():
            if self._check_sigs(body, sigs.get('errors', [])) > 0: return name
        return None

    def detect_language(self, headers, body, url):
        for name, sigs in self.signatures['languages'].items():
            score = 0
            score += self._check_sigs(headers, sigs.get('headers', []))
            score += self._check_sigs(body, sigs.get('errors', []))
            for ext in sigs.get('extensions', []):
                if ext in url.lower(): score += 3
            if score >= 2: return name
        return None

    def detect_web_server(self, headers):
        srv = headers.get('Server', '').lower()
        for s in ['apache', 'nginx', 'iis', 'lighttpd', 'openresty']:
            if s in srv: return s.title()
        return None

    def detect_os(self, headers):
        srv = headers.get('Server', '').lower()
        if any(x in srv for x in ['ubuntu', 'debian']): return 'Linux (Debian-based)'
        if any(x in srv for x in ['centos', 'red hat']): return 'Linux (Red Hat-based)'
        if 'win' in srv: return 'Windows'
        if 'unix' in srv: return 'Unix'
        return None

    def detect_additional_tech(self, headers, body):
        techs = []
        js_libs = {'jQuery': r'jquery', 'React': r'react', 'Vue.js': r'vue', 'Angular': r'angular', 'Bootstrap': r'bootstrap'}
        for name, pat in js_libs.items():
            if re.search(pat, body, re.IGNORECASE): techs.append(name)
        analytics = {'Google Analytics': r'google-analytics', 'Google Tag Manager': r'googletagmanager', 'Facebook Pixel': r'connect\.facebook', 'Hotjar': r'hotjar'}
        for name, pat in analytics.items():
            if re.search(pat, body, re.IGNORECASE): techs.append(name)
        return techs
