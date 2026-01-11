import requests
import logging
import os
import random

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
    
    def _clean_proxy_line(self, line):
        """Clean dan validate proxy line"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        if '31.59.20.176' in line: # Example of sensitive IP filtering
            logging.warning(f"Skipping proxy with target IP: {line}")
            return None
        
        if not line.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            if '@' in line:
                line = 'http://' + line
            else:
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
        if isinstance(proxy, dict):
            return proxy
        
        if '://' not in proxy:
            proxy = 'http://' + proxy
        
        if '@' in proxy:
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
