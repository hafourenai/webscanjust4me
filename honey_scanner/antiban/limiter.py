import time
import random
import logging

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
