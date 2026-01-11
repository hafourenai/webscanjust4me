import json
import hashlib
import time
import requests
import re
import urllib.parse
import html
from difflib import SequenceMatcher
from collections import defaultdict
import logging

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
                    'content_hash': hashlib.md5(response.text.encode()).hexdigest(),
                    'text': response.text
                })
            except:
                pass
        
        if responses:
            baseline = {
                'avg_length': sum(r['length'] for r in responses) / len(responses),
                'avg_time': sum(r['time'] for r in responses) / len(responses),
                'common_status': max(set(r['status'] for r in responses), 
                                    key=lambda x: sum(1 for r in responses if r['status'] == x)),
                'content_hashes': [r['content_hash'] for r in responses],
                'text': responses[0]['text'] # Use first response as text baseline
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
        
        length_diff = abs(len(test_response.text) - baseline['avg_length'])
        length_ratio = length_diff / baseline['avg_length'] if baseline['avg_length'] > 0 else 0
        if length_ratio > 0.3:
            anomaly_score += 0.25
            indicators.append(f"Significant length change: {length_ratio:.2%}")
        
        if test_response.status_code != baseline['common_status']:
            anomaly_score += 0.15
            indicators.append(f"Status code changed: {baseline['common_status']} -> {test_response.status_code}")
        
        test_hash = hashlib.md5(test_response.text.encode()).hexdigest()
        if test_hash not in baseline['content_hashes']:
            sim = SequenceMatcher(None, test_response.text[:1000], baseline['text'][:1000]).ratio()
            if sim < 0.7:
                anomaly_score += 0.35
                indicators.append(f"Content significantly different (similarity: {sim:.2%})")
        
        time_diff = abs(test_response.elapsed.total_seconds() - baseline['avg_time'])
        if time_diff > 3:
            anomaly_score += 0.25
            indicators.append(f"Response time anomaly: +{time_diff:.2f}s")
        
        return {
            'confidence': min(anomaly_score, 1.0),
            'anomaly_detected': anomaly_score > 0.5,
            'indicators': indicators,
            'anomaly_score': anomaly_score
        }
    
    def verify_time_based_vulnerability(self, url, params, payload_param, session):
        timings = {'normal': [], 'payload': []}
        for _ in range(3):
            start = time.time()
            try:
                session.get(url, params=params, timeout=15)
                timings['normal'].append(time.time() - start)
            except:
                pass
            time.sleep(0.5)
        
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
        if payload not in response_text:
            return {'vulnerable': False, 'confidence': 0}
        
        injection_points = []
        for match in re.finditer(re.escape(payload), response_text):
            start = max(0, match.start() - 100)
            end = min(len(response_text), match.end() + 100)
            injection_points.append(response_text[start:end])
        
        vulnerabilities = []
        encoded_versions = [html.escape(payload), urllib.parse.quote(payload)]
        
        for context in injection_points:
            context_lower = context.lower()
            if any(enc in context for enc in encoded_versions if enc != payload):
                continue
            
            if '<script' in context_lower and '</script>' in context_lower:
                if any(x in payload.lower() for x in ['alert', 'eval', 'document', 'window']):
                    vulnerabilities.append({'context': 'script', 'severity': 'high', 'confidence': 0.92, 'reason': 'Script injection'})
            elif re.search(r'<\w+[^>]*' + re.escape(payload) + r'[^>]*>', context):
                if any(event in payload.lower() for event in ['onerror', 'onload', 'onclick']):
                    vulnerabilities.append({'context': 'attribute_event', 'severity': 'high', 'confidence': 0.88, 'reason': 'Event handler'})
            elif '<' + payload in context or payload + '>' in context:
                vulnerabilities.append({'context': 'tag', 'severity': 'medium', 'confidence': 0.72, 'reason': 'Tag injection'})
        
        if vulnerabilities:
            return {'vulnerable': True, 'confidence': max(v['confidence'] for v in vulnerabilities), 'contexts': vulnerabilities}
        return {'vulnerable': False, 'confidence': 0}
    
    def analyze_sql_context(self, response_text, payload):
        confidence_score = 0
        indicators = []
        error_patterns = {
            'mysql': [r"You have an error in your SQL syntax", r"mysql_fetch_array\(\)"],
            'postgresql': [r"PostgreSQL.*?ERROR", r"pg_query\(\)"],
            'mssql': [r"Microsoft OLE DB Provider.*?SQL Server"],
            'oracle': [r"ORA-\d+"]
        }
        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence_score = max(confidence_score, 0.9)
                    indicators.append(f"{db_type.upper()} error")
        return {'vulnerable': confidence_score > 0.7, 'confidence': confidence_score, 'indicators': indicators}

    def analyze_lfi_context(self, response_text, payload):
        confidence = 0
        evidence = []
        file_patterns = {
            'passwd': r'root:.*?:\d+:\d+:',
            'winini': r'\[boot loader\]'
        }
        for name, pattern in file_patterns.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                confidence = 0.95
                evidence.append(f"{name} found")
        return {'vulnerable': confidence > 0.7, 'confidence': confidence, 'evidence': evidence}
