import re
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
import hashlib

class AbuseDetector:
    """Detect various types of abuses in server logs"""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r'union.*select', r'select.*from', r'insert.*into',
        r'update.*set', r'delete.*from', r'drop.*table',
        r'--', r'\/\*.*\*\/', r'waitfor.*delay', r'benchmark\(',
        r'sleep\(', r'pg_sleep\(', r'and.*1=1', r'or.*1=1'
    ]
    
    # Scanner patterns
    SCANNER_PATTERNS = [
        r'sqlmap', r'nikto', r'nmap', r'wpscan', r'gobuster',
        r'dirb', r'dirbuster', r'acunetix', r'nessus', r'openvas'
    ]
    
    def __init__(self, config=None):
        self.config = config or {}
        self.compiled_sql_patterns = [re.compile(p, re.I) for p in self.SQL_INJECTION_PATTERNS]
        self.compiled_scanner_patterns = [re.compile(p, re.I) for p in self.SCANNER_PATTERNS]
    
    def analyze(self, logs: Dict) -> Dict[str, Any]:
        """Main analysis function"""
        
        findings = {
            'suspicious_endpoints': [],
            'malicious_ips': [],
            'data_dumps': [],
            'sql_injections': [],
            'scanner_activity': [],
            'timeline': [],
            'statistics': {}
        }
        
        # Process Nginx logs
        if 'nginx' in logs:
            nginx_findings = self._analyze_nginx(logs['nginx'])
            findings.update(nginx_findings)
        
        # Process PHP logs
        if 'php' in logs:
            php_findings = self._analyze_php(logs['php'])
            findings['php_errors'] = php_findings
        
        # Process MySQL logs
        if 'mysql' in logs:
            mysql_findings = self._analyze_mysql(logs['mysql'])
            findings['suspicious_queries'] = mysql_findings
        
        # Correlate findings
        self._correlate_findings(findings)
        
        # Calculate risk scores
        self._calculate_risk_scores(findings)
        
        return findings
    
    def _analyze_nginx(self, logs: pd.DataFrame) -> Dict:
        """Analyze Nginx access logs"""
        
        findings = {
            'endpoint_abuse': self._detect_endpoint_abuse(logs),
            'data_dump': self._detect_data_dumps(logs),
            'malicious_ips': self._detect_malicious_ips(logs),
            'sqli_attempts': self._detect_sql_injection(logs),
            'scanners': self._detect_scanners(logs),
            'brute_force': self._detect_brute_force(logs)
        }
        
        return findings
    
    def _detect_endpoint_abuse(self, logs: pd.DataFrame) -> List[Dict]:
        """Detect endpoint abuse patterns"""
        
        suspicious_endpoints = []
        
        # Group by endpoint
        endpoint_stats = logs.groupby('endpoint').agg({
            'ip': 'nunique',
            'timestamp': 'count',
            'body_bytes_sent': ['sum', 'mean', 'max'],
            'status': lambda x: Counter(x)
        }).round(2)
        
        endpoint_stats.columns = ['unique_ips', 'total_requests', 
                                  'total_data', 'avg_data', 'max_data', 'status_dist']
        
        # Calculate request rate (requests per minute)
        time_range = (logs['timestamp'].max() - logs['timestamp'].min()).total_seconds() / 60
        endpoint_stats['reqs_per_min'] = endpoint_stats['total_requests'] / max(time_range, 1)
        
        # Identify suspicious endpoints
        high_traffic = endpoint_stats[endpoint_stats['total_requests'] > 
                                     endpoint_stats['total_requests'].quantile(0.95)]
        
        large_data = endpoint_stats[endpoint_stats['total_data'] > 
                                   endpoint_stats['total_data'].quantile(0.95)]
        
        high_rate = endpoint_stats[endpoint_stats['reqs_per_min'] > 
                                  endpoint_stats['reqs_per_min'].quantile(0.95)]
        
        # Combine suspicious endpoints
        suspicious = pd.concat([high_traffic, large_data, high_rate]).drop_duplicates()
        
        for endpoint, row in suspicious.iterrows():
            suspicious_endpoints.append({
                'endpoint': endpoint,
                'total_requests': int(row['total_requests']),
                'unique_ips': int(row['unique_ips']),
                'total_data_mb': row['total_data'] / (1024 * 1024),
                'requests_per_minute': row['reqs_per_min'],
                'status_codes': dict(row['status_dist']),
                'average_response_size': row['avg_data']
            })
        
        return suspicious_endpoints
    
    def _detect_data_dumps(self, logs: pd.DataFrame) -> List[Dict]:
        """Detect potential data dump activities"""
        
        data_dumps = []
        
        # Filter large responses (> 1MB)
        large_responses = logs[logs['body_bytes_sent'] > 1024 * 1024]
        
        if not large_responses.empty:
            # Group by IP and endpoint
            grouped = large_responses.groupby(['ip', 'endpoint']).agg({
                'body_bytes_sent': ['sum', 'count', 'mean'],
                'timestamp': ['min', 'max']
            }).round(2)
            
            grouped.columns = ['total_size', 'request_count', 'avg_size', 
                              'first_request', 'last_request']
            
            # Calculate data transfer rate
            for (ip, endpoint), row in grouped.iterrows():
                time_diff = (row['last_request'] - row['first_request']).total_seconds()
                rate = row['total_size'] / max(time_diff, 1) if time_diff > 0 else row['total_size']
                
                if row['total_size'] > 10 * 1024 * 1024:  # > 10MB total
                    data_dumps.append({
                        'ip': ip,
                        'endpoint': endpoint,
                        'total_data_mb': row['total_size'] / (1024 * 1024),
                        'request_count': int(row['request_count']),
                        'average_size_mb': row['avg_size'] / (1024 * 1024),
                        'data_rate_mbps': (rate * 8) / (1024 * 1024),
                        'time_window_minutes': time_diff / 60 if time_diff > 0 else 0,
                        'first_request': row['first_request'].isoformat(),
                        'last_request': row['last_request'].isoformat()
                    })
        
        return data_dumps
    
    def _detect_malicious_ips(self, logs: pd.DataFrame) -> List[Dict]:
        """Detect malicious IP addresses"""
        
        malicious_ips = []
        
        # Group by IP
        ip_stats = logs.groupby('ip').agg({
            'endpoint': ['nunique', lambda x: list(x)],
            'timestamp': ['count', lambda x: self._calculate_request_rate(x)],
            'status': lambda x: (x == 404).sum(),
            'body_bytes_sent': 'sum'
        }).round(2)
        
        ip_stats.columns = ['unique_endpoints', 'accessed_endpoints', 
                           'total_requests', 'request_rate', 'not_found_count', 
                           'total_data']
        
        # Identify suspicious IPs
        high_rate = ip_stats[ip_stats['request_rate'] > ip_stats['request_rate'].quantile(0.99)]
        many_404s = ip_stats[ip_stats['not_found_count'] > 100]  # More than 100 404s
        many_endpoints = ip_stats[ip_stats['unique_endpoints'] > 50]  > 50 unique endpoints
        
        suspicious_ips = pd.concat([high_rate, many_404s, many_endpoints]).drop_duplicates()
        
        for ip, row in suspicious_ips.iterrows():
            malicious_ips.append({
                'ip': ip,
                'total_requests': int(row['total_requests']),
                'request_rate_per_sec': row['request_rate'],
                'unique_endpoints': int(row['unique_endpoints']),
                'not_found_requests': int(row['not_found_count']),
                'total_data_mb': row['total_data'] / (1024 * 1024),
                'accessed_endpoints_sample': row['accessed_endpoints'][:10]  # First 10
            })
        
        return malicious_ips
    
    def _detect_sql_injection(self, logs: pd.DataFrame) -> List[Dict]:
        """Detect SQL injection attempts"""
        
        sqli_attempts = []
        
        # Check request URLs and parameters
        if 'request' in logs.columns:
            for idx, row in logs.iterrows():
                request = row['request']
                ip = row['ip']
                endpoint = row['endpoint']
                
                # Check for SQL patterns
                for pattern in self.compiled_sql_patterns:
                    if pattern.search(request):
                        sqli_attempts.append({
                            'timestamp': row['timestamp'].isoformat(),
                            'ip': ip,
                            'endpoint': endpoint,
                            'request': request[:200],  # Truncate for display
                            'pattern_found': pattern.pattern,
                            'status_code': row.get('status', 'N/A'),
                            'user_agent': row.get('user_agent', 'N/A')[:100]
                        })
                        break
        
        return sqli_attempts
    
    def _detect_scanners(self, logs: pd.DataFrame) -> List[Dict]:
        """Detect security scanner activity"""
        
        scanner_activity = []
        
        if 'user_agent' in logs.columns:
            for idx, row in logs.iterrows():
                ua = row['user_agent']
                if not isinstance(ua, str):
                    continue
                
                for pattern in self.compiled_scanner_patterns:
                    if pattern.search(ua.lower()):
                        scanner_activity.append({
                            'timestamp': row['timestamp'].isoformat(),
                            'ip': row['ip'],
                            'user_agent': ua[:150],
                            'scanner_type': pattern.pattern,
                            'endpoint': row.get('endpoint', 'N/A'),
                            'status_code': row.get('status', 'N/A')
                        })
                        break
        
        return scanner_activity
    
    def _detect_brute_force(self, logs: pd.DataFrame) -> List[Dict]:
        """Detect brute force attack patterns"""
        
        brute_force = []
        
        # Look for rapid successive requests to login endpoints
        login_logs = logs[logs['endpoint'].str.contains('login|auth|signin', case=False, na=False)]
        
        if not login_logs.empty:
            # Group by IP in 5-minute windows
            login_logs['time_window'] = login_logs['timestamp'].dt.floor('5T')
            
            window_counts = login_logs.groupby(['ip', 'time_window']).size()
            suspicious_windows = window_counts[window_counts > 20]  # >20 login attempts in 5 min
            
            for (ip, window), count in suspicious_windows.items():
                window_logs = login_logs[(login_logs['ip'] == ip) & 
                                        (login_logs['time_window'] == window)]
                
                brute_force.append({
                    'ip': ip,
                    'time_window': window.isoformat(),
                    'attempt_count': int(count),
                    'endpoints': window_logs['endpoint'].unique().tolist(),
                    'status_codes': dict(Counter(window_logs['status'])),
                    'user_agents': window_logs['user_agent'].unique()[:3].tolist()
                })
        
        return brute_force
    
    def _calculate_request_rate(self, timestamps: pd.Series) -> float:
        """Calculate request rate in requests per second"""
        if len(timestamps) < 2:
            return 0
        
        timestamps = pd.to_datetime(timestamps)
        time_diff = (timestamps.max() - timestamps.min()).total_seconds()
        
        if time_diff == 0:
            return len(timestamps)
        
        return len(timestamps) / time_diff
    
    def _correlate_findings(self, findings: Dict):
        """Correlate different types of findings"""
        
        # Build IP threat profile
        ip_threats = defaultdict(lambda: {
            'endpoint_abuse': 0,
            'data_dump': 0,
            'sqli_attempts': 0,
            'scanner_activity': 0,
            'brute_force': 0,
            'total_score': 0
        })
        
        # Count threats per IP
        for finding_type in ['malicious_ips', 'data_dumps', 'sqli_attempts', 
                           'scanner_activity', 'brute_force']:
            if finding_type in findings and isinstance(findings[finding_type], list):
                for item in findings[finding_type]:
                    if 'ip' in item:
                        ip = item['ip']
                        ip_threats[ip][finding_type] += 1
        
        # Calculate total score
        for ip in ip_threats:
            threats = ip_threats[ip]
            total_score = (
                threats['endpoint_abuse'] * 1 +
                threats['data_dump'] * 3 +
                threats['sqli_attempts'] * 5 +
                threats['scanner_activity'] * 4 +
                threats['brute_force'] * 2
            )
            ip_threats[ip]['total_score'] = total_score
        
        findings['ip_threat_profiles'] = dict(ip_threats)
    
    def _calculate_risk_scores(self, findings: Dict):
        """Calculate risk scores for findings"""
        
        # Score endpoints
        for endpoint in findings.get('suspicious_endpoints', []):
            score = 0
            
            # High request volume
            if endpoint['total_requests'] > 1000:
                score += 30
            elif endpoint['total_requests'] > 100:
                score += 15
            
            # High data transfer
            if endpoint['total_data_mb'] > 100:
                score += 40
            elif endpoint['total_data_mb'] > 10:
                score += 20
            
            # Many unique IPs
            if endpoint['unique_ips'] > 50:
                score += 20
            elif endpoint['unique_ips'] > 10:
                score += 10
            
            # High request rate
            if endpoint['requests_per_minute'] > 100:
                score += 30
            elif endpoint['requests_per_minute'] > 10:
                score += 15
            
            # Normalize score to 0-100
            endpoint['risk_score'] = min(score, 100)
            endpoint['risk_level'] = self._score_to_level(endpoint['risk_score'])
        
        # Score IPs
        for ip in findings.get('malicious_ips', []):
            score = 0
            
            if ip['request_rate_per_sec'] > 10:
                score += 40
            elif ip['request_rate_per_sec'] > 1:
                score += 20
            
            if ip['not_found_requests'] > 100:
                score += 30
            
            if ip['unique_endpoints'] > 50:
                score += 30
            
            ip['risk_score'] = min(score, 100)
            ip['risk_level'] = self._score_to_level(ip['risk_score'])
    
    def _score_to_level(self, score: float) -> str:
        """Convert numerical score to risk level"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'INFO'
