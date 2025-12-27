"""
WAF Log Processor
Specialized processing for Web Application Firewall logs
"""

import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from pathlib import Path

class WAFProcessor:
    """Process WAF (ModSecurity) logs"""
    
    # ModSecurity audit log patterns
    AUDIT_LOG_PATTERN = r'^--[a-f0-9]{8}-A--\n(.*?)\n--[a-f0-9]{8}-B--\n(.*?)\n--[a-f0-9]{8}-C--\n(.*?)\n--[a-f0-9]{8}-F--\n(.*?)\n--[a-f0-9]{8}-E--\n(.*?)\n--[a-f0-9]{8}-H--\n(.*?)\n--[a-f0-9]{8}-I--\n(.*?)\n--[a-f0-9]{8}-J--\n(.*?)\n--[a-f0-9]{8}-Z--'
    
    # Common WAF rule categories
    RULE_CATEGORIES = {
        'SQLI': ['SQL Injection', 'sqli', 'sql-injection'],
        'XSS': ['XSS', 'Cross Site Scripting', 'cross-site'],
        'RCE': ['RCE', 'Remote Code Execution', 'code execution'],
        'LFI': ['LFI', 'Local File Inclusion', 'path traversal'],
        'RFI': ['RFI', 'Remote File Inclusion'],
        'PROTOCOL': ['Protocol Violation', 'HTTP protocol'],
        'REQUEST': ['Invalid HTTP Request', 'Malformed Request'],
        'SCANNER': ['Scanner', 'Reconnaissance', 'Information Leakage'],
        'SESSION': ['Session Fixation', 'Cookie Manipulation'],
        'ACCESS': ['Access Control', 'Forceful Browsing']
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.audit_pattern = re.compile(self.AUDIT_LOG_PATTERN, re.MULTILINE | re.DOTALL)
        
    def process_audit_logs(self, log_path: str) -> pd.DataFrame:
        """Process ModSecurity audit logs"""
        
        audit_entries = []
        
        for log_file in self._find_log_files(log_path, ['modsec_audit.log', 'audit.log', '*audit*.log']):
            content = self._read_log_file(log_file)
            
            # Parse audit log entries
            matches = self.audit_pattern.findall(content)
            
            for match in matches:
                parsed = self._parse_audit_entry(match, str(log_file))
                if parsed:
                    audit_entries.append(parsed)
        
        if audit_entries:
            df = pd.DataFrame(audit_entries)
            return self._enhance_audit_data(df)
        
        return pd.DataFrame()
    
    def _parse_audit_entry(self, match: Tuple, filename: str) -> Optional[Dict]:
        """Parse a ModSecurity audit log entry"""
        
        try:
            # Extract sections
            sections = {
                'A': match[0],  # Request headers
                'B': match[1],  # Request body
                'C': match[2],  # Request body (continued)
                'F': match[3],  # Files uploaded
                'E': match[4],  # Response body
                'H': match[5],  # Audit log trailer
                'I': match[6],  # Request body (alternative)
                'J': match[7]   # Response body (alternative)
            }
            
            # Parse request headers
            request_info = self._parse_request_headers(sections['A'])
            
            # Parse audit trailer for rule information
            rule_info = self._parse_audit_trailer(sections['H'])
            
            # Combine information
            audit_entry = {
                'timestamp': request_info.get('timestamp', datetime.now()),
                'client_ip': request_info.get('client_ip'),
                'server_ip': request_info.get('server_ip'),
                'method': request_info.get('method'),
                'uri': request_info.get('uri'),
                'protocol': request_info.get('protocol'),
                'host': request_info.get('host'),
                'user_agent': request_info.get('user_agent'),
                'response_code': rule_info.get('response_code', 0),
                'blocked': rule_info.get('blocked', False),
                'rules_triggered': rule_info.get('rules_triggered', []),
                'rule_categories': rule_info.get('rule_categories', []),
                'severity': rule_info.get('severity', 'MEDIUM'),
                'message': rule_info.get('message', ''),
                'source_file': filename,
                'raw_headers': sections['A'][:1000]  # Truncate
            }
            
            return audit_entry
            
        except Exception as e:
            print(f"Error parsing audit entry: {e}")
            return None
    
    def detect_attack_patterns(self, df: pd.DataFrame) -> Dict[str, List]:
        """Detect attack patterns from WAF logs"""
        
        if df.empty:
            return {}
        
        findings = {
            'blocked_attacks': [],
            'frequent_attackers': [],
            'attack_trends': [],
            'rule_effectiveness': [],
            'evasion_attempts': []
        }
        
        # Analyze blocked attacks
        blocked = df[df['blocked'] == True].copy()
        if not blocked.empty:
            for _, row in blocked.iterrows():
                findings['blocked_attacks'].append({
                    'timestamp': row['timestamp'].isoformat(),
                    'client_ip': row['client_ip'],
                    'method': row['method'],
                    'uri': row['uri'],
                    'rules_triggered': row.get('rules_triggered', []),
                    'rule_categories': row.get('rule_categories', []),
                    'severity': row.get('severity', 'MEDIUM'),
                    'message': row.get('message', '')[:200],
                    'user_agent': row.get('user_agent', '')[:100]
                })
        
        # Find frequent attackers
        attacker_stats = df.groupby('client_ip').agg({
            'timestamp': ['count', 'min', 'max'],
            'blocked': 'sum',
            'severity': lambda x: list(x)
        }).round(2)
        
        attacker_stats.columns = ['total_requests', 'first_seen', 'last_seen', 'blocks', 'severities']
        
        # Identify persistent attackers
        for ip, stats in attacker_stats.iterrows():
            if stats['total_requests'] >= 10:  # At least 10 requests
                time_span = (stats['last_seen'] - stats['first_seen']).total_seconds() / 3600
                
                # Calculate attack rate
                attack_rate = stats['total_requests'] / max(time_span, 1)
                
                findings['frequent_attackers'].append({
                    'ip': ip,
                    'total_requests': int(stats['total_requests']),
                    'blocks': int(stats['blocks']),
                    'block_rate': stats['blocks'] / stats['total_requests'] if stats['total_requests'] > 0 else 0,
                    'time_span_hours': time_span,
                    'attack_rate_per_hour': attack_rate,
                    'first_seen': stats['first_seen'].isoformat(),
                    'last_seen': stats['last_seen'].isoformat(),
                    'max_severity': max(stats['severities'], key=lambda x: self._severity_to_score(x)) 
                    if stats['severities'] else 'MEDIUM'
                })
        
        # Analyze attack trends
        if not df.empty:
            df['hour'] = df['timestamp'].dt.hour
            hourly_attacks = df.groupby('hour').size()
            
            peak_hours = hourly_attacks[hourly_attacks > hourly_attacks.mean() * 1.5]
            for hour, count in peak_hours.items():
                hour_attacks = df[df['hour'] == hour]
                
                findings['attack_trends'].append({
                    'hour': hour,
                    'attack_count': int(count),
                    'block_count': hour_attacks['blocked'].sum(),
                    'block_rate': hour_attacks['blocked'].sum() / count if count > 0 else 0,
                    'common_categories': self._get_common_categories(hour_attacks),
                    'top_attackers': hour_attacks['client_ip'].value_counts().head(3).to_dict()
                })
        
        # Analyze rule effectiveness
        all_rules = []
        for rules in df['rules_triggered']:
            if rules:
                all_rules.extend(rules)
        
        if all_rules:
            rule_counts = pd.Series(all_rules).value_counts()
            
            for rule_id, count in rule_counts.head(10).items():
                rule_entries = df[df['rules_triggered'].apply(lambda x: rule_id in x if x else False)]
                
                findings['rule_effectiveness'].append({
                    'rule_id': rule_id,
                    'trigger_count': int(count),
                    'block_count': rule_entries['blocked'].sum(),
                    'block_rate': rule_entries['blocked'].sum() / count if count > 0 else 0,
                    'common_categories': self._get_common_categories(rule_entries),
                    'top_targets': rule_entries['uri'].value_counts().head(3).to_dict(),
                    'sample_messages': rule_entries['message'].dropna().head(3).tolist()
                })
        
        # Detect evasion attempts
        evasion_patterns = self._detect_evasion_attempts(df)
        findings['evasion_attempts'] = evasion_patterns
        
        return findings
    
    def correlate_with_nginx(self, waf_df: pd.DataFrame, nginx_df: pd.DataFrame) -> List[Dict]:
        """Correlate WAF events with Nginx logs"""
        
        correlations = []
        
        if waf_df.empty or nginx_df.empty:
            return correlations
        
        # For each WAF event, find matching Nginx request
        for _, waf_row in waf_df.iterrows():
            waf_time = waf_row['timestamp']
            waf_ip = waf_row['client_ip']
            waf_uri = waf_row['uri']
            
            # Find matching Nginx requests
            time_window = pd.Timedelta(seconds=2)
            
            matching_requests = nginx_df[
                (nginx_df['timestamp'] >= waf_time - time_window) &
                (nginx_df['timestamp'] <= waf_time + time_window) &
                (nginx_df['ip'] == waf_ip) &
                (nginx_df['endpoint'] == waf_uri)
            ]
            
            if not matching_requests.empty():
                for _, nginx_row in matching_requests.iterrows():
                    correlation_score = self._calculate_waf_correlation(waf_row, nginx_row)
                    
                    correlations.append({
                        'waf_timestamp': waf_time.isoformat(),
                        'nginx_timestamp': nginx_row['timestamp'].isoformat(),
                        'time_difference_ms': abs((waf_time - nginx_row['timestamp']).total_seconds() * 1000),
                        'client_ip': waf_ip,
                        'uri': waf_uri,
                        'waf_blocked': waf_row.get('blocked', False),
                        'waf_severity': waf_row.get('severity', 'MEDIUM'),
                        'waf_rules': waf_row.get('rules_triggered', []),
                        'nginx_status': nginx_row.get('status', 0),
                        'nginx_response_size': nginx_row.get('body_bytes_sent', 0),
                        'correlation_score': correlation_score,
                        'user_agent_match': waf_row.get('user_agent', '') == nginx_row.get('user_agent', '')
                    })
        
        return correlations
    
    # Helper methods
    def _find_log_files(self, base_path: str, patterns: List[str]) -> List[Path]:
        """Find WAF log files"""
        
        base = Path(base_path)
        log_files = []
        
        for pattern in patterns:
            for log_file in base.rglob(pattern):
                if log_file.is_file():
                    log_files.append(log_file)
        
        return sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True)
    
    def _read_log_file(self, file_path: Path) -> str:
        """Read log file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading WAF log {file_path}: {e}")
            return ""
    
    def _parse_request_headers(self, headers_section: str) -> Dict[str, Any]:
        """Parse request headers from section A"""
        
        info = {}
        
        # Extract timestamp
        timestamp_match = re.search(r'\[(\d+/\w+/\d+:\d+:\d+:\d+ [+-]\d+)\]', headers_section)
        if timestamp_match:
            try:
                timestamp_str = timestamp_match.group(1)
                # Parse Apache timestamp format
                info['timestamp'] = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                info['timestamp'] = datetime.now()
        
        # Extract client IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', headers_section.split('\n')[0])
        if ip_match:
            info['client_ip'] = ip_match.group(1)
        
        # Extract request line
        request_match = re.search(r'([A-Z]+) (.*?) (HTTP/\d\.\d)', headers_section)
        if request_match:
            info['method'] = request_match.group(1)
            info['uri'] = request_match.group(2)
            info['protocol'] = request_match.group(3)
        
        # Extract Host header
        host_match = re.search(r'Host: (.*?)\n', headers_section, re.I)
        if host_match:
            info['host'] = host_match.group(1).strip()
        
        # Extract User-Agent
        ua_match = re.search(r'User-Agent: (.*?)\n', headers_section, re.I)
        if ua_match:
            info['user_agent'] = ua_match.group(1).strip()
        
        # Extract server IP (from Apache format)
        server_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', headers_section.split('\n')[1])
        if server_match:
            info['server_ip'] = server_match.group(1)
        
        return info
    
    def _parse_audit_trailer(self, trailer_section: str) -> Dict[str, Any]:
        """Parse audit trailer from section H"""
        
        info = {
            'blocked': False,
            'rules_triggered': [],
            'rule_categories': [],
            'severity': 'MEDIUM',
            'message': '',
            'response_code': 0
        }
        
        # Check if request was blocked
        if 'Intercepted' in trailer_section:
            info['blocked'] = True
        
        # Extract response code
        response_match = re.search(r'Response Body Status Code: (\d+)', trailer_section)
        if response_match:
            info['response_code'] = int(response_match.group(1))
        
        # Extract rule messages
        rule_matches = re.findall(r'Message: (.*?)\n', trailer_section)
        if rule_matches:
            info['rules_triggered'] = [msg.strip() for msg in rule_matches]
            
            # Extract rule IDs if present
            rule_ids = re.findall(r'\[id "(\d+)"\]', trailer_section)
            if rule_ids:
                info['rule_ids'] = rule_ids
            
            # Determine categories
            for msg in rule_matches:
                category = self._categorize_rule_message(msg)
                if category and category not in info['rule_categories']:
                    info['rule_categories'].append(category)
            
            # Determine overall severity
            severities = []
            for msg in rule_matches:
                severity = self._extract_severity(msg)
                if severity:
                    severities.append(severity)
            
            if severities:
                info['severity'] = max(severities, key=lambda x: self._severity_to_score(x))
        
        return info
    
    def _categorize_rule_message(self, message: str) -> Optional[str]:
        """Categorize rule message"""
        
        message_lower = message.lower()
        
        for category, keywords in self.RULE_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in message_lower:
                    return category
        
        return None
    
    def _extract_severity(self, message: str) -> Optional[str]:
        """Extract severity from rule message"""
        
        severity_patterns = {
            'CRITICAL': re.compile(r'critical', re.I),
            'HIGH': re.compile(r'high', re.I),
            'MEDIUM': re.compile(r'medium', re.I),
            'LOW': re.compile(r'low', re.I)
        }
        
        for severity, pattern in severity_patterns.items():
            if pattern.search(message):
                return severity
        
        return None
    
    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numerical score"""
        
        scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        return scores.get(severity.upper(), 0)
    
    def _enhance_audit_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enhance audit data with additional features"""
        
        if df.empty:
            return df
        
        # Add time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Add URI features
        df['uri_length'] = df['uri'].apply(len)
        df['has_parameters'] = df['uri'].str.contains(r'\?', na=False)
        df['parameter_count'] = df['uri'].apply(
            lambda x: len(x.split('?')[1].split('&')) if '?' in x else 0
        )
        
        # Add category features
        df['primary_category'] = df['rule_categories'].apply(
            lambda x: x[0] if x else 'UNKNOWN'
        )
        df['category_count'] = df['rule_categories'].apply(len)
        
        # Add severity score
        df['severity_score'] = df['severity'].apply(self._severity_to_score)
        
        return df
    
    def _get_common_categories(self, df: pd.DataFrame) -> Dict[str, int]:
        """Get common rule categories from DataFrame"""
        
        all_categories = []
        for categories in df['rule_categories']:
            if categories:
                all_categories.extend(categories)
        
        if all_categories:
            return pd.Series(all_categories).value_counts().to_dict()
        
        return {}
    
    def _detect_evasion_attempts(self, df: pd.DataFrame) -> List[Dict]:
        """Detect WAF evasion attempts"""
        
        if df.empty:
            return []
        
        evasion_findings = []
        
        # Look for encoding/obfuscation patterns
        encoding_patterns = [
            (r'%[0-9a-fA-F]{2}', 'URL Encoding'),
            (r'\\x[0-9a-fA-F]{2}', 'Hex Encoding'),
            (r'&#x[0-9a-fA-F]+;', 'HTML Entity'),
            (r'u[0-9a-fA-F]{4}', 'Unicode Encoding'),
            (r'/\*.*\*/', 'SQL Comment'),
            (r'\s+', 'Whitespace Obfuscation'),
            (r'\+', 'Plus Encoding')
        ]
        
        for _, row in df.iterrows():
            uri = row.get('uri', '')
            evasion_techniques = []
            
            for pattern, technique in encoding_patterns:
                if re.search(pattern, uri):
                    evasion_techniques.append(technique)
            
            if evasion_techniques:
                evasion_findings.append({
                    'timestamp': row['timestamp'].isoformat(),
                    'client_ip': row['client_ip'],
                    'uri': uri[:200],
                    'evasion_techniques': list(set(evasion_techniques)),
                    'rules_triggered': row.get('rules_triggered', []),
                    'blocked': row.get('blocked', False)
                })
        
        return evasion_findings
    
    def _calculate_waf_correlation(self, waf_row: pd.Series, nginx_row: pd.Series) -> float:
        """Calculate correlation score between WAF and Nginx events"""
        
        score = 0.0
        
        # Time proximity
        time_diff = abs((waf_row['timestamp'] - nginx_row['timestamp']).total_seconds())
        if time_diff < 0.1:  # 100ms
            score += 0.4
        elif time_diff < 0.5:  # 500ms
            score += 0.3
        elif time_diff < 1.0:  # 1 second
            score += 0.2
        
        # IP match
        if waf_row['client_ip'] == nginx_row['ip']:
            score += 0.3
        
        # URI match
        if waf_row['uri'] == nginx_row['endpoint']:
            score += 0.3
        
        # Check if WAF blocked and Nginx returned error
        if waf_row.get('blocked', False) and nginx_row.get('status', 0) in [403, 404, 500]:
            score += 0.2
        
        return min(score, 1.0)
