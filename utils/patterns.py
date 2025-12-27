"""
Pattern Definitions
Regular expressions and patterns for detection
"""

import re
from typing import Dict, List, Pattern

class DetectionPatterns:
    """Collection of detection patterns for security analysis"""
    
    # SQL Injection patterns
    SQL_INJECTION = {
        'union_select': re.compile(r'union.*select', re.I),
        'select_from': re.compile(r'select.*from', re.I),
        'insert_into': re.compile(r'insert.*into', re.I),
        'update_set': re.compile(r'update.*set', re.I),
        'delete_from': re.compile(r'delete.*from', re.I),
        'drop_table': re.compile(r'drop.*table', re.I),
        'create_table': re.compile(r'create.*table', re.I),
        'alter_table': re.compile(r'alter.*table', re.I),
        'truncate_table': re.compile(r'truncate.*table', re.I),
        'sql_comment': re.compile(r'--|\/\*.*\*\/', re.I),
        'sql_sleep': re.compile(r'sleep\(', re.I),
        'sql_benchmark': re.compile(r'benchmark\(', re.I),
        'waitfor_delay': re.compile(r'waitfor.*delay', re.I),
        'xp_cmdshell': re.compile(r'xp_cmdshell', re.I),
        'information_schema': re.compile(r'information_schema', re.I),
        'version_comment': re.compile(r'@@version|version\(\)', re.I),
        'load_file': re.compile(r'load_file\(', re.I),
        'into_outfile': re.compile(r'into.*outfile', re.I),
        'into_dumpfile': re.compile(r'into.*dumpfile', re.I),
        'tautology': re.compile(r'1\s*=\s*1|"a"\s*=\s*"a"|\'a\'\s*=\s*\'a\'', re.I)
    }
    
    # XSS patterns
    XSS = {
        'script_tag': re.compile(r'<script.*?>.*?</script>', re.I),
        'javascript_protocol': re.compile(r'javascript:', re.I),
        'onload_event': re.compile(r'onload\s*=', re.I),
        'onerror_event': re.compile(r'onerror\s*=', re.I),
        'onclick_event': re.compile(r'onclick\s*=', re.I),
        'alert_function': re.compile(r'alert\(', re.I),
        'prompt_function': re.compile(r'prompt\(', re.I),
        'confirm_function': re.compile(r'confirm\(', re.I),
        'iframe_tag': re.compile(r'<iframe.*?>', re.I),
        'img_tag_with_js': re.compile(r'<img.*?onerror=.*?>', re.I),
        'svg_tag': re.compile(r'<svg.*?>.*?</svg>', re.I),
        'body_onload': re.compile(r'<body.*?onload=.*?>', re.I)
    }
    
    # Path Traversal patterns
    PATH_TRAVERSAL = {
        'dot_dot_slash': re.compile(r'\.\./|\.\.\\'),
        'absolute_path': re.compile(r'/(etc|bin|sbin|usr|var|home|root)/'),
        'windows_path': re.compile(r'[a-zA-Z]:\\'),
        'null_byte': re.compile(r'%00|\x00'),
        'directory_listing': re.compile(r'index\.of|directory\s+listing', re.I)
    }
    
    # Command Injection patterns
    COMMAND_INJECTION = {
        'system_call': re.compile(r'system\(|exec\(|shell_exec\(|passthru\(', re.I),
        'backtick': re.compile(r'`.*?`'),
        'pipe_operator': re.compile(r'\|\s*[a-z]'),
        'semicolon': re.compile(r';\s*[a-z]'),
        'ampersand': re.compile(r'&\s*[a-z]'),
        'subprocess': re.compile(r'subprocess\.', re.I)
    }
    
    # File Inclusion patterns
    FILE_INCLUSION = {
        'include': re.compile(r'(include|require)(_once)?\s*\(', re.I),
        'file_get_contents': re.compile(r'file_get_contents\s*\(', re.I),
        'readfile': re.compile(r'readfile\s*\(', re.I),
        'fopen': re.compile(r'fopen\s*\(', re.I),
        'file_put_contents': re.compile(r'file_put_contents\s*\(', re.I)
    }
    
    # Security Scanner patterns
    SCANNERS = {
        'sqlmap': re.compile(r'sqlmap', re.I),
        'nikto': re.compile(r'nikto', re.I),
        'nmap': re.compile(r'nmap', re.I),
        'wpscan': re.compile(r'wpscan', re.I),
        'gobuster': re.compile(r'gobuster', re.I),
        'dirb': re.compile(r'dirb', re.I),
        'dirbuster': re.compile(r'dirbuster', re.I),
        'acunetix': re.compile(r'acunetix', re.I),
        'nessus': re.compile(r'nessus', re.I),
        'openvas': re.compile(r'openvas', re.I),
        'burpsuite': re.compile(r'burp', re.I),
        'metasploit': re.compile(r'metasploit', re.I),
        'zap': re.compile(r'zap|owasp', re.I)
    }
    
    # Suspicious User Agent patterns
    SUSPICIOUS_USER_AGENTS = {
        'sqlmap_ua': re.compile(r'sqlmap/\d', re.I),
        'nikto_ua': re.compile(r'Nikto/\d', re.I),
        'nmap_ua': re.compile(r'Nmap Scripting Engine', re.I),
        'python_requests': re.compile(r'python-requests/\d', re.I),
        'curl': re.compile(r'curl/\d', re.I),
        'wget': re.compile(r'Wget/\d', re.I),
        'go_http': re.compile(r'Go-http-client/\d', re.I),
        'java_http': re.compile(r'Java/\d', re.I),
        'scrapy': re.compile(r'Scrapy/\d', re.I),
        'phantomjs': re.compile(r'PhantomJS', re.I),
        'headless_chrome': re.compile(r'HeadlessChrome', re.I)
    }
    
    # Brute Force patterns
    BRUTE_FORCE = {
        'login_attempts': re.compile(r'(login|signin|auth|authenticate)', re.I),
        'failed_login': re.compile(r'(failed|invalid|incorrect).*(password|login|credential)', re.I),
        'account_locked': re.compile(r'account.*locked', re.I),
        'too_many_attempts': re.compile(r'too.*many.*attempts', re.I),
        'rate_limit': re.compile(r'rate.*limit', re.I)
    }
    
    # Data Dump patterns
    DATA_DUMP = {
        'large_response': re.compile(r'Content-Length:\s*\d{7,}', re.I),  # > 1MB
        'json_array': re.compile(r'\[\s*\{.*?\}\s*\]', re.S),
        'csv_data': re.compile(r'("[^"]*",?){10,}', re.I),  # At least 10 CSV columns
        'base64_data': re.compile(r'[A-Za-z0-9+/]{100,}={0,2}'),
        'serialized_data': re.compile(r'(a|s|i|o|d):\d+:'),
        'xml_data': re.compile(r'<\?xml.*?\?>', re.S)
    }
    
    # API Abuse patterns
    API_ABUSE = {
        'high_rate': re.compile(r'Rate-Limit.*exceeded', re.I),
        'api_key_abuse': re.compile(r'(apikey|api_key|token).*(invalid|expired)', re.I),
        'endpoint_flood': re.compile(r'/(api|v\d)/.*', re.I)
    }
    
    # Sensitive Data patterns
    SENSITIVE_DATA = {
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'credit_card': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
        'ssn': re.compile(r'\b\d{3}[ -]?\d{2}[ -]?\d{4}\b'),
        'phone': re.compile(r'\b(?:\+?1[-.]?)?\(?[2-9][0-8][0-9]\)?[-.]?[2-9][0-9]{2}[-.]?[0-9]{4}\b'),
        'jwt_token': re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
        'api_key': re.compile(r'(?i)(api[_-]?key|access[_-]?token|secret[_-]?key)[=:]\s*[\w\-\.]+'),
        'password': re.compile(r'(?i)(passwd|password|pwd)[=:]\s*\S+'),
        'private_key': re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----')
    }
    
    # Malicious File patterns
    MALICIOUS_FILES = {
        'webshell': re.compile(r'(cmd|shell|backdoor|phpspy|wso|c99|r57)', re.I),
        'malware': re.compile(r'(malware|virus|trojan|worm|ransomware)', re.I),
        'exploit': re.compile(r'(exploit|payload|reverse_shell)', re.I)
    }
    
    # Anomaly patterns
    ANOMALY = {
        'unusual_time': re.compile(r'(02:00|03:00|04:00):\d{2}'),  # 2-4 AM
        'weekend_activity': re.compile(r'(Sat|Sun)'),
        'holiday_activity': re.compile(r'(Jan 01|Dec 25|Jul 04)')  # Example holidays
    }
    
    # Endpoint sensitivity levels
    SENSITIVE_ENDPOINTS = {
        'CRITICAL': [
            r'/admin',
            r'/phpmyadmin',
            r'/wp-admin',
            r'/database',
            r'/config',
            r'/\.env',
            r'/\.git',
            r'/\.svn',
            r'/backup',
            r'/dump',
            r'/export',
            r'/import'
        ],
        'HIGH': [
            r'/api/auth',
            r'/api/token',
            r'/api/users',
            r'/api/customers',
            r'/api/orders',
            r'/api/payments',
            r'/login',
            r'/register',
            r'/password',
            r'/reset',
            r'/oauth',
            r'/session'
        ],
        'MEDIUM': [
            r'/api/',
            r'/upload',
            r'/download',
            r'/files',
            r'/images',
            r'/documents',
            r'/search',
            r'/query'
        ],
        'LOW': [
            r'/public',
            r'/static',
            r'/assets',
            r'/css',
            r'/js',
            r'/images',
            r'/fonts'
        ]
    }
    
    @classmethod
    def get_patterns_by_category(cls, category: str) -> Dict[str, Pattern]:
        """Get patterns by category name"""
        
        category_map = {
            'sql_injection': cls.SQL_INJECTION,
            'xss': cls.XSS,
            'path_traversal': cls.PATH_TRAVERSAL,
            'command_injection': cls.COMMAND_INJECTION,
            'file_inclusion': cls.FILE_INCLUSION,
            'scanners': cls.SCANNERS,
            'suspicious_user_agents': cls.SUSPICIOUS_USER_AGENTS,
            'brute_force': cls.BRUTE_FORCE,
            'data_dump': cls.DATA_DUMP,
            'api_abuse': cls.API_ABUSE,
            'sensitive_data': cls.SENSITIVE_DATA,
            'malicious_files': cls.MALICIOUS_FILES,
            'anomaly': cls.ANOMALY
        }
        
        return category_map.get(category.lower(), {})
    
    @classmethod
    def check_pattern(cls, text: str, pattern_category: str, pattern_name: str = None) -> bool:
        """Check if text matches a specific pattern"""
        
        patterns = cls.get_patterns_by_category(pattern_category)
        
        if pattern_name:
            pattern = patterns.get(pattern_name)
            return bool(pattern.search(text)) if pattern else False
        
        # Check all patterns in category
        for pattern in patterns.values():
            if pattern.search(text):
                return True
        
        return False
    
    @classmethod
    def find_matches(cls, text: str, pattern_category: str) -> List[Dict[str, str]]:
        """Find all pattern matches in text"""
        
        matches = []
        patterns = cls.get_patterns_by_category(pattern_category)
        
        for name, pattern in patterns.items():
            match = pattern.search(text)
            if match:
                matches.append({
                    'pattern_name': name,
                    'matched_text': match.group(),
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
        
        return matches
    
    @classmethod
    def get_endpoint_sensitivity(cls, endpoint: str) -> str:
        """Get sensitivity level for an endpoint"""
        
        for level, patterns in cls.SENSITIVE_ENDPOINTS.items():
            for pattern in patterns:
                if re.search(pattern, endpoint, re.I):
                    return level
        
        return 'INFO'
    
    @classmethod
    def is_sensitive_endpoint(cls, endpoint: str) -> bool:
        """Check if endpoint is sensitive"""
        
        return cls.get_endpoint_sensitivity(endpoint) in ['CRITICAL', 'HIGH']
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, Dict[str, Pattern]]:
        """Get all patterns organized by category"""
        
        return {
            'sql_injection': cls.SQL_INJECTION,
            'xss': cls.XSS,
            'path_traversal': cls.PATH_TRAVERSAL,
            'command_injection': cls.COMMAND_INJECTION,
            'file_inclusion': cls.FILE_INCLUSION,
            'scanners': cls.SCANNERS,
            'suspicious_user_agents': cls.SUSPICIOUS_USER_AGENTS,
            'brute_force': cls.BRUTE_FORCE,
            'data_dump': cls.DATA_DUMP,
            'api_abuse': cls.API_ABUSE,
            'sensitive_data': cls.SENSITIVE_DATA,
            'malicious_files': cls.MALICIOUS_FILES,
            'anomaly': cls.ANOMALY
        }
