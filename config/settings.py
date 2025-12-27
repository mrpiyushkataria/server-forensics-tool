import yaml
from pathlib import Path
from typing import Dict, Any

class Config:
    """Configuration management"""
    
    DEFAULT_CONFIG = {
        'analysis': {
            'time_window_hours': 24,
            'min_request_threshold': 100,
            'large_response_bytes': 1048576,  # 1MB
            'suspicious_request_rate': 10,  # requests per second
            'data_dump_threshold_mb': 10
        },
        'detection': {
            'sql_injection_enabled': True,
            'scanner_detection_enabled': True,
            'brute_force_detection_enabled': True,
            'data_dump_detection_enabled': True,
            'endpoint_abuse_detection_enabled': True
        },
        'scoring': {
            'critical_threshold': 80,
            'high_threshold': 60,
            'medium_threshold': 40,
            'low_threshold': 20
        },
        'output': {
            'generate_json': True,
            'generate_csv': True,
            'generate_pdf': True,
            'generate_html': True,
            'output_directory': './reports',
            'redact_sensitive_data': True
        },
        'patterns': {
            'sql_keywords': [
                'union', 'select', 'insert', 'update', 'delete',
                'drop', 'create', 'alter', 'sleep', 'benchmark',
                'waitfor', 'shutdown', 'xp_cmdshell'
            ],
            'scanner_indicators': [
                'sqlmap', 'nikto', 'nmap', 'wpscan', 'gobuster',
                'dirb', 'dirbuster', 'acunetix', 'nessus', 'openvas'
            ],
            'sensitive_endpoints': [
                '/admin', '/api/auth', '/login', '/oauth',
                '/api/users', '/api/customers', '/api/orders',
                '/database', '/phpmyadmin', '/wp-admin'
            ]
        }
    }
    
    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else None
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_path and Path(config_path).exists():
            self.load_config(config_path)
    
    def load_config(self, config_path: str):
        """Load configuration from YAML file"""
        with open(config_path, 'r', encoding='utf-8') as f:
            user_config = yaml.safe_load(f)
            self._deep_update(self.config, user_config)
    
    def _deep_update(self, original: Dict, update: Dict):
        """Deep update dictionary"""
        for key, value in update.items():
            if isinstance(value, dict) and key in original:
                self._deep_update(original[key], value)
            else:
                original[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def save(self, config_path: str = None):
        """Save configuration to file"""
        path = Path(config_path) if config_path else self.config_path
        if not path:
            raise ValueError("No config path specified")
        
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False)
