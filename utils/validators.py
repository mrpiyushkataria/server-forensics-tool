"""
Data Validators
Validation functions for data integrity and security
"""

import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple
import json
import yaml
import xml.etree.ElementTree as ET

class DataValidator:
    """Data validation utilities"""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address"""
        
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_ip_range(ip_range: str) -> bool:
        """Validate IP range/CIDR"""
        
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address"""
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL"""
        
        pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url, re.I))
    
    @staticmethod
    def validate_timestamp(timestamp: str, format: str = None) -> bool:
        """Validate timestamp"""
        
        try:
            if format:
                datetime.strptime(timestamp, format)
            else:
                # Try common formats
                formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%d/%b/%Y:%H:%M:%S',
                    '%a %b %d %H:%M:%S %Y'
                ]
                
                for fmt in formats:
                    try:
                        datetime.strptime(timestamp, fmt)
                        return True
                    except ValueError:
                        continue
                
                # Try ISO format
                datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def validate_json(data: str) -> bool:
        """Validate JSON data"""
        
        try:
            json.loads(data)
            return True
        except (json.JSONDecodeError, TypeError):
            return False
    
    @staticmethod
    def validate_yaml(data: str) -> bool:
        """Validate YAML data"""
        
        try:
            yaml.safe_load(data)
            return True
        except (yaml.YAMLError, TypeError):
            return False
    
    @staticmethod
    def validate_xml(data: str) -> bool:
        """Validate XML data"""
        
        try:
            ET.fromstring(data)
            return True
        except (ET.ParseError, TypeError):
            return False
    
    @staticmethod
    def validate_csv(data: str, delimiter: str = ',') -> bool:
        """Validate CSV data"""
        
        try:
            lines = data.strip().split('\n')
            if not lines:
                return False
            
            # Check if all lines have same number of columns
            first_line_cols = len(lines[0].split(delimiter))
            for line in lines[1:]:
                if len(line.split(delimiter)) != first_line_cols:
                    return False
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def validate_log_format(line: str, format_type: str = 'nginx_combined') -> bool:
        """Validate log line format"""
        
        patterns = {
            'nginx_combined': r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            'apache_combined': r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            'clf': r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)'
        }
        
        if format_type not in patterns:
            return False
        
        return bool(re.match(patterns[format_type], line))
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """Validate port number"""
        
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """Validate MAC address"""
        
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    @staticmethod
    def validate_file_path(path: str, check_exists: bool = False) -> bool:
        """Validate file path"""
        
        import os
        
        try:
            # Check for path traversal attempts
            if '..' in path or path.startswith('/') or ':' in path:
                return False
            
            # Check if path exists
            if check_exists:
                return os.path.exists(path)
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def validate_input_string(input_str: str, max_length: int = 1000, 
                             allowed_chars: str = None) -> bool:
        """Validate input string for security"""
        
        if not isinstance(input_str, str):
            return False
        
        # Check length
        if len(input_str) > max_length:
            return False
        
        # Check for null bytes
        if '\x00' in input_str:
            return False
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'<script.*?>',
            r'javascript:',
            r'vbscript:',
            r'onload=',
            r'onerror=',
            r'eval\(',
            r'exec\(',
            r'system\('
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, input_str, re.I):
                return False
        
        # Check allowed characters
        if allowed_chars:
            pattern = f'^[{re.escape(allowed_chars)}]+$'
            return bool(re.match(pattern, input_str))
        
        return True
    
    @staticmethod
    def validate_config(config: Dict[str, Any], required_keys: List[str] = None) -> Tuple[bool, List[str]]:
        """Validate configuration dictionary"""
        
        errors = []
        
        if not isinstance(config, dict):
            errors.append("Configuration must be a dictionary")
            return False, errors
        
        # Check required keys
        if required_keys:
            for key in required_keys:
                if key not in config:
                    errors.append(f"Missing required key: {key}")
        
        # Validate specific configuration values
        if 'time_window' in config:
            if not isinstance(config['time_window'], (int, float)) or config['time_window'] <= 0:
                errors.append("time_window must be a positive number")
        
        if 'thresholds' in config and isinstance(config['thresholds'], dict):
            thresholds = config['thresholds']
            for key, value in thresholds.items():
                if not isinstance(value, (int, float)):
                    errors.append(f"Threshold {key} must be a number")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_finding(finding: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate finding dictionary"""
        
        errors = []
        required_keys = ['type', 'severity', 'timestamp', 'description']
        
        # Check required keys
        for key in required_keys:
            if key not in finding:
                errors.append(f"Missing required key in finding: {key}")
        
        # Validate severity
        if 'severity' in finding:
            valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            if finding['severity'] not in valid_severities:
                errors.append(f"Invalid severity: {finding['severity']}. Must be one of {valid_severities}")
        
        # Validate timestamp
        if 'timestamp' in finding:
            if not DataValidator.validate_timestamp(finding['timestamp']):
                errors.append(f"Invalid timestamp: {finding['timestamp']}")
        
        # Validate IP if present
        if 'ip' in finding and finding['ip']:
            if not DataValidator.validate_ip_address(finding['ip']):
                errors.append(f"Invalid IP address: {finding['ip']}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input string"""
        
        if not isinstance(input_str, str):
            return ''
        
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        # Remove control characters (except newline and tab)
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        # Escape HTML entities
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&apos;",
            ">": "&gt;",
            "<": "&lt;",
        }
        
        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized
    
    @staticmethod
    def normalize_data(data: Any, data_type: str = None) -> Any:
        """Normalize data based on type"""
        
        if data_type == 'ip':
            try:
                return str(ipaddress.ip_address(data))
            except ValueError:
                return data
        
        elif data_type == 'timestamp':
            if DataValidator.validate_timestamp(data):
                return data
            return None
        
        elif data_type == 'number':
            try:
                return float(data)
            except (ValueError, TypeError):
                return 0
        
        elif data_type == 'boolean':
            if isinstance(data, bool):
                return data
            if isinstance(data, str):
                return data.lower() in ['true', 'yes', '1', 'on']
            return bool(data)
        
        elif data_type == 'string':
            return str(data) if data is not None else ''
        
        else:
            return data
