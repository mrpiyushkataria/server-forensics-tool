"""
Utility Helper Functions
Common helper functions used throughout the application
"""

import os
import sys
import json
import hashlib
import logging
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Callable
import re
import ipaddress
import socket
import csv

def setup_logging(log_level: str = 'INFO', log_file: str = None) -> logging.Logger:
    """Setup application logging"""
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logger
    logger = logging.getLogger('server_forensics')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logger.addHandler(file_handler)
    
    return logger

def create_hash(value: str, algorithm: str = 'sha256') -> str:
    """Create hash of a string"""
    
    hash_func = getattr(hashlib, algorithm.lower(), hashlib.sha256)
    return hash_func(value.encode()).hexdigest()

def normalize_ip(ip: str) -> str:
    """Normalize IP address format"""
    
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    
    if not url:
        return None
    
    # Remove protocol
    if '://' in url:
        url = url.split('://')[1]
    
    # Remove path and query
    domain = url.split('/')[0]
    
    # Remove port
    if ':' in domain:
        domain = domain.split(':')[0]
    
    return domain

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem usage"""
    
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255 - len(ext)] + ext
    
    return sanitized

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string"""
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def format_timedelta(delta: timedelta) -> str:
    """Format timedelta to human readable string"""
    
    total_seconds = int(delta.total_seconds())
    
    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes}m {seconds}s"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        return f"{days}d {hours}h"

def parse_time_string(time_str: str) -> timedelta:
    """Parse time string like '24h', '30m', '7d' to timedelta"""
    
    time_str = time_str.lower().strip()
    
    unit_multipliers = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400,
        'w': 604800
    }
    
    match = re.match(r'^(\d+)([smhdw])$', time_str)
    if match:
        value, unit = match.groups()
        return timedelta(seconds=int(value) * unit_multipliers[unit])
    
    # Try to parse ISO format
    try:
        return datetime.fromisoformat(time_str) - datetime.now()
    except ValueError:
        pass
    
    # Default to 24 hours
    return timedelta(hours=24)

def find_files(pattern: str, root_dir: str = '.', recursive: bool = True) -> List[Path]:
    """Find files matching pattern"""
    
    root = Path(root_dir)
    files = []
    
    if recursive:
        for file_path in root.rglob(pattern):
            if file_path.is_file():
                files.append(file_path)
    else:
        for file_path in root.glob(pattern):
            if file_path.is_file():
                files.append(file_path)
    
    return sorted(files)

def read_file_safely(file_path: Union[str, Path], encoding: str = 'utf-8') -> Optional[str]:
    """Read file with error handling"""
    
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except Exception as e:
        logging.warning(f"Failed to read {file_path}: {e}")
        return None

def write_file_safely(file_path: Union[str, Path], content: str, encoding: str = 'utf-8') -> bool:
    """Write file with error handling"""
    
    try:
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        logging.error(f"Failed to write {file_path}: {e}")
        return False

def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks of specified size"""
    
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

def flatten_dict(nested_dict: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary"""
    
    items = []
    for key, value in nested_dict.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, sep=sep).items())
        elif isinstance(value, list):
            # Convert lists to strings
            items.append((new_key, ';'.join(str(v) for v in value)))
        else:
            items.append((new_key, value))
    
    return dict(items)

def deep_merge(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries"""
    
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result

def retry_on_error(func: Callable, max_attempts: int = 3, delay: float = 1.0, 
                   exceptions: tuple = (Exception,)) -> Any:
    """Retry function on failure"""
    
    import time
    
    for attempt in range(max_attempts):
        try:
            return func()
        except exceptions as e:
            if attempt == max_attempts - 1:
                raise
            time.sleep(delay)
    
    return None

def is_running_in_docker() -> bool:
    """Check if running inside Docker container"""
    
    path = Path('/.dockerenv')
    return path.exists()

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    
    import platform
    import psutil
    
    info = {
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'hostname': socket.gethostname(),
        'cpu_count': psutil.cpu_count(),
        'memory_gb': psutil.virtual_memory().total / (1024**3),
        'disk_usage': psutil.disk_usage('/')._asdict(),
        'running_in_docker': is_running_in_docker()
    }
    
    return info

def measure_execution_time(func: Callable) -> Callable:
    """Decorator to measure function execution time"""
    
    import time
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        logging.info(f"{func.__name__} executed in {end_time - start_time:.2f} seconds")
        return result
    
    return wrapper

def create_temp_file(content: str = '', suffix: str = '.tmp') -> str:
    """Create temporary file with content"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        if content:
            f.write(content)
        return f.name

def execute_command(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Execute shell command with timeout"""
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success': result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': f'Command timed out after {timeout} seconds',
            'success': False
        }
    except Exception as e:
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': str(e),
            'success': False
        }

def validate_json_schema(data: Dict, schema: Dict) -> bool:
    """Validate data against JSON schema (simplified)"""
    
    # This is a simplified schema validation
    # For production, use jsonschema library
    
    def validate_item(item, schema_item, path=''):
        if schema_item == 'string':
            return isinstance(item, str)
        elif schema_item == 'number':
            return isinstance(item, (int, float))
        elif schema_item == 'boolean':
            return isinstance(item, bool)
        elif schema_item == 'array':
            return isinstance(item, list)
        elif schema_item == 'object':
            return isinstance(item, dict)
        elif isinstance(schema_item, dict):
            if 'type' in schema_item:
                return validate_item(item, schema_item['type'], path)
        return True
    
    for key, schema_type in schema.items():
        if key not in data:
            return False
        if not validate_item(data[key], schema_type, key):
            return False
    
    return True

def generate_report_id() -> str:
    """Generate unique report ID"""
    
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_part = hashlib.md5(str(os.urandom(16)).encode()).hexdigest()[:8]
    return f"REPORT-{timestamp}-{random_part}"

def anonymize_data(data: str, keep_chars: int = 4) -> str:
    """Anonymize sensitive data"""
    
    if len(data) <= keep_chars * 2:
        return '*' * len(data)
    
    return data[:keep_chars] + '*' * (len(data) - keep_chars * 2) + data[-keep_chars:]

def compress_data(data: str, compression: str = 'gzip') -> bytes:
    """Compress data"""
    
    import gzip
    import bz2
    
    if compression == 'gzip':
        return gzip.compress(data.encode())
    elif compression == 'bz2':
        return bz2.compress(data.encode())
    else:
        return data.encode()

def decompress_data(data: bytes, compression: str = 'gzip') -> str:
    """Decompress data"""
    
    import gzip
    import bz2
    
    try:
        if compression == 'gzip':
            return gzip.decompress(data).decode()
        elif compression == 'bz2':
            return bz2.decompress(data).decode()
        else:
            return data.decode()
    except:
        return data.decode('utf-8', errors='ignore')
