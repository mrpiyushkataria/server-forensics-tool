import pandas as pd
import re
import gzip
import bz2
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import pytz

class LogCollector:
    """Collect and parse logs from various sources"""
    
    def __init__(self, log_dir: str, time_range: str = '24h'):
        self.log_dir = Path(log_dir)
        self.time_range = self._parse_time_range(time_range)
        self.timezone = pytz.UTC
    
    def collect_all(self) -> Dict[str, pd.DataFrame]:
        """Collect all available logs"""
        
        logs = {}
        
        # Nginx logs
        nginx_logs = self._collect_nginx_logs()
        if not nginx_logs.empty:
            logs['nginx'] = nginx_logs
        
        # PHP logs
        php_logs = self._collect_php_logs()
        if not php_logs.empty:
            logs['php'] = php_logs
        
        # MySQL logs
        mysql_logs = self._collect_mysql_logs()
        if not mysql_logs.empty:
            logs['mysql'] = mysql_logs
        
        return logs
    
def _collect_nginx_logs(self) -> pd.DataFrame:
    """Collect and parse Nginx logs"""
    
    nginx_logs = []
    log_patterns = [
        'access.log*',  # Changed from ['access.log', 'access.log.*']
        'error.log*',   # Changed from ['error.log', 'error.log.*']
    ]
    
    print(f"🔍 Looking for Nginx logs in: {self.log_dir}")
    
    for pattern in log_patterns:
        try:
            # Use glob instead of rglob for simpler pattern matching
            for log_file in self.log_dir.glob(pattern):
                if not log_file.is_file():
                    continue
                    
                print(f"📄 Found log file: {log_file}")
                
                try:
                    if log_file.suffix == '.gz':
                        with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    elif log_file.suffix == '.bz2':
                        with bz2.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    else:
                        # Try to read with appropriate encoding
                        try:
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        except UnicodeDecodeError:
                            with open(log_file, 'r', encoding='latin-1', errors='ignore') as f:
                                content = f.read()
                    
                    # Parse Nginx combined format
                    parsed = self._parse_nginx_log(content)
                    if parsed:
                        nginx_logs.extend(parsed)
                        print(f"✅ Parsed {len(parsed)} entries from {log_file.name}")
                    
                except PermissionError as e:
                    print(f"⚠️  Permission denied: {log_file}")
                    continue
                except Exception as e:
                    print(f"⚠️  Could not parse {log_file}: {e}")
                    continue
                    
        except Exception as e:
            print(f"⚠️  Error searching for pattern {pattern}: {e}")
            continue
    
    if nginx_logs:
        df = pd.DataFrame(nginx_logs)
        print(f"📊 Collected {len(df)} log entries")
        
        # Filter by time range
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df = df.dropna(subset=['timestamp'])
            
            cutoff = datetime.now(self.timezone) - self.time_range
            df = df[df['timestamp'] >= cutoff]
            
            print(f"📅 Filtered to {len(df)} entries within time range")
        
        return df
    
    print("❌ No Nginx logs found or parsed")
    return pd.DataFrame()
    
  def _parse_nginx_log(self, content: str) -> List[Dict]:
    """Parse Nginx combined log format"""
    
    logs = []
    # Nginx combined log format pattern (more flexible)
    pattern = r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    
    for line in content.splitlines():
        if not line.strip():
            continue
            
        match = re.match(pattern, line)
        if match:
            ip, _, timestamp_str, request, status, body_bytes_sent, referrer, user_agent = match.groups()
            
            try:
                # Parse timestamp with multiple format attempts
                timestamp = None
                timestamp_formats = [
                    '%d/%b/%Y:%H:%M:%S %z',
                    '%d/%b/%Y:%H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S%z',
                    '%Y-%m-%d %H:%M:%S'
                ]
                
                for fmt in timestamp_formats:
                    try:
                        timestamp = datetime.strptime(timestamp_str, fmt)
                        if '%z' not in fmt:  # If no timezone in format, assume UTC
                            timestamp = self.timezone.localize(timestamp)
                        break
                    except ValueError:
                        continue
                
                if timestamp is None:
                    print(f"⚠️  Could not parse timestamp: {timestamp_str}")
                    continue
                
                # Extract endpoint from request
                endpoint = self._extract_endpoint(request)
                
                logs.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'request': request,
                    'endpoint': endpoint,
                    'status': int(status),
                    'body_bytes_sent': int(body_bytes_sent) if body_bytes_sent.isdigit() else 0,
                    'referrer': referrer if referrer != '-' else None,
                    'user_agent': user_agent if user_agent != '-' else None,
                    'source': 'nginx'
                })
            except (ValueError, AttributeError) as e:
                continue
    
    return logs
    
    def _extract_endpoint(self, request: str) -> str:
        """Extract endpoint from HTTP request"""
        
        if not request:
            return '/'
        
        # Extract method and path
        parts = request.split()
        if len(parts) >= 2:
            # Get just the path without query parameters
            path = parts[1].split('?')[0]
            return path
        return '/'
    
    def _collect_php_logs(self) -> pd.DataFrame:
        """Collect and parse PHP logs"""
        
        php_logs = []
        log_patterns = [
            'php_errors.log', 'php-fpm.log', '*.php.log',
            '**/*error_log', '**/*php*.log'
        ]
        
        for pattern in log_patterns:
            for log_file in self.log_dir.rglob(pattern):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    parsed = self._parse_php_log(content, str(log_file))
                    php_logs.extend(parsed)
                    
                except Exception as e:
                    print(f"Warning: Could not parse PHP log {log_file}: {e}")
        
        if php_logs:
            df = pd.DataFrame(php_logs)
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
            
            return df
        
        return pd.DataFrame()
    
    def _parse_php_log(self, content: str, filename: str) -> List[Dict]:
        """Parse PHP error logs"""
        
        logs = []
        # Common PHP error patterns
        patterns = [
            r'\[(.*?)\] \[.*?\] PHP (Warning|Error|Notice|Fatal error): (.*)',
            r'\[(.*?)\] PHP (.*?): (.*)'
        ]
        
        for line in content.splitlines():
            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    timestamp_str, error_type, message = match.groups()
                    
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%d-%b-%Y %H:%M:%S')
                        timestamp = self.timezone.localize(timestamp)
                        
                        logs.append({
                            'timestamp': timestamp,
                            'error_type': error_type,
                            'message': message[:500],  # Truncate long messages
                            'filename': filename,
                            'source': 'php'
                        })
                    except ValueError:
                        # Try alternative format
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
                            timestamp = self.timezone.localize(timestamp)
                            
                            logs.append({
                                'timestamp': timestamp,
                                'error_type': error_type,
                                'message': message[:500],
                                'filename': filename,
                                'source': 'php'
                            })
                        except ValueError:
                            continue
        
        return logs
    
    def _collect_mysql_logs(self) -> pd.DataFrame:
        """Collect and parse MySQL logs"""
        
        mysql_logs = []
        log_patterns = [
            'mysql-slow.log', 'mysql.log', 'mysqld.log',
            '**/*mysql*.log'
        ]
        
        for pattern in log_patterns:
            for log_file in self.log_dir.rglob(pattern):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    parsed = self._parse_mysql_log(content)
                    mysql_logs.extend(parsed)
                    
                except Exception as e:
                    print(f"Warning: Could not parse MySQL log {log_file}: {e}")
        
        if mysql_logs:
            df = pd.DataFrame(mysql_logs)
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
            
            return df
        
        return pd.DataFrame()
    
    def _parse_mysql_log(self, content: str) -> List[Dict]:
        """Parse MySQL slow query and general logs"""
        
        logs = []
        
        # Slow query log pattern
        slow_pattern = r'^# Time: (.*?)\n# User@Host: (.*?)\n# Query_time: (.*?) Lock_time: (.*?) .*\n(.*?);'
        
        matches = re.findall(slow_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            time_str, user_host, query_time, lock_time, query = match
            
            try:
                timestamp = datetime.strptime(time_str.strip(), '%y%m%d %H:%M:%S')
                timestamp = self.timezone.localize(timestamp)
                
                # Extract user and host
                user_match = re.match(r'(\S+)\[@(\S+)\]', user_host)
                user = user_match.group(1) if user_match else 'unknown'
                host = user_match.group(2) if user_match else 'unknown'
                
                logs.append({
                    'timestamp': timestamp,
                    'user': user,
                    'host': host,
                    'query_time': float(query_time),
                    'lock_time': float(lock_time),
                    'query': query.strip()[:1000],  # Truncate very long queries
                    'query_type': self._get_query_type(query),
                    'source': 'mysql'
                })
            except ValueError:
                continue
        
        return logs
    
    def _get_query_type(self, query: str) -> str:
        """Determine query type"""
        query_upper = query.upper()
        
        if query_upper.startswith('SELECT'):
            return 'SELECT'
        elif query_upper.startswith('INSERT'):
            return 'INSERT'
        elif query_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif query_upper.startswith('DELETE'):
            return 'DELETE'
        elif query_upper.startswith('CREATE'):
            return 'CREATE'
        elif query_upper.startswith('DROP'):
            return 'DROP'
        elif query_upper.startswith('ALTER'):
            return 'ALTER'
        else:
            return 'OTHER'
    
    def _parse_time_range(self, time_range: str) -> pd.Timedelta:
        """Parse time range string to timedelta"""
        
        unit_map = {
            's': 'seconds',
            'm': 'minutes',
            'h': 'hours',
            'd': 'days',
            'w': 'weeks'
        }
        
        match = re.match(r'^(\d+)([smhdw])$', time_range.lower())
        if match:
            value, unit = match.groups()
            return pd.Timedelta(**{unit_map[unit]: int(value)})
        
        # Default to 24 hours
        return pd.Timedelta(hours=24)
