"""
PHP Log Processor
Specialized processing for PHP/FPM error logs
"""

import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from pathlib import Path

class PHPProcessor:
    """Process PHP error logs"""
    
    # PHP error patterns
    ERROR_PATTERNS = {
        'fatal_error': re.compile(r'PHP Fatal error:\s*(.*?) in (.*?) on line (\d+)', re.I),
        'parse_error': re.compile(r'PHP Parse error:\s*(.*?) in (.*?) on line (\d+)', re.I),
        'warning': re.compile(r'PHP Warning:\s*(.*?) in (.*?) on line (\d+)', re.I),
        'notice': re.compile(r'PHP Notice:\s*(.*?) in (.*?) on line (\d+)', re.I),
        'deprecated': re.compile(r'PHP Deprecated:\s*(.*?) in (.*?) on line (\d+)', re.I),
        'exception': re.compile(r'PHP Exception:\s*(.*?) in (.*?) on line (\d+)', re.I)
    }
    
    # Common error messages indicating attacks
    SUSPICIOUS_ERRORS = {
        'sql_injection': [
            r'mysql(i)?_real_escape_string',
            r'SQL syntax',
            r'You have an error in your SQL syntax',
            r'MySQL server has gone away',
            r'Division by zero'
        ],
        'file_inclusion': [
            r'failed to open stream',
            r'No such file or directory',
            r'failed to open stream: HTTP request failed',
            r'include_path'
        ],
        'xss': [
            r'Undefined index',
            r'Undefined variable',
            r'Illegal string offset'
        ],
        'path_traversal': [
            r'\.\./',
            r'\.\.\\',
            r'open_basedir restriction',
            r'Permission denied'
        ],
        'memory_exhaustion': [
            r'Allowed memory size',
            r'Out of memory',
            r'exhausted memory'
        ]
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.compiled_suspicious = {}
        
        # Compile suspicious patterns
        for category, patterns in self.SUSPICIOUS_ERRORS.items():
            self.compiled_suspicious[category] = [
                re.compile(pattern, re.I) for pattern in patterns
            ]
    
    def process_error_logs(self, log_path: str) -> pd.DataFrame:
        """Process PHP error logs"""
        
        errors = []
        
        for log_file in self._find_log_files(log_path, ['error_log', 'php_errors.log', '*.php.log']):
            content = self._read_log_file(log_file)
            
            for line in content.splitlines():
                parsed = self._parse_error_line(line, str(log_file))
                if parsed:
                    errors.append(parsed)
        
        if errors:
            df = pd.DataFrame(errors)
            return self._enhance_error_data(df)
        
        return pd.DataFrame()
    
    def _parse_error_line(self, line: str, filename: str) -> Optional[Dict]:
        """Parse a single PHP error log line"""
        
        # Try different timestamp formats
        timestamp = None
        error_data = None
        
        # Format 1: [Day Mon DD HH:MM:SS.XXXXXX YYYY]
        match = re.match(r'^\[(.*?)\]\s+(.*)', line)
        if match:
            timestamp_str, error_message = match.groups()
            timestamp = self._parse_php_timestamp(timestamp_str)
            error_data = self._parse_error_message(error_message, filename)
        
        # Format 2: PHP error without timestamp
        if not error_data:
            error_data = self._parse_error_message(line, filename)
            timestamp = datetime.now()  # Use current time if no timestamp
        
        if error_data:
            error_data['timestamp'] = timestamp
            error_data['source_file'] = filename
            error_data['raw_line'] = line[:500]
            
            # Check if error is suspicious
            error_data['is_suspicious'] = self._check_suspicious_error(error_data)
            error_data['suspicious_categories'] = self._get_suspicious_categories(error_data)
            
            return error_data
        
        return None
    
    def _parse_error_message(self, message: str, filename: str) -> Optional[Dict]:
        """Parse PHP error message"""
        
        for error_type, pattern in self.ERROR_PATTERNS.items():
            match = pattern.search(message)
            if match:
                error_msg, file_path, line_no = match.groups()
                
                return {
                    'error_type': error_type.upper(),
                    'error_message': error_msg.strip(),
                    'file_path': file_path.strip(),
                    'line_number': int(line_no) if line_no.isdigit() else 0,
                    'severity': self._get_error_severity(error_type)
                }
        
        return None
    
    def detect_error_patterns(self, df: pd.DataFrame) -> Dict[str, List]:
        """Detect patterns in PHP errors"""
        
        if df.empty:
            return {}
        
        findings = {
            'suspicious_errors': [],
            'frequent_errors': [],
            'error_trends': [],
            'attack_indicators': []
        }
        
        # Find suspicious errors
        suspicious = df[df['is_suspicious']].copy()
        if not suspicious.empty:
            for _, row in suspicious.iterrows():
                findings['suspicious_errors'].append({
                    'timestamp': row['timestamp'].isoformat(),
                    'error_type': row['error_type'],
                    'error_message': row['error_message'][:200],
                    'file_path': row['file_path'],
                    'line_number': row['line_number'],
                    'suspicious_categories': row.get('suspicious_categories', []),
                    'severity': row.get('severity', 'MEDIUM')
                })
        
        # Find frequent errors
        error_counts = df.groupby(['error_type', 'error_message']).size()
        frequent_errors = error_counts[error_counts >= 10]  # At least 10 occurrences
        
        for (error_type, message), count in frequent_errors.items():
            error_group = df[(df['error_type'] == error_type) & 
                           (df['error_message'] == message)]
            
            findings['frequent_errors'].append({
                'error_type': error_type,
                'error_message': message[:150],
                'occurrence_count': int(count),
                'first_occurrence': error_group['timestamp'].min().isoformat(),
                'last_occurrence': error_group['timestamp'].max().isoformat(),
                'unique_files': error_group['file_path'].nunique(),
                'severity': self._get_error_severity(error_type.lower())
            })
        
        # Analyze error trends
        if not df.empty:
            df['hour'] = df['timestamp'].dt.hour
            hourly_trends = df.groupby('hour').size()
            
            peak_hours = hourly_trends[hourly_trends > hourly_trends.mean() * 2]
            for hour, count in peak_hours.items():
                hour_errors = df[df['hour'] == hour]
                
                findings['error_trends'].append({
                    'hour': hour,
                    'error_count': int(count),
                    'peak_period': f"{hour:02d}:00-{hour:02d}:59",
                    'common_error_types': hour_errors['error_type'].value_counts().head(3).to_dict(),
                    'severity_distribution': hour_errors['severity'].value_counts().to_dict()
                })
        
        # Detect attack indicators
        attack_errors = df[df['suspicious_categories'].apply(lambda x: len(x) > 0)]
        if not attack_errors.empty:
            for category in ['sql_injection', 'file_inclusion', 'path_traversal']:
                category_errors = attack_errors[
                    attack_errors['suspicious_categories'].apply(
                        lambda x: category in x
                    )
                ]
                
                if not category_errors.empty:
                    findings['attack_indicators'].append({
                        'attack_type': category.replace('_', ' ').title(),
                        'error_count': len(category_errors),
                        'unique_ips': category_errors.get('client_ip', pd.Series()).nunique(),
                        'time_range': {
                            'start': category_errors['timestamp'].min().isoformat(),
                            'end': category_errors['timestamp'].max().isoformat()
                        },
                        'common_files': category_errors['file_path'].value_counts().head(5).to_dict(),
                        'sample_errors': category_errors['error_message'].head(3).tolist()
                    })
        
        return findings
    
    def correlate_with_requests(self, error_df: pd.DataFrame, 
                              request_df: pd.DataFrame, 
                              time_window: int = 5) -> List[Dict]:
        """Correlate PHP errors with HTTP requests"""
        
        correlations = []
        
        if error_df.empty or request_df.empty:
            return correlations
        
        # For each error, find requests around the same time
        for _, error_row in error_df.iterrows():
            error_time = error_row['timestamp']
            
            # Find requests within time window
            time_start = error_time - pd.Timedelta(seconds=time_window)
            time_end = error_time + pd.Timedelta(seconds=time_window)
            
            matching_requests = request_df[
                (request_df['timestamp'] >= time_start) & 
                (request_df['timestamp'] <= time_end)
            ]
            
            if not matching_requests.empty:
                # Check if any request parameters match error context
                for _, req_row in matching_requests.iterrows():
                    correlation_score = self._calculate_correlation_score(error_row, req_row)
                    
                    if correlation_score > 0.5:  # Threshold
                        correlations.append({
                            'error_timestamp': error_time.isoformat(),
                            'request_timestamp': req_row['timestamp'].isoformat(),
                            'time_difference_seconds': abs((error_time - req_row['timestamp']).total_seconds()),
                            'error_type': error_row['error_type'],
                            'error_message': error_row['error_message'][:200],
                            'request_endpoint': req_row.get('endpoint', 'N/A'),
                            'request_ip': req_row.get('ip', 'N/A'),
                            'request_method': req_row.get('method', 'N/A'),
                            'correlation_score': correlation_score,
                            'suspicious_categories': error_row.get('suspicious_categories', [])
                        })
        
        return correlations
    
    # Helper methods
    def _find_log_files(self, base_path: str, patterns: List[str]) -> List[Path]:
        """Find PHP log files"""
        
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
            print(f"Error reading PHP log {file_path}: {e}")
            return ""
    
    def _parse_php_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse PHP timestamp"""
        
        formats = [
            '%a %b %d %H:%M:%S.%f %Y',
            '%a %b %d %H:%M:%S %Y',
            '%d-%b-%Y %H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return datetime.now()
    
    def _get_error_severity(self, error_type: str) -> str:
        """Get severity level for error type"""
        
        severity_map = {
            'fatal_error': 'CRITICAL',
            'parse_error': 'CRITICAL',
            'exception': 'HIGH',
            'warning': 'MEDIUM',
            'notice': 'LOW',
            'deprecated': 'INFO'
        }
        
        return severity_map.get(error_type.lower(), 'MEDIUM')
    
    def _check_suspicious_error(self, error_data: Dict) -> bool:
        """Check if error indicates suspicious activity"""
        
        error_msg = error_data.get('error_message', '').lower()
        file_path = error_data.get('file_path', '').lower()
        
        # Check all suspicious categories
        for category, patterns in self.compiled_suspicious.items():
            for pattern in patterns:
                if pattern.search(error_msg) or pattern.search(file_path):
                    return True
        
        return False
    
    def _get_suspicious_categories(self, error_data: Dict) -> List[str]:
        """Get suspicious categories for an error"""
        
        categories = []
        error_msg = error_data.get('error_message', '').lower()
        file_path = error_data.get('file_path', '').lower()
        
        for category, patterns in self.compiled_suspicious.items():
            for pattern in patterns:
                if pattern.search(error_msg) or pattern.search(file_path):
                    categories.append(category)
                    break
        
        return list(set(categories))
    
    def _enhance_error_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enhance error data with additional features"""
        
        if df.empty:
            return df
        
        # Add time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Add error category
        df['error_category'] = df['error_type'].apply(lambda x: x.split('_')[0] if '_' in x else x)
        
        # Add file extension
        df['file_extension'] = df['file_path'].apply(
            lambda x: Path(x).suffix.lower() if isinstance(x, str) else ''
        )
        
        # Add error complexity (message length)
        df['message_length'] = df['error_message'].apply(len)
        
        return df
    
    def _calculate_correlation_score(self, error_row: pd.Series, request_row: pd.Series) -> float:
        """Calculate correlation score between error and request"""
        
        score = 0.0
        
        # Time proximity (closer = higher score)
        time_diff = abs((error_row['timestamp'] - request_row['timestamp']).total_seconds())
        if time_diff < 1:
            score += 0.4
        elif time_diff < 5:
            score += 0.2
        elif time_diff < 10:
            score += 0.1
        
        # Check if request endpoint matches error file
        endpoint = request_row.get('endpoint', '')
        error_file = error_row.get('file_path', '')
        
        if endpoint and error_file:
            # Extract filename from endpoint
            endpoint_file = Path(endpoint).name
            
            # Extract filename from error file path
            error_filename = Path(error_file).name
            
            if endpoint_file and error_filename and endpoint_file == error_filename:
                score += 0.3
        
        # Check if error is suspicious and request has suspicious parameters
        if error_row.get('is_suspicious', False):
            request_params = request_row.get('query_params', {})
            if request_params:
                # Check for suspicious parameters
                suspicious_params = ['id', 'file', 'page', 'dir', 'cmd']
                if any(param in request_params for param in suspicious_params):
                    score += 0.3
        
        return min(score, 1.0)
