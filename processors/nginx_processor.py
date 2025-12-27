"""
Nginx Log Processor
Specialized processing for Nginx access and error logs
"""

import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
import gzip
import bz2
from pathlib import Path

class NginxProcessor:
    """Process Nginx logs with specialized analysis"""
    
    NGINX_COMBINED_FORMAT = r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    NGINX_ERROR_FORMAT = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): \*(.*?) (.*?)(?:, client: (.*?))?(?:, server: (.*?))?(?:, request: "(.*?)")?(?:, host: "(.*?)")?'
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.access_pattern = re.compile(self.NGINX_COMBINED_FORMAT)
        self.error_pattern = re.compile(self.NGINX_ERROR_FORMAT)
    
    def process_access_logs(self, log_path: str) -> pd.DataFrame:
        """Process Nginx access logs"""
        
        logs = []
        
        for log_file in self._find_log_files(log_path, ['access.log', 'access.log.*']):
            content = self._read_log_file(log_file)
            
            for line in content.splitlines():
                parsed = self._parse_access_line(line)
                if parsed:
                    logs.append(parsed)
        
        if logs:
            df = pd.DataFrame(logs)
            return self._enhance_access_data(df)
        
        return pd.DataFrame()
    
    def process_error_logs(self, log_path: str) -> pd.DataFrame:
        """Process Nginx error logs"""
        
        errors = []
        
        for log_file in self._find_log_files(log_path, ['error.log', 'error.log.*']):
            content = self._read_log_file(log_file)
            
            for line in content.splitlines():
                parsed = self._parse_error_line(line)
                if parsed:
                    errors.append(parsed)
        
        if errors:
            return pd.DataFrame(errors)
        
        return pd.DataFrame()
    
    def _parse_access_line(self, line: str) -> Optional[Dict]:
        """Parse a single Nginx access log line"""
        
        match = self.access_pattern.match(line)
        if not match:
            return None
        
        ip, _, timestamp_str, request, status, body_bytes_sent, referrer, user_agent = match.groups()
        
        try:
            timestamp = self._parse_nginx_timestamp(timestamp_str)
            
            # Parse request
            method, path, http_version = self._parse_request(request)
            
            # Extract endpoint
            endpoint = self._extract_endpoint(path)
            
            # Extract query parameters
            query_params = self._extract_query_params(path)
            
            return {
                'timestamp': timestamp,
                'ip': ip,
                'method': method,
                'path': path,
                'endpoint': endpoint,
                'query_params': query_params,
                'status': int(status),
                'body_bytes_sent': int(body_bytes_sent),
                'referrer': referrer if referrer != '-' else None,
                'user_agent': user_agent if user_agent != '-' else None,
                'http_version': http_version,
                'raw_line': line[:500]  # Store truncated raw line
            }
        except (ValueError, AttributeError) as e:
            return None
    
    def _parse_error_line(self, line: str) -> Optional[Dict]:
        """Parse a single Nginx error log line"""
        
        match = self.error_pattern.match(line)
        if not match:
            return None
        
        timestamp_str, log_level, pid, tid, error_code, message, client, server, request, host = match.groups()
        
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S')
            
            return {
                'timestamp': timestamp,
                'log_level': log_level,
                'pid': int(pid) if pid else None,
                'tid': int(tid) if tid else None,
                'error_code': error_code,
                'message': message,
                'client': client,
                'server': server,
                'request': request,
                'host': host,
                'raw_line': line[:500]
            }
        except (ValueError, AttributeError):
            return None
    
    def _enhance_access_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enhance access log data with additional features"""
        
        if df.empty:
            return df
        
        # Add time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Add user agent features
        df['is_bot'] = df['user_agent'].apply(self._is_bot_user_agent)
        df['is_mobile'] = df['user_agent'].apply(self._is_mobile_user_agent)
        
        # Add request complexity
        df['path_length'] = df['path'].apply(len)
        df['param_count'] = df['query_params'].apply(lambda x: len(x) if x else 0)
        
        # Add response categories
        df['response_category'] = df['status'].apply(self._categorize_status)
        
        # Add data transfer categories
        df['data_category'] = pd.cut(
            df['body_bytes_sent'],
            bins=[-1, 1024, 10240, 102400, 1048576, float('inf')],
            labels=['TINY', 'SMALL', 'MEDIUM', 'LARGE', 'HUGE']
        )
        
        return df
    
    def detect_brute_force(self, df: pd.DataFrame, 
                          endpoint_pattern: str = 'login|auth',
                          window_minutes: int = 5,
                          threshold: int = 20) -> List[Dict]:
        """Detect brute force attacks on authentication endpoints"""
        
        login_requests = df[
            df['endpoint'].str.contains(endpoint_pattern, case=False, na=False) |
            df['path'].str.contains(endpoint_pattern, case=False, na=False)
        ].copy()
        
        if login_requests.empty:
            return []
        
        # Create time windows
        login_requests['time_window'] = login_requests['timestamp'].dt.floor(f'{window_minutes}T')
        
        # Group by IP and time window
        window_counts = login_requests.groupby(['ip', 'time_window']).size()
        suspicious_windows = window_counts[window_counts >= threshold]
        
        findings = []
        for (ip, window), count in suspicious_windows.items():
            window_data = login_requests[
                (login_requests['ip'] == ip) & 
                (login_requests['time_window'] == window)
            ]
            
            # Analyze success/failure ratio
            status_counts = window_data['status'].value_counts().to_dict()
            success_count = sum(v for k, v in status_counts.items() if k in [200, 302, 303])
            failure_count = count - success_count
            
            # Check for credential stuffing patterns
            user_agents = window_data['user_agent'].unique().tolist()
            unique_user_agents = len(user_agents)
            
            findings.append({
                'ip': ip,
                'time_window_start': window.isoformat(),
                'time_window_end': (window + pd.Timedelta(minutes=window_minutes)).isoformat(),
                'attempt_count': int(count),
                'success_count': success_count,
                'failure_count': failure_count,
                'success_rate': success_count / count if count > 0 else 0,
                'unique_user_agents': unique_user_agents,
                'endpoints_accessed': window_data['endpoint'].unique().tolist(),
                'status_distribution': status_counts,
                'user_agents_sample': user_agents[:3]
            })
        
        return findings
    
    def detect_data_scraping(self, df: pd.DataFrame,
                           large_response_threshold: int = 1048576,  # 1MB
                           consecutive_threshold: int = 10) -> List[Dict]:
        """Detect potential data scraping patterns"""
        
        # Find large responses
        large_responses = df[df['body_bytes_sent'] >= large_response_threshold].copy()
        
        if large_responses.empty:
            return []
        
        # Sort by IP and timestamp
        large_responses = large_responses.sort_values(['ip', 'timestamp'])
        
        findings = []
        current_chain = []
        
        for _, row in large_responses.iterrows():
            if not current_chain:
                current_chain.append(row)
                continue
            
            last_row = current_chain[-1]
            
            # Check if same IP and consecutive timing
            if (row['ip'] == last_row['ip'] and 
                (row['timestamp'] - last_row['timestamp']).total_seconds() < 300):  # 5 minutes
                current_chain.append(row)
            else:
                if len(current_chain) >= consecutive_threshold:
                    findings.append(self._analyze_scraping_chain(current_chain))
                current_chain = [row]
        
        # Check last chain
        if len(current_chain) >= consecutive_threshold:
            findings.append(self._analyze_scraping_chain(current_chain))
        
        return findings
    
    def detect_enumeration(self, df: pd.DataFrame,
                          id_pattern: str = r'id=\d+',
                          threshold: int = 100) -> List[Dict]:
        """Detect ID enumeration attacks"""
        
        # Find requests with ID parameters
        id_requests = df[df['path'].str.contains(id_pattern, na=False)].copy()
        
        if id_requests.empty:
            return []
        
        # Group by IP and endpoint pattern
        findings = []
        
        for (ip, endpoint), group in id_requests.groupby(['ip', 'endpoint']):
            if len(group) >= threshold:
                # Check for sequential patterns
                ids = self._extract_ids_from_paths(group['path'].tolist())
                is_sequential = self._check_sequential_ids(ids)
                
                findings.append({
                    'ip': ip,
                    'endpoint': endpoint,
                    'request_count': len(group),
                    'unique_ids_count': len(set(ids)),
                    'is_sequential': is_sequential,
                    'id_range': f"{min(ids)}-{max(ids)}" if ids else None,
                    'time_range_start': group['timestamp'].min().isoformat(),
                    'time_range_end': group['timestamp'].max().isoformat(),
                    'sample_ids': ids[:5]
                })
        
        return findings
    
    def analyze_endpoint_traffic(self, df: pd.DataFrame, 
                               endpoint: str) -> Dict[str, Any]:
        """Detailed analysis of traffic to a specific endpoint"""
        
        endpoint_data = df[df['endpoint'] == endpoint].copy()
        
        if endpoint_data.empty:
            return {}
        
        # Basic statistics
        total_requests = len(endpoint_data)
        unique_ips = endpoint_data['ip'].nunique()
        total_data = endpoint_data['body_bytes_sent'].sum()
        
        # Time-based analysis
        hourly_traffic = endpoint_data.groupby(
            endpoint_data['timestamp'].dt.hour
        ).size().to_dict()
        
        daily_traffic = endpoint_data.groupby(
            endpoint_data['timestamp'].dt.date
        ).size().to_dict()
        
        # IP analysis
        top_ips = endpoint_data['ip'].value_counts().head(10).to_dict()
        
        # Status code analysis
        status_distribution = endpoint_data['status'].value_counts().to_dict()
        
        # User agent analysis
        top_user_agents = endpoint_data['user_agent'].value_counts().head(5).to_dict()
        
        # Request method analysis
        method_distribution = endpoint_data['method'].value_counts().to_dict()
        
        return {
            'endpoint': endpoint,
            'total_requests': total_requests,
            'unique_ips': unique_ips,
            'total_data_mb': total_data / (1024 * 1024),
            'avg_response_size': endpoint_data['body_bytes_sent'].mean(),
            'time_span_hours': (endpoint_data['timestamp'].max() - 
                               endpoint_data['timestamp'].min()).total_seconds() / 3600,
            'requests_per_hour': total_requests / max((endpoint_data['timestamp'].max() - 
                                                     endpoint_data['timestamp'].min()).total_seconds() / 3600, 1),
            'hourly_traffic': hourly_traffic,
            'daily_traffic': daily_traffic,
            'top_ips': top_ips,
            'status_distribution': status_distribution,
            'top_user_agents': top_user_agents,
            'method_distribution': method_distribution,
            'bot_traffic_percentage': (endpoint_data['is_bot'].sum() / total_requests * 100 
                                      if total_requests > 0 else 0),
            'mobile_traffic_percentage': (endpoint_data['is_mobile'].sum() / total_requests * 100 
                                         if total_requests > 0 else 0)
        }
    
    # Helper methods
    def _find_log_files(self, base_path: str, patterns: List[str]) -> List[Path]:
        """Find log files matching patterns"""
        
        base = Path(base_path)
        log_files = []
        
        for pattern in patterns:
            for log_file in base.rglob(pattern):
                if log_file.is_file():
                    log_files.append(log_file)
        
        return sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True)
    
    def _read_log_file(self, file_path: Path) -> str:
        """Read log file, handling compression"""
        
        suffix = file_path.suffix
        
        try:
            if suffix == '.gz':
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    return f.read()
            elif suffix == '.bz2':
                with bz2.open(file_path, 'rt', encoding='utf-8') as f:
                    return f.read()
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return ""
    
    def _parse_nginx_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Nginx timestamp format"""
        
        # Try common formats
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y/%m/%d %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Fallback to manual parsing
        return datetime.now()
    
    def _parse_request(self, request: str) -> Tuple[str, str, str]:
        """Parse HTTP request line"""
        
        parts = request.split()
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], 'HTTP/1.0'
        elif len(parts) == 1:
            return parts[0], '/', 'HTTP/1.0'
        else:
            return 'GET', '/', 'HTTP/1.0'
    
    def _extract_endpoint(self, path: str) -> str:
        """Extract endpoint from path"""
        
        if not path:
            return '/'
        
        # Remove query parameters
        clean_path = path.split('?')[0]
        
        # Remove trailing slashes
        clean_path = clean_path.rstrip('/')
        
        # Ensure it starts with /
        if not clean_path.startswith('/'):
            clean_path = '/' + clean_path
        
        return clean_path or '/'
    
    def _extract_query_params(self, path: str) -> Dict[str, List[str]]:
        """Extract query parameters from path"""
        
        if '?' not in path:
            return {}
        
        query_string = path.split('?')[1]
        params = defaultdict(list)
        
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key].append(value)
        
        return dict(params)
    
    def _is_bot_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is a bot/crawler"""
        
        if not isinstance(user_agent, str):
            return False
        
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python-requests', 'java', 'go-http-client',
            'apache-httpclient', 'okhttp', 'node-fetch'
        ]
        
        ua_lower = user_agent.lower()
        return any(indicator in ua_lower for indicator in bot_indicators)
    
    def _is_mobile_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is mobile"""
        
        if not isinstance(user_agent, str):
            return False
        
        mobile_indicators = [
            'mobile', 'android', 'iphone', 'ipad', 'ipod',
            'blackberry', 'windows phone', 'opera mini'
        ]
        
        ua_lower = user_agent.lower()
        return any(indicator in ua_lower for indicator in mobile_indicators)
    
    def _categorize_status(self, status: int) -> str:
        """Categorize HTTP status code"""
        
        if 100 <= status < 200:
            return 'INFORMATIONAL'
        elif 200 <= status < 300:
            return 'SUCCESS'
        elif 300 <= status < 400:
            return 'REDIRECTION'
        elif 400 <= status < 500:
            return 'CLIENT_ERROR'
        elif 500 <= status < 600:
            return 'SERVER_ERROR'
        else:
            return 'UNKNOWN'
    
    def _analyze_scraping_chain(self, chain: List[pd.Series]) -> Dict[str, Any]:
        """Analyze a chain of scraping requests"""
        
        df_chain = pd.DataFrame(chain)
        
        return {
            'ip': df_chain['ip'].iloc[0],
            'endpoints_accessed': df_chain['endpoint'].unique().tolist(),
            'request_count': len(df_chain),
            'total_data_mb': df_chain['body_bytes_sent'].sum() / (1024 * 1024),
            'time_span_minutes': (df_chain['timestamp'].max() - 
                                 df_chain['timestamp'].min()).total_seconds() / 60,
            'data_rate_mbps': (df_chain['body_bytes_sent'].sum() * 8) / 
                             max((df_chain['timestamp'].max() - 
                                  df_chain['timestamp'].min()).total_seconds(), 1) / (1024 * 1024),
            'start_time': df_chain['timestamp'].min().isoformat(),
            'end_time': df_chain['timestamp'].max().isoformat(),
            'status_distribution': df_chain['status'].value_counts().to_dict(),
            'user_agents': df_chain['user_agent'].unique().tolist()[:3]
        }
    
    def _extract_ids_from_paths(self, paths: List[str]) -> List[int]:
        """Extract numeric IDs from paths"""
        
        ids = []
        id_pattern = re.compile(r'id=(\d+)')
        
        for path in paths:
            match = id_pattern.search(path)
            if match:
                try:
                    ids.append(int(match.group(1)))
                except ValueError:
                    continue
        
        return sorted(ids)
    
    def _check_sequential_ids(self, ids: List[int]) -> bool:
        """Check if IDs are sequential"""
        
        if len(ids) < 3:
            return False
        
        # Check for sequential patterns
        for i in range(1, len(ids)):
            if ids[i] != ids[i-1] + 1:
                return False
        
        return True
