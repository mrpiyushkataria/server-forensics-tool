"""
MySQL Log Processor
Specialized processing for MySQL slow query and general logs
"""

import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from pathlib import Path

class MySQLProcessor:
    """Process MySQL logs with specialized analysis"""
    
    SLOW_QUERY_PATTERN = r'^# Time: (.*?)\n# User@Host: (.*?)\n# Query_time: (.*?) Lock_time: (.*?) .*\n(.*?);'
    GENERAL_QUERY_PATTERN = r'(\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+(\d+)\s+(\w+)\s+(.*)'
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.slow_query_regex = re.compile(self.SLOW_QUERY_PATTERN, re.MULTILINE | re.DOTALL)
        self.general_query_regex = re.compile(self.GENERAL_QUERY_PATTERN)
        
        # SQL injection patterns
        self.sqli_patterns = [
            r'union.*select', r'select.*from.*where.*=', r'or.*1=1',
            r'and.*1=1', r'exec.*xp_cmdshell', r'waitfor.*delay',
            r'benchmark\(', r'sleep\(', r'pg_sleep\(', r'--',
            r'\/\*.*\*\/', r'@@version', r'load_file\(', r'into.*outfile',
            r'into.*dumpfile', r'schema_name', r'table_name',
            r'column_name', r'information_schema'
        ]
        self.compiled_sqli_patterns = [re.compile(p, re.I) for p in self.sqli_patterns]
    
    def process_slow_logs(self, log_path: str) -> pd.DataFrame:
        """Process MySQL slow query logs"""
        
        slow_queries = []
        
        for log_file in self._find_log_files(log_path, ['mysql-slow.log', 'slow.log', '*slow*.log']):
            content = self._read_log_file(log_file)
            
            # Find all slow query entries
            matches = self.slow_query_regex.findall(content)
            
            for match in matches:
                parsed = self._parse_slow_query(match)
                if parsed:
                    slow_queries.append(parsed)
        
        if slow_queries:
            df = pd.DataFrame(slow_queries)
            return self._enhance_slow_query_data(df)
        
        return pd.DataFrame()
    
    def process_general_logs(self, log_path: str) -> pd.DataFrame:
        """Process MySQL general query logs"""
        
        general_queries = []
        
        for log_file in self._find_log_files(log_path, ['mysql.log', 'general.log', '*general*.log']):
            content = self._read_log_file(log_file)
            
            for line in content.splitlines():
                parsed = self._parse_general_query(line)
                if parsed:
                    general_queries.append(parsed)
        
        if general_queries:
            df = pd.DataFrame(general_queries)
            return self._enhance_general_query_data(df)
        
        return pd.DataFrame()
    
    def _parse_slow_query(self, match: Tuple) -> Optional[Dict]:
        """Parse a single slow query entry"""
        
        try:
            time_str, user_host, query_time, lock_time, query = match
            
            # Parse timestamp
            timestamp = datetime.strptime(time_str.strip(), '%y%m%d %H:%M:%S')
            
            # Parse user@host
            user_match = re.match(r'(\S+)\[@(\S+)\]', user_host.strip())
            user = user_match.group(1) if user_match else 'unknown'
            host = user_match.group(2) if user_match else 'unknown'
            
            # Clean query
            query = query.strip()
            
            # Determine query type
            query_type = self._get_query_type(query)
            
            # Extract table names
            tables = self._extract_tables(query)
            
            # Check for suspicious patterns
            is_suspicious = self._check_suspicious_query(query)
            
            return {
                'timestamp': timestamp,
                'user': user,
                'host': host,
                'query_time': float(query_time.strip()),
                'lock_time': float(lock_time.strip()),
                'query': query[:1000],  # Truncate very long queries
                'query_type': query_type,
                'tables': tables,
                'is_suspicious': is_suspicious,
                'suspicious_reasons': self._get_suspicious_reasons(query) if is_suspicious else [],
                'query_hash': self._hash_query(query)
            }
        except Exception as e:
            print(f"Error parsing slow query: {e}")
            return None
    
    def _parse_general_query(self, line: str) -> Optional[Dict]:
        """Parse a single general query log line"""
        
        match = self.general_query_regex.match(line)
        if not match:
            return None
        
        try:
            timestamp_str, thread_id, command_type, query = match.groups()
            
            # Parse timestamp (YYMMDD HH:MM:SS)
            timestamp = datetime.strptime(timestamp_str, '%y%m%d %H:%M:%S')
            
            # Clean query
            query = query.strip().rstrip(';')
            
            return {
                'timestamp': timestamp,
                'thread_id': int(thread_id),
                'command_type': command_type,
                'query': query[:500],  # Truncate
                'query_type': self._get_query_type(query),
                'is_suspicious': self._check_suspicious_query(query),
                'query_hash': self._hash_query(query)
            }
        except Exception as e:
            print(f"Error parsing general query: {e}")
            return None
    
    def detect_slow_query_attacks(self, df: pd.DataFrame, 
                                 query_time_threshold: float = 5.0,
                                 consecutive_threshold: int = 3) -> List[Dict]:
        """Detect potential slow query attacks"""
        
        if df.empty:
            return []
        
        # Find suspiciously slow queries
        slow_queries = df[df['query_time'] >= query_time_threshold].copy()
        
        if slow_queries.empty:
            return []
        
        findings = []
        
        # Group by user and query pattern
        slow_queries['query_pattern'] = slow_queries['query'].apply(self._normalize_query)
        
        for (user, pattern), group in slow_queries.groupby(['user', 'query_pattern']):
            if len(group) >= consecutive_threshold:
                # Check timing patterns
                group = group.sort_values('timestamp')
                time_diffs = group['timestamp'].diff().dt.total_seconds().dropna()
                
                findings.append({
                    'user': user,
                    'query_pattern': pattern[:200],
                    'occurrences': len(group),
                    'avg_query_time': group['query_time'].mean(),
                    'max_query_time': group['query_time'].max(),
                    'time_span_minutes': (group['timestamp'].max() - 
                                         group['timestamp'].min()).total_seconds() / 60,
                    'avg_time_between_queries': time_diffs.mean() if len(time_diffs) > 0 else 0,
                    'tables_affected': list(set([t for tables in group['tables'] 
                                               for t in tables if tables])),
                    'first_occurrence': group['timestamp'].min().isoformat(),
                    'last_occurrence': group['timestamp'].max().isoformat(),
                    'sample_queries': group['query'].head(3).tolist()
                })
        
        return findings
    
    def detect_sql_injection_patterns(self, df: pd.DataFrame) -> List[Dict]:
        """Detect SQL injection patterns in queries"""
        
        if df.empty:
            return []
        
        findings = []
        
        for _, row in df.iterrows():
            query = row.get('query', '')
            reasons = self._get_suspicious_reasons(query)
            
            if reasons:
                findings.append({
                    'timestamp': row.get('timestamp').isoformat() if pd.notnull(row.get('timestamp')) else None,
                    'user': row.get('user', 'unknown'),
                    'host': row.get('host', 'unknown'),
                    'query_type': row.get('query_type'),
                    'query_sample': query[:300],
                    'suspicious_reasons': reasons,
                    'query_time': row.get('query_time', 0),
                    'query_hash': row.get('query_hash'),
                    'tables': row.get('tables', [])
                })
        
        return findings
    
    def detect_data_exfiltration(self, df: pd.DataFrame,
                                large_result_threshold: int = 100000,
                                consecutive_selects: int = 10) -> List[Dict]:
        """Detect potential data exfiltration via SELECT queries"""
        
        if df.empty:
            return []
        
        # Focus on SELECT queries
        select_queries = df[df['query_type'] == 'SELECT'].copy()
        
        if select_queries.empty:
            return []
        
        findings = []
        current_user = None
        current_chain = []
        
        # Sort by user and timestamp
        select_queries = select_queries.sort_values(['user', 'timestamp'])
        
        for _, row in select_queries.iterrows():
            if not current_user:
                current_user = row['user']
                current_chain.append(row)
                continue
            
            if row['user'] == current_user:
                # Check if queries are within a short time window
                if current_chain and (row['timestamp'] - current_chain[-1]['timestamp']).total_seconds() < 300:
                    current_chain.append(row)
                else:
                    if len(current_chain) >= consecutive_selects:
                        findings.append(self._analyze_select_chain(current_chain))
                    current_chain = [row]
            else:
                if len(current_chain) >= consecutive_selects:
                    findings.append(self._analyze_select_chain(current_chain))
                current_user = row['user']
                current_chain = [row]
        
        # Check last chain
        if len(current_chain) >= consecutive_selects:
            findings.append(self._analyze_select_chain(current_chain))
        
        return findings
    
    def analyze_query_performance(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze query performance patterns"""
        
        if df.empty:
            return {}
        
        # Basic statistics
        total_queries = len(df)
        unique_users = df['user'].nunique()
        unique_tables = len(set([t for tables in df['tables'] for t in tables if tables]))
        
        # Query type distribution
        query_type_dist = df['query_type'].value_counts().to_dict()
        
        # Slowest queries
        slowest_queries = df.nlargest(10, 'query_time')[[
            'query', 'query_time', 'user', 'timestamp', 'tables'
        ]].to_dict('records')
        
        # Most frequent queries
        df['query_pattern'] = df['query'].apply(self._normalize_query)
        frequent_patterns = df['query_pattern'].value_counts().head(10).to_dict()
        
        # Time-based analysis
        hourly_dist = df.groupby(df['timestamp'].dt.hour).size().to_dict()
        
        # User activity
        active_users = df['user'].value_counts().head(10).to_dict()
        
        # Suspicious activity
        suspicious_count = df['is_suspicious'].sum()
        
        return {
            'total_queries': total_queries,
            'time_span_hours': (df['timestamp'].max() - 
                               df['timestamp'].min()).total_seconds() / 3600,
            'unique_users': unique_users,
            'unique_tables': unique_tables,
            'avg_query_time': df['query_time'].mean(),
            'max_query_time': df['query_time'].max(),
            'query_type_distribution': query_type_dist,
            'slowest_queries': slowest_queries,
            'most_frequent_patterns': frequent_patterns,
            'hourly_distribution': hourly_dist,
            'most_active_users': active_users,
            'suspicious_query_percentage': (suspicious_count / total_queries * 100 
                                          if total_queries > 0 else 0),
            'queries_per_hour': total_queries / max((df['timestamp'].max() - 
                                                   df['timestamp'].min()).total_seconds() / 3600, 1)
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
        """Read log file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return ""
    
    def _get_query_type(self, query: str) -> str:
        """Determine query type"""
        
        query_upper = query.upper().strip()
        
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
        elif query_upper.startswith('TRUNCATE'):
            return 'TRUNCATE'
        elif query_upper.startswith('EXPLAIN'):
            return 'EXPLAIN'
        elif query_upper.startswith('SHOW'):
            return 'SHOW'
        elif query_upper.startswith('DESCRIBE') or query_upper.startswith('DESC'):
            return 'DESCRIBE'
        else:
            return 'OTHER'
    
    def _extract_tables(self, query: str) -> List[str]:
        """Extract table names from query"""
        
        tables = []
        query_upper = query.upper()
        
        # Look for FROM, JOIN, INSERT INTO, UPDATE table patterns
        from_pattern = r'FROM\s+([\w\.]+)'
        join_pattern = r'JOIN\s+([\w\.]+)'
        insert_pattern = r'INSERT\s+INTO\s+([\w\.]+)'
        update_pattern = r'UPDATE\s+([\w\.]+)'
        delete_pattern = r'DELETE\s+FROM\s+([\w\.]+)'
        
        patterns = [
            (from_pattern, query_upper),
            (join_pattern, query_upper),
            (insert_pattern, query_upper),
            (update_pattern, query_upper),
            (delete_pattern, query_upper)
        ]
        
        for pattern, text in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Clean table name
                table = match.strip().split()[0]  # Take first word
                if '.' in table:
                    table = table.split('.')[-1]  # Remove database prefix
                if table and table not in tables:
                    tables.append(table)
        
        return tables
    
    def _check_suspicious_query(self, query: str) -> bool:
        """Check if query contains suspicious patterns"""
        
        query_lower = query.lower()
        
        for pattern in self.compiled_sqli_patterns:
            if pattern.search(query_lower):
                return True
        
        # Check for suspicious functions
        suspicious_functions = [
            'sleep', 'benchmark', 'waitfor', 'xp_cmdshell',
            'load_file', 'into outfile', 'into dumpfile'
        ]
        
        if any(func in query_lower for func in suspicious_functions):
            return True
        
        # Check for information schema access
        if 'information_schema' in query_lower:
            return True
        
        # Check for tautologies (1=1, 'a'='a')
        tautology_patterns = [r'1\s*=\s*1', r"'a'\s*=\s*'a'", r'"a"\s*=\s*"a"']
        for pattern in tautology_patterns:
            if re.search(pattern, query_lower):
                return True
        
        return False
    
    def _get_suspicious_reasons(self, query: str) -> List[str]:
        """Get specific reasons why a query is suspicious"""
        
        reasons = []
        query_lower = query.lower()
        
        # Check each pattern
        pattern_reasons = {
            'union.*select': 'UNION SELECT injection attempt',
            'select.*from.*where.*=': 'Potential tautology',
            'or.*1=1': 'OR 1=1 tautology',
            'and.*1=1': 'AND 1=1 tautology',
            'exec.*xp_cmdshell': 'XP_CMDSHELL command execution',
            'waitfor.*delay': 'Time-based delay',
            'benchmark\(': 'BENCHMARK function call',
            'sleep\(': 'SLEEP function call',
            '--': 'SQL comment',
            '\/\*.*\*\/': 'Multi-line comment',
            '@@version': 'Version disclosure',
            'load_file\(': 'FILE_READ function',
            'into.*outfile': 'File write attempt',
            'into.*dumpfile': 'File dump attempt',
            'information_schema': 'Information schema access'
        }
        
        for pattern, reason in pattern_reasons.items():
            if re.search(pattern, query_lower, re.IGNORECASE):
                reasons.append(reason)
        
        return reasons
    
    def _hash_query(self, query: str) -> str:
        """Create hash of normalized query for comparison"""
        
        normalized = self._normalize_query(query)
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query by removing variable data"""
        
        # Convert to lowercase
        normalized = query.lower()
        
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        # Remove string literals
        normalized = re.sub(r"'[^']*'", "'?'", normalized)
        normalized = re.sub(r'"[^"]*"', '"?"', normalized)
        normalized = re.sub(r'`[^`]*`', '`?`', normalized)
        
        # Remove numbers
        normalized = re.sub(r'\b\d+\b', '?', normalized)
        
        # Remove IN clauses
        normalized = re.sub(r'in\s*\([^)]+\)', 'in (?)', normalized)
        
        # Remove LIMIT clauses
        normalized = re.sub(r'limit\s+\d+(\s*,\s*\d+)?', 'limit ?', normalized)
        
        return normalized
    
    def _enhance_slow_query_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enhance slow query data with additional features"""
        
        if df.empty:
            return df
        
        # Add time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Add performance categories
        df['performance_category'] = pd.cut(
            df['query_time'],
            bins=[-1, 0.1, 1, 5, 10, 30, float('inf')],
            labels=['FAST', 'NORMAL', 'SLOW', 'VERY_SLOW', 'EXTREMELY_SLOW', 'CRITICAL']
        )
        
        # Add lock time categories
        df['lock_category'] = pd.cut(
            df['lock_time'],
            bins=[-1, 0.001, 0.01, 0.1, 1, float('inf')],
            labels=['NONE', 'MINIMAL', 'LOW', 'MEDIUM', 'HIGH']
        )
        
        # Add query complexity
        df['query_length'] = df['query'].apply(len)
        df['table_count'] = df['tables'].apply(len)
        
        return df
    
    def _enhance_general_query_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enhance general query data with additional features"""
        
        if df.empty:
            return df
        
        # Add time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Add suspicious flag for non-SELECT queries in general logs
        suspicious_types = ['DROP', 'TRUNCATE', 'ALTER', 'CREATE', 'DELETE']
        df['is_ddl_or_destructive'] = df['query_type'].isin(suspicious_types)
        
        return df
    
    def _analyze_select_chain(self, chain: List[pd.Series]) -> Dict[str, Any]:
        """Analyze a chain of SELECT queries"""
        
        df_chain = pd.DataFrame(chain)
        
        # Extract common patterns
        table_usage = {}
        for tables in df_chain['tables']:
            for table in tables:
                table_usage[table] = table_usage.get(table, 0) + 1
        
        # Calculate query patterns
        query_patterns = df_chain['query_pattern'].value_counts().to_dict()
        
        return {
            'user': df_chain['user'].iloc[0],
            'query_count': len(df_chain),
            'time_span_minutes': (df_chain['timestamp'].max() - 
                                 df_chain['timestamp'].min()).total_seconds() / 60,
            'avg_queries_per_minute': len(df_chain) / max((df_chain['timestamp'].max() - 
                                                         df_chain['timestamp'].min()).total_seconds() / 60, 1),
            'tables_accessed': list(table_usage.keys()),
            'table_usage_frequency': table_usage,
            'unique_query_patterns': len(query_patterns),
            'most_common_patterns': dict(list(query_patterns.items())[:3]),
            'start_time': df_chain['timestamp'].min().isoformat(),
            'end_time': df_chain['timestamp'].max().isoformat(),
            'suspicious_query_count': df_chain['is_suspicious'].sum(),
            'sample_queries': df_chain['query'].head(3).tolist()
        }
