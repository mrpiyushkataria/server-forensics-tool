import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class DatabaseManager:
    """SQLite database manager for storing analysis results"""
    
    def __init__(self, db_path: str = ':memory:'):
        self.db_path = db_path
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize database with required tables"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT NOT NULL,
            total_requests INTEGER,
            unique_ips INTEGER,
            total_data_bytes INTEGER,
            avg_response_size REAL,
            request_rate REAL,
            risk_score INTEGER,
            risk_level TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            total_requests INTEGER,
            request_rate REAL,
            unique_endpoints INTEGER,
            not_found_count INTEGER,
            total_data_bytes INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS data_dumps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            endpoint TEXT,
            total_data_bytes INTEGER,
            request_count INTEGER,
            avg_response_size REAL,
            data_rate REAL,
            time_window_minutes REAL,
            first_request TIMESTAMP,
            last_request TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sql_injections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            ip TEXT,
            endpoint TEXT,
            pattern_found TEXT,
            request_sample TEXT,
            status_code INTEGER,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            log_directory TEXT,
            time_range TEXT,
            total_findings INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        self.conn.commit()
    
    def store_findings(self, findings: Dict[str, Any], session_id: str = None):
        """Store analysis findings in database"""
        
        if session_id is None:
            session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Store suspicious endpoints
        if 'suspicious_endpoints' in findings:
            for endpoint in findings['suspicious_endpoints']:
                self._store_endpoint(endpoint)
        
        # Store malicious IPs
        if 'malicious_ips' in findings:
            for ip in findings['malicious_ips']:
                self._store_malicious_ip(ip)
        
        # Store data dumps
        if 'data_dumps' in findings:
            for dump in findings['data_dumps']:
                self._store_data_dump(dump)
        
        # Store SQL injections
        if 'sqli_attempts' in findings:
            for attempt in findings['sqli_attempts']:
                self._store_sql_injection(attempt)
        
        # Record analysis session
        total_findings = (
            len(findings.get('suspicious_endpoints', [])) +
            len(findings.get('malicious_ips', [])) +
            len(findings.get('data_dumps', [])) +
            len(findings.get('sqli_attempts', []))
        )
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO analysis_sessions (session_id, total_findings)
        VALUES (?, ?)
        ''', (session_id, total_findings))
        
        self.conn.commit()
    
    def _store_endpoint(self, endpoint: Dict):
        """Store suspicious endpoint"""
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO suspicious_endpoints 
        (endpoint, total_requests, unique_ips, total_data_bytes, 
         avg_response_size, request_rate, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            endpoint.get('endpoint'),
            endpoint.get('total_requests'),
            endpoint.get('unique_ips'),
            int(endpoint.get('total_data_mb', 0) * 1024 * 1024),
            endpoint.get('average_response_size', 0),
            endpoint.get('requests_per_minute', 0),
            endpoint.get('risk_score', 0),
            endpoint.get('risk_level', 'INFO')
        ))
    
    def _store_malicious_ip(self, ip_data: Dict):
        """Store malicious IP"""
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO malicious_ips 
        (ip, total_requests, request_rate, unique_endpoints, 
         not_found_count, total_data_bytes, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip_data.get('ip'),
            ip_data.get('total_requests'),
            ip_data.get('request_rate_per_sec', 0),
            ip_data.get('unique_endpoints', 0),
            ip_data.get('not_found_requests', 0),
            int(ip_data.get('total_data_mb', 0) * 1024 * 1024),
            ip_data.get('risk_score', 0),
            ip_data.get('risk_level', 'INFO')
        ))
    
    def _store_data_dump(self, dump: Dict):
        """Store data dump finding"""
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO data_dumps 
        (ip, endpoint, total_data_bytes, request_count, 
         avg_response_size, data_rate, time_window_minutes, 
         first_request, last_request)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            dump.get('ip'),
            dump.get('endpoint'),
            int(dump.get('total_data_mb', 0) * 1024 * 1024),
            dump.get('request_count', 0),
            dump.get('average_size_mb', 0) * 1024 * 1024,
            dump.get('data_rate_mbps', 0),
            dump.get('time_window_minutes', 0),
            dump.get('first_request'),
            dump.get('last_request')
        ))
    
    def _store_sql_injection(self, attempt: Dict):
        """Store SQL injection attempt"""
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO sql_injections 
        (timestamp, ip, endpoint, pattern_found, 
         request_sample, status_code, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            attempt.get('timestamp'),
            attempt.get('ip'),
            attempt.get('endpoint'),
            attempt.get('pattern_found'),
            attempt.get('request', '')[:500],
            attempt.get('status_code'),
            attempt.get('user_agent', '')[:200]
        ))
    
    def get_recent_findings(self, limit: int = 100) -> Dict[str, pd.DataFrame]:
        """Get recent findings from database"""
        
        findings = {}
        
        # Get suspicious endpoints
        endpoints_df = pd.read_sql_query(
            'SELECT * FROM suspicious_endpoints ORDER BY risk_score DESC LIMIT ?',
            self.conn, params=(limit,)
        )
        findings['suspicious_endpoints'] = endpoints_df
        
        # Get malicious IPs
        ips_df = pd.read_sql_query(
            'SELECT * FROM malicious_ips ORDER BY risk_score DESC LIMIT ?',
            self.conn, params=(limit,)
        )
        findings['malicious_ips'] = ips_df
        
        return findings
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
