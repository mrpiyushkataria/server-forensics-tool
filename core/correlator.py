"""
Log Correlation Engine
Correlates events across different log sources to identify attack chains
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import hashlib

class LogCorrelator:
    """Correlates events across Nginx, PHP, and MySQL logs"""
    
    def __init__(self, time_window_seconds: int = 5):
        self.time_window = timedelta(seconds=time_window_seconds)
    
    def correlate(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate findings across different log sources
        Returns enhanced findings with correlation metadata
        """
        
        correlated_findings = findings.copy()
        
        # Build timeline of events
        timeline = self._build_timeline(findings)
        correlated_findings['timeline'] = timeline
        
        # Correlate endpoints with errors
        endpoint_errors = self._correlate_endpoints_with_errors(findings)
        correlated_findings['endpoint_errors'] = endpoint_errors
        
        # Correlate IP activity across attack types
        ip_correlations = self._correlate_ip_activity(findings)
        correlated_findings['ip_correlations'] = ip_correlations
        
        # Correlate SQLi with slow queries
        sqli_correlations = self._correlate_sqli_with_mysql(findings)
        correlated_findings['sqli_correlations'] = sqli_correlations
        
        # Identify attack chains
        attack_chains = self._identify_attack_chains(findings)
        correlated_findings['attack_chains'] = attack_chains
        
        # Calculate correlation scores
        correlation_scores = self._calculate_correlation_scores(correlated_findings)
        correlated_findings['correlation_scores'] = correlation_scores
        
        return correlated_findings
    
    def _build_timeline(self, findings: Dict) -> List[Dict]:
        """Build unified timeline of events"""
        
        timeline = []
        
        # Add Nginx events
        if 'nginx' in findings.get('raw_logs', {}):
            nginx_logs = findings['raw_logs']['nginx']
            for _, row in nginx_logs.iterrows():
                timeline.append({
                    'timestamp': row['timestamp'],
                    'source': 'nginx',
                    'event_type': 'request',
                    'ip': row.get('ip'),
                    'endpoint': row.get('endpoint'),
                    'status': row.get('status'),
                    'data_sent': row.get('body_bytes_sent', 0)
                })
        
        # Add PHP error events
        if 'php_errors' in findings:
            for error in findings['php_errors']:
                timeline.append({
                    'timestamp': error.get('timestamp'),
                    'source': 'php',
                    'event_type': 'error',
                    'error_type': error.get('error_type'),
                    'message': error.get('message'),
                    'severity': self._get_php_error_severity(error.get('error_type'))
                })
        
        # Add MySQL slow query events
        if 'suspicious_queries' in findings:
            for query in findings['suspicious_queries']:
                timeline.append({
                    'timestamp': query.get('timestamp'),
                    'source': 'mysql',
                    'event_type': 'slow_query',
                    'query_time': query.get('query_time'),
                    'query_type': query.get('query_type'),
                    'query': query.get('query')[:100]  # Truncate
                })
        
        # Add SQL injection attempts
        if 'sqli_attempts' in findings:
            for attempt in findings['sqli_attempts']:
                timeline.append({
                    'timestamp': attempt.get('timestamp'),
                    'source': 'detection',
                    'event_type': 'sqli',
                    'ip': attempt.get('ip'),
                    'endpoint': attempt.get('endpoint'),
                    'pattern': attempt.get('pattern_found')
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _correlate_endpoints_with_errors(self, findings: Dict) -> Dict[str, List]:
        """Correlate endpoints with PHP errors"""
        
        correlations = defaultdict(list)
        
        if 'suspicious_endpoints' not in findings or 'php_errors' not in findings:
            return correlations
        
        # Create time windows for each endpoint
        endpoint_windows = {}
        for endpoint in findings['suspicious_endpoints']:
            # This would need endpoint timestamps - simplified for now
            endpoint_windows[endpoint['endpoint']] = {
                'start': None,  # Would be calculated from logs
                'end': None
            }
        
        # Simplified correlation - match by endpoint patterns
        for error in findings['php_errors']:
            error_msg = error.get('message', '').lower()
            
            for endpoint in findings['suspicious_endpoints']:
                endpoint_path = endpoint['endpoint'].lower()
                
                # Check if error message mentions endpoint or related terms
                if (endpoint_path in error_msg or 
                    self._endpoint_related_to_error(endpoint_path, error_msg)):
                    correlations[endpoint['endpoint']].append({
                        'error_type': error.get('error_type'),
                        'message': error.get('message')[:200],
                        'timestamp': error.get('timestamp'),
                        'severity': self._get_php_error_severity(error.get('error_type'))
                    })
        
        return dict(correlations)
    
    def _correlate_ip_activity(self, findings: Dict) -> Dict[str, Dict]:
        """Correlate IP activity across different attack types"""
        
        ip_profiles = defaultdict(lambda: {
            'endpoint_abuse': [],
            'data_dumps': [],
            'sqli_attempts': [],
            'scanner_activity': [],
            'brute_force': [],
            'total_score': 0
        })
        
        # Collect all activities by IP
        if 'malicious_ips' in findings:
            for ip_data in findings['malicious_ips']:
                ip = ip_data['ip']
                ip_profiles[ip]['endpoint_abuse'].append({
                    'endpoints': ip_data.get('accessed_endpoints_sample', []),
                    'request_count': ip_data.get('total_requests', 0),
                    'rate': ip_data.get('request_rate_per_sec', 0)
                })
        
        if 'data_dumps' in findings:
            for dump in findings['data_dumps']:
                ip = dump['ip']
                ip_profiles[ip]['data_dumps'].append({
                    'endpoint': dump.get('endpoint'),
                    'data_mb': dump.get('total_data_mb', 0),
                    'time_window': dump.get('time_window_minutes', 0)
                })
        
        if 'sqli_attempts' in findings:
            for attempt in findings['sqli_attempts']:
                ip = attempt['ip']
                ip_profiles[ip]['sqli_attempts'].append({
                    'endpoint': attempt.get('endpoint'),
                    'pattern': attempt.get('pattern_found'),
                    'timestamp': attempt.get('timestamp')
                })
        
        if 'scanner_activity' in findings:
            for scanner in findings['scanner_activity']:
                ip = scanner['ip']
                ip_profiles[ip]['scanner_activity'].append({
                    'scanner_type': scanner.get('scanner_type'),
                    'user_agent': scanner.get('user_agent'),
                    'timestamp': scanner.get('timestamp')
                })
        
        if 'brute_force' in findings:
            for bf in findings['brute_force']:
                ip = bf['ip']
                ip_profiles[ip]['brute_force'].append({
                    'time_window': bf.get('time_window'),
                    'attempt_count': bf.get('attempt_count'),
                    'endpoints': bf.get('endpoints', [])
                })
        
        # Calculate total threat score for each IP
        for ip, profile in ip_profiles.items():
            score = 0
            score += len(profile['endpoint_abuse']) * 10
            score += len(profile['data_dumps']) * 30
            score += len(profile['sqli_attempts']) * 50
            score += len(profile['scanner_activity']) * 40
            score += len(profile['brute_force']) * 20
            profile['total_score'] = min(score, 100)
        
        return dict(ip_profiles)
    
    def _correlate_sqli_with_mysql(self, findings: Dict) -> List[Dict]:
        """Correlate SQL injection attempts with MySQL slow queries"""
        
        correlations = []
        
        if 'sqli_attempts' not in findings or 'suspicious_queries' not in findings:
            return correlations
        
        # Simplified correlation - look for patterns
        for sqli in findings['sqli_attempts']:
            sqli_time = datetime.fromisoformat(sqli['timestamp'].replace('Z', '+00:00'))
            sqli_endpoint = sqli.get('endpoint', '')
            
            for query in findings['suspicious_queries']:
                query_time = query.get('timestamp')
                
                if not query_time:
                    continue
                
                # Check if times are close
                time_diff = abs((sqli_time - query_time).total_seconds())
                
                if time_diff < 10:  # 10-second window
                    query_text = query.get('query', '').lower()
                    sqli_pattern = sqli.get('pattern_found', '').lower()
                    
                    # Check if query pattern matches SQLi pattern
                    if self._patterns_match(sqli_pattern, query_text):
                        correlations.append({
                            'sqli_attempt': sqli,
                            'mysql_query': {
                                'query': query.get('query')[:200],
                                'query_time': query.get('query_time'),
                                'timestamp': query.get('timestamp')
                            },
                            'time_difference_seconds': time_diff,
                            'confidence': self._calculate_match_confidence(sqli_pattern, query_text)
                        })
        
        return correlations
    
    def _identify_attack_chains(self, findings: Dict) -> List[Dict]:
        """Identify potential attack chains"""
        
        attack_chains = []
        
        # Group activities by IP and time
        ip_activities = defaultdict(list)
        
        # Collect all timestamped activities
        all_activities = []
        
        # Add SQLi attempts
        if 'sqli_attempts' in findings:
            for sqli in findings['sqli_attempts']:
                all_activities.append({
                    'type': 'sqli',
                    'ip': sqli.get('ip'),
                    'timestamp': sqli.get('timestamp'),
                    'data': sqli
                })
        
        # Add scanner activity
        if 'scanner_activity' in findings:
            for scanner in findings['scanner_activity']:
                all_activities.append({
                    'type': 'scanner',
                    'ip': scanner.get('ip'),
                    'timestamp': scanner.get('timestamp'),
                    'data': scanner
                })
        
        # Add brute force
        if 'brute_force' in findings:
            for bf in findings['brute_force']:
                all_activities.append({
                    'type': 'brute_force',
                    'ip': bf.get('ip'),
                    'timestamp': bf.get('time_window'),
                    'data': bf
                })
        
        # Add data dumps
        if 'data_dumps' in findings:
            for dump in findings['data_dumps']:
                all_activities.append({
                    'type': 'data_dump',
                    'ip': dump.get('ip'),
                    'timestamp': dump.get('first_request'),
                    'data': dump
                })
        
        # Sort activities by timestamp and group by IP
        all_activities.sort(key=lambda x: x['timestamp'])
        
        for activity in all_activities:
            ip = activity['ip']
            ip_activities[ip].append(activity)
        
        # Identify chains for each IP
        for ip, activities in ip_activities.items():
            if len(activities) < 2:
                continue
            
            # Look for progression patterns
            chain = self._detect_attack_progression(activities)
            if chain:
                attack_chains.append({
                    'ip': ip,
                    'chain': chain,
                    'total_activities': len(activities),
                    'time_span': self._calculate_time_span(activities)
                })
        
        return attack_chains
    
    def _detect_attack_progression(self, activities: List) -> List:
        """Detect attack progression patterns"""
        
        if len(activities) < 2:
            return []
        
        # Common attack progression: reconnaissance → exploitation → data exfiltration
        progression = []
        
        # Sort by timestamp
        activities.sort(key=lambda x: x['timestamp'])
        
        # Check for common progression patterns
        for i in range(len(activities) - 1):
            current = activities[i]
            next_act = activities[i + 1]
            
            # Scanner followed by SQLi
            if (current['type'] == 'scanner' and 
                next_act['type'] == 'sqli'):
                progression.append({
                    'step': 'recon_to_exploit',
                    'from': current['type'],
                    'to': next_act['type'],
                    'time_diff': self._time_diff(current['timestamp'], next_act['timestamp'])
                })
            
            # SQLi followed by data dump
            elif (current['type'] == 'sqli' and 
                  next_act['type'] == 'data_dump'):
                progression.append({
                    'step': 'exploit_to_exfiltration',
                    'from': current['type'],
                    'to': next_act['type'],
                    'time_diff': self._time_diff(current['timestamp'], next_act['timestamp'])
                })
        
        return progression
    
    def _calculate_correlation_scores(self, correlated_findings: Dict) -> Dict[str, float]:
        """Calculate correlation confidence scores"""
        
        scores = {
            'endpoint_error_correlation': 0.0,
            'ip_threat_correlation': 0.0,
            'attack_chain_confidence': 0.0,
            'overall_correlation': 0.0
        }
        
        # Calculate endpoint-error correlation score
        if 'endpoint_errors' in correlated_findings:
            endpoint_count = len(correlated_findings.get('suspicious_endpoints', []))
            if endpoint_count > 0:
                correlated_endpoints = len(correlated_findings['endpoint_errors'])
                scores['endpoint_error_correlation'] = correlated_endpoints / endpoint_count
        
        # Calculate IP threat correlation
        if 'ip_correlations' in correlated_findings:
            total_ips = len(correlated_findings['ip_correlations'])
            high_threat_ips = sum(
                1 for ip, profile in correlated_findings['ip_correlations'].items()
                if profile['total_score'] > 50
            )
            if total_ips > 0:
                scores['ip_threat_correlation'] = high_threat_ips / total_ips
        
        # Calculate attack chain confidence
        if 'attack_chains' in correlated_findings:
            chain_count = len(correlated_findings['attack_chains'])
            if chain_count > 0:
                avg_chain_length = np.mean([
                    len(chain['chain']) for chain in correlated_findings['attack_chains']
                ])
                scores['attack_chain_confidence'] = min(avg_chain_length / 5, 1.0)
        
        # Overall correlation score
        scores['overall_correlation'] = np.mean([
            scores['endpoint_error_correlation'],
            scores['ip_threat_correlation'],
            scores['attack_chain_confidence']
        ])
        
        return scores
    
    # Helper methods
    def _get_php_error_severity(self, error_type: str) -> str:
        """Map PHP error type to severity"""
        severity_map = {
            'Fatal error': 'CRITICAL',
            'Error': 'HIGH',
            'Warning': 'MEDIUM',
            'Notice': 'LOW',
            'Deprecated': 'INFO'
        }
        return severity_map.get(error_type, 'INFO')
    
    def _endpoint_related_to_error(self, endpoint: str, error_msg: str) -> bool:
        """Check if endpoint is related to error message"""
        # Extract filename from endpoint or check common patterns
        endpoint_parts = endpoint.split('/')
        filename = endpoint_parts[-1] if endpoint_parts else ''
        
        return (filename in error_msg or 
                any(part in error_msg for part in endpoint_parts if len(part) > 3))
    
    def _patterns_match(self, pattern1: str, pattern2: str) -> bool:
        """Check if two patterns are similar"""
        pattern1 = pattern1.lower()
        pattern2 = pattern2.lower()
        
        # Check for common SQL keywords
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop']
        matches = sum(1 for kw in sql_keywords if kw in pattern1 and kw in pattern2)
        
        return matches >= 2  # At least 2 common keywords
    
    def _calculate_match_confidence(self, pattern1: str, pattern2: str) -> float:
        """Calculate confidence score for pattern match"""
        pattern1 = set(pattern1.lower().split())
        pattern2 = set(pattern2.lower().split())
        
        if not pattern1 or not pattern2:
            return 0.0
        
        intersection = pattern1.intersection(pattern2)
        union = pattern1.union(pattern2)
        
        return len(intersection) / len(union)
    
    def _time_diff(self, time1: str, time2: str) -> float:
        """Calculate time difference in minutes"""
        try:
            t1 = datetime.fromisoformat(time1.replace('Z', '+00:00'))
            t2 = datetime.fromisoformat(time2.replace('Z', '+00:00'))
            return abs((t2 - t1).total_seconds() / 60)
        except:
            return 0.0
    
    def _calculate_time_span(self, activities: List) -> float:
        """Calculate total time span of activities in minutes"""
        if len(activities) < 2:
            return 0.0
        
        timestamps = []
        for act in activities:
            try:
                ts = datetime.fromisoformat(act['timestamp'].replace('Z', '+00:00'))
                timestamps.append(ts)
            except:
                pass
        
        if len(timestamps) < 2:
            return 0.0
        
        return (max(timestamps) - min(timestamps)).total_seconds() / 60
