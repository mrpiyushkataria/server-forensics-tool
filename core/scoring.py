"""
Risk Scoring Engine
Calculates comprehensive risk scores based on multiple factors
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class RiskFactors:
    """Individual risk factors contributing to overall score"""
    request_volume: float = 0.0
    data_exposure: float = 0.0
    request_rate: float = 0.0
    error_rate: float = 0.0
    sql_injection: float = 0.0
    scanner_activity: float = 0.0
    brute_force: float = 0.0
    endpoint_sensitivity: float = 0.0
    time_pattern: float = 0.0
    ip_reputation: float = 0.0

class RiskScorer:
    """Calculates risk scores for endpoints, IPs, and activities"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.weights = self._load_weights()
    
    def _load_weights(self) -> Dict[str, float]:
        """Load weight configuration for risk factors"""
        
        default_weights = {
            'request_volume': 0.15,
            'data_exposure': 0.20,
            'request_rate': 0.10,
            'error_rate': 0.05,
            'sql_injection': 0.25,
            'scanner_activity': 0.15,
            'brute_force': 0.10,
            'endpoint_sensitivity': 0.20,
            'time_pattern': 0.05,
            'ip_reputation': 0.10
        }
        
        # Override with config if provided
        if 'scoring_weights' in self.config:
            default_weights.update(self.config['scoring_weights'])
        
        return default_weights
    
    def score_endpoint(self, endpoint_data: Dict) -> Dict[str, Any]:
        """Calculate comprehensive risk score for an endpoint"""
        
        factors = self._calculate_endpoint_factors(endpoint_data)
        overall_score = self._calculate_overall_score(factors)
        risk_level = self._score_to_risk_level(overall_score)
        
        return {
            'endpoint': endpoint_data.get('endpoint'),
            'risk_score': overall_score,
            'risk_level': risk_level.value,
            'risk_factors': factors.__dict__,
            'contributing_factors': self._get_top_factors(factors, 3),
            'confidence': self._calculate_confidence(factors)
        }
    
    def score_ip_address(self, ip_data: Dict) -> Dict[str, Any]:
        """Calculate comprehensive risk score for an IP address"""
        
        factors = self._calculate_ip_factors(ip_data)
        overall_score = self._calculate_overall_score(factors)
        risk_level = self._score_to_risk_level(overall_score)
        
        return {
            'ip': ip_data.get('ip'),
            'risk_score': overall_score,
            'risk_level': risk_level.value,
            'risk_factors': factors.__dict__,
            'threat_profile': self._build_ip_threat_profile(ip_data),
            'recommended_action': self._get_recommended_action(overall_score)
        }
    
    def score_data_dump(self, dump_data: Dict) -> Dict[str, Any]:
        """Calculate risk score for data dump activity"""
        
        factors = RiskFactors()
        
        # Data exposure factor
        data_mb = dump_data.get('total_data_mb', 0)
        if data_mb > 1000:
            factors.data_exposure = 1.0
        elif data_mb > 100:
            factors.data_exposure = 0.8
        elif data_mb > 10:
            factors.data_exposure = 0.5
        elif data_mb > 1:
            factors.data_exposure = 0.3
        
        # Request rate factor
        request_count = dump_data.get('request_count', 0)
        time_window = dump_data.get('time_window_minutes', 1)
        rate_per_min = request_count / max(time_window, 1)
        
        if rate_per_min > 100:
            factors.request_rate = 1.0
        elif rate_per_min > 10:
            factors.request_rate = 0.7
        elif rate_per_min > 1:
            factors.request_rate = 0.4
        
        # Endpoint sensitivity
        endpoint = dump_data.get('endpoint', '')
        factors.endpoint_sensitivity = self._score_endpoint_sensitivity(endpoint)
        
        overall_score = self._calculate_overall_score(factors)
        risk_level = self._score_to_risk_level(overall_score)
        
        return {
            'ip': dump_data.get('ip'),
            'endpoint': endpoint,
            'risk_score': overall_score,
            'risk_level': risk_level.value,
            'data_exposed_mb': data_mb,
            'exposure_rate_mb_per_min': data_mb / max(time_window, 1)
        }
    
    def _calculate_endpoint_factors(self, endpoint_data: Dict) -> RiskFactors:
        """Calculate risk factors for an endpoint"""
        
        factors = RiskFactors()
        
        # Request volume factor
        total_requests = endpoint_data.get('total_requests', 0)
        if total_requests > 10000:
            factors.request_volume = 1.0
        elif total_requests > 1000:
            factors.request_volume = 0.8
        elif total_requests > 100:
            factors.request_volume = 0.5
        elif total_requests > 10:
            factors.request_volume = 0.2
        
        # Data exposure factor
        data_mb = endpoint_data.get('total_data_mb', 0)
        if data_mb > 1000:
            factors.data_exposure = 1.0
        elif data_mb > 100:
            factors.data_exposure = 0.8
        elif data_mb > 10:
            factors.data_exposure = 0.5
        elif data_mb > 1:
            factors.data_exposure = 0.3
        
        # Request rate factor
        reqs_per_min = endpoint_data.get('requests_per_minute', 0)
        if reqs_per_min > 1000:
            factors.request_rate = 1.0
        elif reqs_per_min > 100:
            factors.request_rate = 0.8
        elif reqs_per_min > 10:
            factors.request_rate = 0.5
        elif reqs_per_min > 1:
            factors.request_rate = 0.2
        
        # Error rate factor
        status_codes = endpoint_data.get('status_codes', {})
        error_codes = sum(v for k, v in status_codes.items() 
                         if str(k).startswith('4') or str(k).startswith('5'))
        total = sum(status_codes.values())
        
        if total > 0:
            error_rate = error_codes / total
            if error_rate > 0.5:
                factors.error_rate = 1.0
            elif error_rate > 0.2:
                factors.error_rate = 0.7
            elif error_rate > 0.05:
                factors.error_rate = 0.3
        
        # Endpoint sensitivity
        endpoint = endpoint_data.get('endpoint', '')
        factors.endpoint_sensitivity = self._score_endpoint_sensitivity(endpoint)
        
        return factors
    
    def _calculate_ip_factors(self, ip_data: Dict) -> RiskFactors:
        """Calculate risk factors for an IP address"""
        
        factors = RiskFactors()
        
        # Request rate factor
        reqs_per_sec = ip_data.get('request_rate_per_sec', 0)
        if reqs_per_sec > 100:
            factors.request_rate = 1.0
        elif reqs_per_sec > 10:
            factors.request_rate = 0.8
        elif reqs_per_sec > 1:
            factors.request_rate = 0.5
        elif reqs_per_sec > 0.1:
            factors.request_rate = 0.2
        
        # Error rate factor (404s)
        not_found = ip_data.get('not_found_requests', 0)
        total_requests = ip_data.get('total_requests', 1)
        
        if total_requests > 0:
            not_found_rate = not_found / total_requests
            if not_found_rate > 0.8:
                factors.error_rate = 1.0
            elif not_found_rate > 0.5:
                factors.error_rate = 0.8
            elif not_found_rate > 0.2:
                factors.error_rate = 0.5
            elif not_found_rate > 0.05:
                factors.error_rate = 0.2
        
        # Unique endpoints factor (reconnaissance indicator)
        unique_endpoints = ip_data.get('unique_endpoints', 0)
        if unique_endpoints > 100:
            factors.scanner_activity = 1.0
        elif unique_endpoints > 50:
            factors.scanner_activity = 0.8
        elif unique_endpoints > 20:
            factors.scanner_activity = 0.5
        elif unique_endpoints > 10:
            factors.scanner_activity = 0.2
        
        return factors
    
    def _score_endpoint_sensitivity(self, endpoint: str) -> float:
        """Score endpoint sensitivity based on path patterns"""
        
        sensitive_patterns = {
            # Admin endpoints
            '/admin': 1.0,
            '/wp-admin': 1.0,
            '/administrator': 1.0,
            '/backend': 0.9,
            '/manage': 0.8,
            
            # Authentication endpoints
            '/login': 0.9,
            '/auth': 0.9,
            '/oauth': 0.9,
            '/token': 1.0,
            '/session': 0.8,
            
            # API endpoints with data
            '/api/users': 1.0,
            '/api/customers': 1.0,
            '/api/orders': 1.0,
            '/api/payments': 1.0,
            '/api/database': 1.0,
            
            # Configuration endpoints
            '/config': 1.0,
            '/settings': 0.8,
            '/env': 1.0,
            '/.env': 1.0,
            
            # Database endpoints
            '/phpmyadmin': 1.0,
            '/mysql': 1.0,
            '/db': 0.9,
            '/database': 1.0,
            
            # File access
            '/uploads': 0.7,
            '/files': 0.7,
            '/download': 0.6,
            '/export': 0.8,
            
            # Internal endpoints
            '/internal': 0.9,
            '/private': 0.9,
            '/secure': 0.8
        }
        
        endpoint_lower = endpoint.lower()
        
        # Check for exact matches and partial matches
        max_score = 0.0
        for pattern, score in sensitive_patterns.items():
            if pattern in endpoint_lower:
                max_score = max(max_score, score)
        
        # Check for parameter patterns
        if '?' in endpoint_lower:
            params = endpoint_lower.split('?')[1]
            sensitive_params = ['password', 'token', 'key', 'secret', 'auth']
            if any(param in params for param in sensitive_params):
                max_score = max(max_score, 0.9)
        
        return max_score
    
    def _calculate_overall_score(self, factors: RiskFactors) -> float:
        """Calculate overall risk score from factors"""
        
        score = 0.0
        
        # Apply weights to each factor
        for factor_name, factor_value in factors.__dict__.items():
            weight = self.weights.get(factor_name, 0.0)
            score += factor_value * weight
        
        # Cap at 100
        return min(score * 100, 100)
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numerical score to risk level"""
        
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _get_top_factors(self, factors: RiskFactors, top_n: int = 3) -> List[Tuple[str, float]]:
        """Get top contributing factors"""
        
        factor_dict = factors.__dict__
        sorted_factors = sorted(
            factor_dict.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_factors[:top_n]
    
    def _calculate_confidence(self, factors: RiskFactors) -> float:
        """Calculate confidence in the risk assessment"""
        
        # Confidence increases with more significant factors
        significant_factors = sum(1 for v in factors.__dict__.values() if v > 0.3)
        total_factors = len(factors.__dict__)
        
        if total_factors == 0:
            return 0.0
        
        base_confidence = significant_factors / total_factors
        
        # Increase confidence if multiple factors are high
        high_factors = sum(1 for v in factors.__dict__.values() if v > 0.7)
        if high_factors >= 2:
            base_confidence = min(base_confidence + 0.2, 1.0)
        
        return base_confidence
    
    def _build_ip_threat_profile(self, ip_data: Dict) -> Dict[str, Any]:
        """Build comprehensive threat profile for an IP"""
        
        profile = {
            'request_patterns': {
                'total_requests': ip_data.get('total_requests', 0),
                'request_rate_per_sec': ip_data.get('request_rate_per_sec', 0),
                'unique_endpoints': ip_data.get('unique_endpoints', 0)
            },
            'error_patterns': {
                'not_found_requests': ip_data.get('not_found_requests', 0),
                'error_rate': ip_data.get('not_found_requests', 0) / 
                             max(ip_data.get('total_requests', 1), 1)
            },
            'data_patterns': {
                'total_data_mb': ip_data.get('total_data_mb', 0),
                'data_intensity': ip_data.get('total_data_mb', 0) / 
                                 max(ip_data.get('total_requests', 1), 1)
            }
        }
        
        # Determine threat type
        threat_types = []
        
        if ip_data.get('request_rate_per_sec', 0) > 10:
            threat_types.append('HIGH_VOLUME_ATTACK')
        
        if ip_data.get('not_found_requests', 0) > 100:
            threat_types.append('RECONNAISSANCE')
        
        if ip_data.get('unique_endpoints', 0) > 50:
            threat_types.append('SCANNING')
        
        profile['threat_types'] = threat_types
        profile['primary_threat'] = threat_types[0] if threat_types else 'UNKNOWN'
        
        return profile
    
    def _get_recommended_action(self, score: float) -> str:
        """Get recommended action based on risk score"""
        
        if score >= 80:
            return "IMMEDIATE_BLOCK_AND_INVESTIGATE"
        elif score >= 60:
            return "BLOCK_AND_ALERT_SECURITY_TEAM"
        elif score >= 40:
            return "RATE_LIMIT_AND_MONITOR"
        elif score >= 20:
            return "MONITOR_CLOSELY"
        else:
            return "CONTINUE_MONITORING"
    
    def aggregate_scores(self, scores: List[Dict]) -> Dict[str, Any]:
        """Aggregate multiple risk scores"""
        
        if not scores:
            return {
                'average_score': 0,
                'max_score': 0,
                'risk_distribution': {},
                'recommendation': 'NO_ACTION_NEEDED'
            }
        
        risk_scores = [s.get('risk_score', 0) for s in scores]
        risk_levels = [s.get('risk_level', 'INFO') for s in scores]
        
        # Calculate distribution
        distribution = {}
        for level in RiskLevel:
            distribution[level.value] = risk_levels.count(level.value)
        
        avg_score = np.mean(risk_scores)
        max_score = max(risk_scores)
        
        # Determine overall recommendation
        if max_score >= 80 or avg_score >= 60:
            overall_rec = 'IMMEDIATE_INVESTIGATION_REQUIRED'
        elif max_score >= 60 or avg_score >= 40:
            overall_rec = 'PRIORITY_INVESTIGATION'
        elif max_score >= 40 or avg_score >= 20:
            overall_rec = 'SCHEDULED_REVIEW'
        else:
            overall_rec = 'ROUTINE_MONITORING'
        
        return {
            'average_score': avg_score,
            'max_score': max_score,
            'median_score': np.median(risk_scores),
            'std_deviation': np.std(risk_scores),
            'risk_distribution': distribution,
            'critical_count': distribution.get('CRITICAL', 0),
            'high_count': distribution.get('HIGH', 0),
            'overall_recommendation': overall_rec
        }
