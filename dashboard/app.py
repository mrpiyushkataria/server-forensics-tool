"""
Web Dashboard for Server Log Forensics Tool
"""

from flask import Flask, render_template, jsonify, send_file, request
from flask_socketio import SocketIO
import pandas as pd
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.log_parsers import LogCollector
from core.detectors import AbuseDetector
from core.correlator import LogCorrelator
from output.reporter import ReportGenerator
from output.visualizer import ForensicVisualizer
from storage.sqlite_manager import DatabaseManager

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app)

# Global variables for analysis results
analysis_results = {}
recent_analyses = []

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    """API endpoint to analyze logs"""
    try:
        data = request.json
        log_dir = data.get('log_dir', '/var/log')
        time_range = data.get('time_range', '24h')
        
        # Run analysis
        collector = LogCollector(log_dir, time_range)
        logs = collector.collect_all()
        
        detector = AbuseDetector()
        findings = detector.analyze(logs)
        
        correlator = LogCorrelator()
        correlated = correlator.correlate(findings)
        
        # Store results
        analysis_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        analysis_results[analysis_id] = correlated
        
        # Add to recent analyses
        recent_analyses.append({
            'id': analysis_id,
            'timestamp': datetime.now().isoformat(),
            'log_dir': log_dir,
            'findings_count': len(correlated.get('suspicious_endpoints', []))
        })
        
        # Keep only last 10 analyses
        if len(recent_analyses) > 10:
            recent_analyses.pop(0)
        
        # Generate visualizations
        visualizer = ForensicVisualizer()
        dashboard = visualizer.create_dashboard(correlated)
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'summary': _create_summary(correlated),
            'dashboard': dashboard,
            'findings': correlated
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/recent-analyses')
def get_recent_analyses():
    """Get list of recent analyses"""
    return jsonify({'analyses': recent_analyses})

@app.route('/api/analysis/<analysis_id>')
def get_analysis(analysis_id):
    """Get specific analysis results"""
    if analysis_id in analysis_results:
        visualizer = ForensicVisualizer()
        dashboard = visualizer.create_dashboard(analysis_results[analysis_id])
        
        return jsonify({
            'success': True,
            'analysis': analysis_results[analysis_id],
            'dashboard': dashboard,
            'summary': _create_summary(analysis_results[analysis_id])
        })
    return jsonify({'success': False, 'error': 'Analysis not found'})

@app.route('/api/live-monitor')
def live_monitor():
    """Stream live analysis updates"""
    # This would connect to live log monitoring
    return jsonify({'status': 'Live monitoring endpoint'})

@app.route('/api/export/<analysis_id>/<format>')
def export_analysis(analysis_id, format):
    """Export analysis in specified format"""
    if analysis_id not in analysis_results:
        return jsonify({'success': False, 'error': 'Analysis not found'})
    
    try:
        from output.exporters import DataExporter
        
        exporter = DataExporter('./exports')
        filename = f'analysis_{analysis_id}.{format}'
        
        if format == 'json':
            filepath = exporter.export_json(analysis_results[analysis_id], filename)
        elif format == 'csv':
            filepath = exporter.export_csv(analysis_results[analysis_id], f'analysis_{analysis_id}')
            return jsonify({'success': True, 'files': filepath})
        elif format == 'html':
            visualizer = ForensicVisualizer()
            html = visualizer.create_interactive_report(analysis_results[analysis_id])
            filepath = f'./exports/analysis_{analysis_id}.html'
            Path(filepath).parent.mkdir(exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
        else:
            return jsonify({'success': False, 'error': f'Unsupported format: {format}'})
        
        return send_file(filepath, as_attachment=True)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/endpoint/<endpoint_path>')
def analyze_endpoint(endpoint_path):
    """Analyze specific endpoint"""
    # This would query the database for endpoint-specific analysis
    return jsonify({'endpoint': endpoint_path, 'analysis': 'Endpoint analysis would go here'})

@app.route('/api/ip/<ip_address>')
def analyze_ip(ip_address):
    """Analyze specific IP address"""
    # This would query the database for IP-specific analysis
    return jsonify({'ip': ip_address, 'analysis': 'IP analysis would go here'})

def _create_summary(findings):
    """Create summary statistics"""
    total_endpoints = len(findings.get('suspicious_endpoints', []))
    total_ips = len(findings.get('malicious_ips', []))
    
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for endpoint in findings.get('suspicious_endpoints', []):
        risk = endpoint.get('risk_level', 'INFO')
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    total_data = sum(ep.get('total_data_mb', 0) for ep in findings.get('suspicious_endpoints', []))
    
    return {
        'total_findings': total_endpoints + total_ips,
        'suspicious_endpoints': total_endpoints,
        'malicious_ips': total_ips,
        'risk_distribution': risk_counts,
        'total_data_exposure_gb': total_data / 1024,
        'critical_count': risk_counts['CRITICAL']
    }

# Real-time updates via WebSocket
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('status', {'message': 'Connected to forensic dashboard'})

@socketio.on('request_update')
def handle_update_request(data):
    """Handle real-time update requests"""
    analysis_id = data.get('analysis_id')
    if analysis_id in analysis_results:
        socketio.emit('analysis_update', {
            'analysis_id': analysis_id,
            'timestamp': datetime.now().isoformat(),
            'data': _create_summary(analysis_results[analysis_id])
        })

if __name__ == '__main__':
    # Create necessary directories
    Path('./exports').mkdir(exist_ok=True)
    Path('./static').mkdir(exist_ok=True)
    Path('./templates').mkdir(exist_ok=True)
    
    print("🚀 Starting Forensic Dashboard...")
    print("📊 Dashboard URL: http://localhost:5000")
    print("🔍 API Base URL: http://localhost:5000/api")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
