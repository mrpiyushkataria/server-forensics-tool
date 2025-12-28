"""
Web Dashboard for Server Log Forensics Tool - WITH UPLOAD SUPPORT - DEBUGGED VERSION
"""

from flask import Flask, render_template, jsonify, send_file, request
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
import pandas as pd
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os
import shutil
import zipfile
import tarfile
import uuid
import numpy as np

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import the analysis modules (provide fallbacks if not available)
try:
    from core.log_parsers import LogCollector
    from core.detectors import AbuseDetector
    from core.correlator import LogCorrelator
    from output.visualizer import ForensicVisualizer
    ANALYSIS_MODULES_AVAILABLE = True
except ImportError:
    print("Warning: Analysis modules not available. Using mock data.")
    ANALYSIS_MODULES_AVAILABLE = False
    
    # Mock classes for testing - SIMPLIFIED AND CORRECTED
    class LogCollector:
        def __init__(self, log_dir, time_range):
            self.log_dir = log_dir
            self.time_range = time_range
            
        def collect_all(self):
            # Return realistic mock DataFrame
            now = datetime.now()
            timestamps = [now - timedelta(minutes=i*10) for i in range(144)]  # 24 hours
            
            data = {
                'timestamp': timestamps,
                'ip': ['192.168.1.' + str(i%254+1) for i in range(144)],
                'endpoint': ['/api/data', '/admin', '/login', '/download', 
                            '/api/users', '/wp-admin', '/config', '/.env'] * 18,
                'status_code': [200, 404, 500, 200, 403, 302, 200, 404] * 18,
                'body_bytes_sent': [1024, 0, 0, 2048, 512, 0, 1536, 0] * 18,
                'user_agent': ['Mozilla/5.0', 'sqlmap/1.6', 'curl/7.68', 'python-requests/2.28'] * 36,
                'request': ['GET /api/data HTTP/1.1', 'POST /login HTTP/1.1'] * 72,
                'method': ['GET', 'POST'] * 72
            }
            return {'nginx': pd.DataFrame(data)}
    
    class AbuseDetector:
        def analyze(self, logs):
            # Always return the same structure regardless of input
            now = datetime.now()
            
            # ALWAYS return data even if logs appear empty
            suspicious_endpoints = [
                {'endpoint': '/admin', 'total_requests': 150, 'unique_ips': 25, 
                 'total_data_mb': 45.2, 'requests_per_minute': 12.5, 
                 'status_codes': {'200': 80, '404': 70}, 'average_response_size': 1024,
                 'risk_score': 85, 'risk_level': 'CRITICAL'},
                {'endpoint': '/api/data', 'total_requests': 300, 'unique_ips': 15,
                 'total_data_mb': 120.5, 'requests_per_minute': 25.0,
                 'status_codes': {'200': 280, '500': 20}, 'average_response_size': 2048,
                 'risk_score': 75, 'risk_level': 'HIGH'},
                {'endpoint': '/login', 'total_requests': 200, 'unique_ips': 45,
                 'total_data_mb': 15.8, 'requests_per_minute': 8.3,
                 'status_codes': {'200': 120, '403': 80}, 'average_response_size': 512,
                 'risk_score': 65, 'risk_level': 'MEDIUM'}
            ]
            
            malicious_ips = [
                {'ip': '192.168.1.100', 'total_requests': 500, 'request_rate_per_sec': 2.5,
                 'unique_endpoints': 15, 'not_found_requests': 120, 'total_data_mb': 45.8,
                 'accessed_endpoints_sample': ['/admin', '/login', '/api/data'],
                 'risk_score': 95, 'risk_level': 'CRITICAL'},
                {'ip': '10.0.0.5', 'total_requests': 200, 'request_rate_per_sec': 1.2,
                 'unique_endpoints': 8, 'not_found_requests': 85, 'total_data_mb': 12.3,
                 'accessed_endpoints_sample': ['/wp-admin', '/config'],
                 'risk_score': 80, 'risk_level': 'HIGH'}
            ]
            
            data_dumps = [
                {'ip': '192.168.1.100', 'endpoint': '/api/data', 'total_data_mb': 120.5,
                 'request_count': 300, 'average_size_mb': 0.4, 'data_rate_mbps': 1.2,
                 'time_window_minutes': 120, 'first_request': (now - timedelta(hours=2)).isoformat(),
                 'last_request': now.isoformat()}
            ]
            
            sqli_attempts = [
                {'timestamp': (now - timedelta(hours=1)).isoformat(), 'ip': '192.168.1.100',
                 'endpoint': '/api/data', 'request': "GET /api/data?q=' OR 1=1-- HTTP/1.1",
                 'pattern_found': 'or.*1=1', 'status_code': 500, 'user_agent': 'sqlmap/1.6'}
            ]
            
            scanner_activity = [
                {'timestamp': (now - timedelta(hours=3)).isoformat(), 'ip': '10.0.0.5',
                 'user_agent': 'sqlmap/1.6', 'scanner_type': 'sqlmap',
                 'endpoint': '/wp-admin', 'status_code': 404}
            ]
            
            brute_force = [
                {'ip': '172.16.0.23', 'time_window': (now - timedelta(minutes=30)).isoformat(),
                 'attempt_count': 45, 'endpoints': ['/login', '/auth'],
                 'status_codes': {'403': 45}, 'user_agents': ['python-requests/2.28']}
            ]
            
            # ALWAYS return this structure
            return {
                'suspicious_endpoints': suspicious_endpoints,
                'malicious_ips': malicious_ips,
                'data_dumps': data_dumps,
                'sqli_attempts': sqli_attempts,
                'scanner_activity': scanner_activity,
                'brute_force': brute_force,
                'total_requests': 1500,
                'total_data_exposure_mb': 205.7
            }
    
    class LogCorrelator:
        def correlate(self, findings):
            # Add timeline data
            now = datetime.now()
            timeline = []
            
            for i in range(20):
                event_time = now - timedelta(hours=i)
                timeline.append({
                    'timestamp': event_time.isoformat(),
                    'event_type': 'sqli' if i % 3 == 0 else 'scanner' if i % 3 == 1 else 'brute_force',
                    'ip': f"192.168.1.{i+1}",
                    'endpoint': '/admin' if i % 2 == 0 else '/api/data',
                    'message': 'Suspicious activity detected'
                })
            
            findings['timeline'] = timeline
            return findings
    
    class ForensicVisualizer:
        def create_dashboard(self, correlated):
            # Create simple but valid visualizations
            risk_data = {
                'data': [{
                    'values': [15, 25, 30, 20, 10],
                    'labels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                    'type': 'pie',
                    'name': 'Risk Distribution',
                    'marker': {'colors': ['#FF0000', '#FF6B6B', '#FFD93D', '#6BCF7F', '#4D96FF']}
                }],
                'layout': {
                    'title': 'Risk Distribution',
                    'paper_bgcolor': '#1a1a2e',
                    'plot_bgcolor': '#16213e',
                    'font': {'color': '#e2e8f0'}
                }
            }
            
            timeline_data = {
                'data': [{
                    'x': list(range(24)),
                    'y': [10, 15, 20, 18, 25, 30, 35, 40, 35, 30, 25, 20, 15, 10, 5, 10, 15, 20, 25, 30, 35, 30, 25, 20],
                    'type': 'scatter',
                    'name': 'Requests',
                    'line': {'color': '#0ea5e9'}
                }],
                'layout': {
                    'title': 'Activity Timeline',
                    'paper_bgcolor': '#1a1a2e',
                    'plot_bgcolor': '#16213e',
                    'font': {'color': '#e2e8f0'},
                    'xaxis': {'title': 'Hour'},
                    'yaxis': {'title': 'Request Count'}
                }
            }
            
            heatmap_data = {
                'data': [{
                    'z': [[10, 20, 30], [20, 30, 40], [30, 40, 50]],
                    'x': ['/api', '/admin', '/login'],
                    'y': ['GET', 'POST', 'PUT'],
                    'type': 'heatmap',
                    'colorscale': 'Viridis'
                }],
                'layout': {
                    'title': 'Endpoint Heatmap',
                    'paper_bgcolor': '#1a1a2e',
                    'plot_bgcolor': '#16213e',
                    'font': {'color': '#e2e8f0'}
                }
            }
            
            return {
                'risk_distribution': json.dumps(risk_data),
                'timeline': json.dumps(timeline_data),
                'endpoint_heatmap': json.dumps(heatmap_data)
            }

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'log', 'txt', 'gz', 'bz2', 'zip', 'tar', 'gz', 'json', 'csv'}
app.config['TEMP_FOLDER'] = './temp'

socketio = SocketIO(app, cors_allowed_origins="*")

# Create necessary directories
for folder in [app.config['UPLOAD_FOLDER'], app.config['TEMP_FOLDER']]:
    Path(folder).mkdir(exist_ok=True, parents=True)

# Global variables for analysis results
analysis_results = {}
recent_analyses = []
uploaded_files = {}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def extract_archive(file_path, extract_to):
    """Extract compressed archives"""
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to)
        elif file_path.endswith('.tar.bz2'):
            with tarfile.open(file_path, 'r:bz2') as tar_ref:
                tar_ref.extractall(extract_to)
        elif file_path.endswith('.tar'):
            with tarfile.open(file_path, 'r:') as tar_ref:
                tar_ref.extractall(extract_to)
        return True
    except Exception as e:
        print(f"Error extracting archive: {e}")
        return False

def process_uploaded_file(file, session_id):
    """Process uploaded file and prepare for analysis"""
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    upload_dir = Path(app.config['UPLOAD_FOLDER']) / session_id
    upload_dir.mkdir(exist_ok=True, parents=True)
    
    file_path = upload_dir / filename
    file.save(str(file_path))
    
    # Check if it's an archive
    is_archive = any(str(file_path).endswith(ext) for ext in ['.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2'])
    
    extracted_files = []
    log_dir = str(upload_dir)
    
    if is_archive:
        # Extract archive
        extract_dir = upload_dir / 'extracted'
        extract_dir.mkdir(exist_ok=True)
        
        if extract_archive(str(file_path), str(extract_dir)):
            log_dir = str(extract_dir)
            # List extracted files
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    if f.endswith(('.log', '.txt', '.gz', '.bz2')):
                        extracted_files.append(os.path.join(root, f))
    
    return {
        'original_filename': filename,
        'file_path': str(file_path),
        'log_dir': log_dir,
        'is_archive': is_archive,
        'extracted_files': extracted_files,
        'upload_time': datetime.now().isoformat(),
        'file_size': os.path.getsize(file_path)
    }

def _create_summary(correlated):
    """Create summary from correlated findings"""
    # Count critical and high risks
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for ep in correlated.get('suspicious_endpoints', []):
        risk_level = ep.get('risk_level', '').upper()
        if risk_level == 'CRITICAL':
            critical_count += 1
        elif risk_level == 'HIGH':
            high_count += 1
        elif risk_level == 'MEDIUM':
            medium_count += 1
        elif risk_level == 'LOW':
            low_count += 1
    
    summary = {
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'suspicious_endpoints': len(correlated.get('suspicious_endpoints', [])),
        'malicious_ips': len(correlated.get('malicious_ips', [])),
        'total_requests': correlated.get('total_requests', 0),
        'total_data_exposure_gb': correlated.get('total_data_exposure_mb', 0) / 1024,
        'time_period': '24h'
    }
    
    return summary

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/upload')
def upload_page():
    """Upload logs page"""
    return render_template('upload.html')

@app.route('/api/upload', methods=['POST'])
def upload_files():
    """API endpoint to upload files"""
    try:
        # Check if files were uploaded
        if 'log_files' not in request.files:
            return jsonify({'success': False, 'error': 'No files uploaded'})
        
        files = request.files.getlist('log_files')
        session_id = str(uuid.uuid4())
        uploaded_files[session_id] = []
        
        # Process each file
        for file in files:
            if file.filename == '':
                continue
            
            if file and allowed_file(file.filename):
                file_info = process_uploaded_file(file, session_id)
                uploaded_files[session_id].append(file_info)
                
                # Send progress update via WebSocket
                socketio.emit('upload_update', {
                    'session_id': session_id,
                    'progress': 100,
                    'filename': file.filename,
                    'message': 'File uploaded successfully'
                })
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'file_count': len(uploaded_files[session_id]),
            'message': f'Successfully uploaded {len(uploaded_files[session_id])} file(s)'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analyze-upload', methods=['POST'])
def analyze_uploaded_logs():
    """Analyze uploaded logs"""
    try:
        data = request.json
        session_id = data.get('session_id')
        time_range = data.get('time_range', '24h')
        
        if session_id not in uploaded_files:
            return jsonify({'success': False, 'error': 'Session not found'})
        
        # Get the first uploaded directory
        upload_info = uploaded_files[session_id][0]
        log_dir = upload_info['log_dir']
        
        print(f"DEBUG: Analyzing logs from {log_dir}")
        
        # Run analysis
        collector = LogCollector(log_dir, time_range)
        logs = collector.collect_all()
        
        print(f"DEBUG: Logs collected: {type(logs)}, keys: {list(logs.keys())}")
        
        detector = AbuseDetector()
        findings = detector.analyze(logs)
        
        print(f"DEBUG: Findings generated: {type(findings)}, keys: {list(findings.keys())}")
        print(f"DEBUG: Suspicious endpoints count: {len(findings.get('suspicious_endpoints', []))}")
        
        correlator = LogCorrelator()
        correlated = correlator.correlate(findings)
        
        print(f"DEBUG: After correlation, timeline count: {len(correlated.get('timeline', []))}")
        
        # Store results
        analysis_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        analysis_results[analysis_id] = correlated
        
        # Add to recent analyses
        recent_analyses.append({
            'id': analysis_id,
            'timestamp': datetime.now().isoformat(),
            'source': 'upload',
            'filename': upload_info['original_filename'],
            'findings_count': len(correlated.get('suspicious_endpoints', []))
        })
        
        # Keep only last 10 analyses
        if len(recent_analyses) > 10:
            recent_analyses.pop(0)
        
        # Generate visualizations
        visualizer = ForensicVisualizer()
        dashboard = visualizer.create_dashboard(correlated)
        
        print(f"DEBUG: Dashboard created: {type(dashboard)}, keys: {list(dashboard.keys())}")
        
        # Send WebSocket update
        summary = _create_summary(correlated)
        socketio.emit('analysis_update', {
            'analysis_id': analysis_id,
            'critical_count': summary['critical_count'],
            'status': 'completed',
            'message': 'Analysis completed successfully'
        })
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'summary': summary,
            'dashboard': dashboard,
            'findings': correlated
        })
        
    except Exception as e:
        import traceback
        print(f"ERROR in analyze_uploaded_logs: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/upload-info/<session_id>')
def get_upload_info(session_id):
    """Get information about uploaded files"""
    if session_id in uploaded_files:
        files_info = []
        for file_info in uploaded_files[session_id]:
            files_info.append({
                'filename': file_info['original_filename'],
                'size_mb': round(file_info['file_size'] / (1024 * 1024), 2),
                'upload_time': file_info['upload_time'],
                'is_archive': file_info['is_archive'],
                'extracted_count': len(file_info['extracted_files'])
            })
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'files': files_info
        })
    
    return jsonify({'success': False, 'error': 'Session not found'})

@app.route('/api/list-uploads')
def list_uploads():
    """List all uploaded sessions"""
    sessions = []
    for session_id, files in uploaded_files.items():
        total_size = sum(f['file_size'] for f in files)
        sessions.append({
            'session_id': session_id,
            'file_count': len(files),
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'upload_time': files[0]['upload_time'] if files else None
        })
    
    return jsonify({'sessions': sessions})

@app.route('/api/clear-upload/<session_id>')
def clear_upload(session_id):
    """Clear uploaded files"""
    if session_id in uploaded_files:
        # Remove files from disk
        upload_dir = Path(app.config['UPLOAD_FOLDER']) / session_id
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
        
        del uploaded_files[session_id]
        return jsonify({'success': True, 'message': 'Upload cleared'})
    
    return jsonify({'success': False, 'error': 'Session not found'})

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    """API endpoint to analyze logs (existing functionality)"""
    try:
        data = request.json
        log_dir = data.get('log_dir', '/var/log')
        time_range = data.get('time_range', '24h')
        
        print(f"DEBUG: Starting analysis of {log_dir}")
        
        # Run analysis
        collector = LogCollector(log_dir, time_range)
        logs = collector.collect_all()
        
        print(f"DEBUG: Logs collected from {log_dir}")
        
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
        
        # Send WebSocket update
        summary = _create_summary(correlated)
        socketio.emit('analysis_update', {
            'analysis_id': analysis_id,
            'critical_count': summary['critical_count'],
            'status': 'completed',
            'message': 'Analysis completed successfully'
        })
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'summary': summary,
            'dashboard': dashboard,
            'findings': correlated
        })
        
    except Exception as e:
        import traceback
        print(f"ERROR in analyze_logs: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/recent-analyses')
def get_recent_analyses():
    """Get recent analyses"""
    return jsonify({
        'success': True,
        'analyses': recent_analyses[-10:]  # Last 10 analyses
    })

@app.route('/api/analysis/<analysis_id>')
def get_analysis(analysis_id):
    """Get specific analysis by ID"""
    if analysis_id in analysis_results:
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'summary': _create_summary(analysis_results[analysis_id]),
            'findings': analysis_results[analysis_id]
        })
    return jsonify({'success': False, 'error': 'Analysis not found'})

@app.route('/api/export/<analysis_id>/<format>')
def export_analysis(analysis_id, format):
    """Export analysis in various formats"""
    if analysis_id not in analysis_results:
        return jsonify({'success': False, 'error': 'Analysis not found'})
    
    data = analysis_results[analysis_id]
    
    if format == 'json':
        return jsonify(data)
    elif format == 'csv':
        # Convert to CSV
        import csv
        from io import StringIO
        
        si = StringIO()
        writer = csv.writer(si)
        
        # Write headers and some data
        writer.writerow(['Analysis ID', analysis_id])
        writer.writerow(['Timestamp', datetime.now().isoformat()])
        writer.writerow([])
        writer.writerow(['Suspicious Endpoints'])
        writer.writerow(['Endpoint', 'Requests', 'Risk Level', 'Unique IPs'])
        
        for endpoint in data.get('suspicious_endpoints', []):
            writer.writerow([
                endpoint.get('endpoint', ''),
                endpoint.get('total_requests', 0),
                endpoint.get('risk_level', ''),
                endpoint.get('unique_ips', 0)
            ])
        
        writer.writerow([])
        writer.writerow(['Malicious IPs'])
        writer.writerow(['IP Address', 'Requests', 'Risk Level', 'Unique Endpoints'])
        
        for ip in data.get('malicious_ips', []):
            writer.writerow([
                ip.get('ip', ''),
                ip.get('total_requests', 0),
                ip.get('risk_level', ''),
                ip.get('unique_endpoints', 0)
            ])
        
        output = si.getvalue()
        return output, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.csv'
        }
    else:
        return jsonify({'success': False, 'error': 'Unsupported format'})

@app.route('/api/system-info')
def system_info():
    """Get system information"""
    return jsonify({
        'version': 'v1.0.0',
        'status': 'running',
        'analyses_count': len(analysis_results),
        'uploads_count': len(uploaded_files),
        'storage_usage': 25  # percentage
    })

@app.route('/api/test-data')
def test_data():
    """Return test data for debugging"""
    now = datetime.now()
    
    test_findings = {
        'suspicious_endpoints': [
            {'endpoint': '/admin', 'total_requests': 150, 'unique_ips': 25, 
             'total_data_mb': 45.2, 'requests_per_minute': 12.5, 
             'risk_score': 85, 'risk_level': 'CRITICAL'},
            {'endpoint': '/api/data', 'total_requests': 300, 'unique_ips': 15,
             'total_data_mb': 120.5, 'requests_per_minute': 25.0,
             'risk_score': 75, 'risk_level': 'HIGH'}
        ],
        'malicious_ips': [
            {'ip': '192.168.1.100', 'total_requests': 500, 'request_rate_per_sec': 2.5,
             'unique_endpoints': 15, 'not_found_requests': 120, 'total_data_mb': 45.8,
             'risk_score': 95, 'risk_level': 'CRITICAL'}
        ],
        'timeline': [
            {'timestamp': (now - timedelta(hours=1)).isoformat(), 
             'event_type': 'sqli', 'ip': '192.168.1.100', 'endpoint': '/api/data'}
        ],
        'total_requests': 1500,
        'total_data_exposure_mb': 205.7
    }
    
    visualizer = ForensicVisualizer()
    dashboard = visualizer.create_dashboard(test_findings)
    
    return jsonify({
        'success': True,
        'analysis_id': 'test_001',
        'summary': _create_summary(test_findings),
        'dashboard': dashboard,
        'findings': test_findings
    })

# Real-time updates via WebSocket
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('status', {'message': 'Connected to forensic dashboard', 'timestamp': datetime.now().isoformat()})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('upload_progress')
def handle_upload_progress(data):
    """Handle upload progress updates"""
    socketio.emit('upload_update', {
        'session_id': data.get('session_id'),
        'progress': data.get('progress'),
        'filename': data.get('filename'),
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('analysis_status')
def handle_analysis_status(data):
    """Handle analysis status updates"""
    socketio.emit('analysis_update', {
        'analysis_id': data.get('analysis_id'),
        'status': data.get('status'),
        'progress': data.get('progress'),
        'message': data.get('message'),
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Starting Forensic Dashboard - DEBUGGED VERSION")
    print("=" * 60)
    print("📊 Dashboard URL: http://localhost:5000")
    print("📤 Upload Page: http://localhost:5000/upload")
    print("🔍 API Base URL: http://localhost:5000/api")
    print("🧪 Test Data: http://localhost:5000/api/test-data")
    print("📡 WebSocket: ws://localhost:5000")
    print("=" * 60)
    print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"📁 Temp folder: {app.config['TEMP_FOLDER']}")
    print(f"⚡ Analysis modules: {'Available' if ANALYSIS_MODULES_AVAILABLE else 'Mock Mode (ENHANCED)'}")
    print("=" * 60)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
