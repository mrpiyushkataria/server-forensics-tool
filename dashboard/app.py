"""
Web Dashboard for Server Log Forensics Tool - WITH UPLOAD SUPPORT
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
    
    # Mock classes for testing
    class LogCollector:
        def __init__(self, log_dir, time_range):
            self.log_dir = log_dir
            self.time_range = time_range
            
        def collect_all(self):
            # Return mock DataFrame
            data = {
                'timestamp': [datetime.now() - timedelta(hours=i) for i in range(24)],
                'ip': ['192.168.1.' + str(i) for i in range(1, 25)],
                'endpoint': ['/api/data', '/admin', '/login', '/download'] * 6,
                'status_code': [200, 404, 500, 200] * 6,
                'bytes_sent': [1024, 0, 0, 2048] * 6,
                'user_agent': ['Mozilla/5.0'] * 24
            }
            return pd.DataFrame(data)
    
    class AbuseDetector:
        def analyze(self, logs):
            return {
                'suspicious_endpoints': [
                    {'endpoint': '/admin', 'total_requests': 150, 'risk_level': 'HIGH'},
                    {'endpoint': '/api/data', 'total_requests': 300, 'risk_level': 'MEDIUM'},
                ],
                'malicious_ips': [
                    {'ip': '192.168.1.100', 'total_requests': 500, 'risk_level': 'CRITICAL'},
                    {'ip': '10.0.0.5', 'total_requests': 200, 'risk_level': 'HIGH'},
                ],
                'total_requests': 1000,
                'total_data_exposure_mb': 50.5
            }
    
    class LogCorrelator:
        def correlate(self, findings):
            findings['timeline'] = [
                {'timestamp': datetime.now() - timedelta(hours=1), 'event_type': 'suspicious', 'endpoint': '/admin'},
                {'timestamp': datetime.now() - timedelta(hours=2), 'event_type': 'malicious', 'ip': '192.168.1.100'},
            ]
            return findings
    
    class ForensicVisualizer:
        def create_dashboard(self, correlated):
            return {
                'risk_distribution': json.dumps({
                    'data': [{
                        'labels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        'values': [5, 10, 25, 60],
                        'type': 'pie',
                        'name': 'Risk Distribution'
                    }],
                    'layout': {'title': 'Risk Distribution'}
                }),
                'timeline': json.dumps({
                    'data': [{
                        'x': list(range(24)),
                        'y': [10, 15, 20, 18, 25, 30, 35, 40, 35, 30, 25, 20, 15, 10, 5, 10, 15, 20, 25, 30, 35, 30, 25, 20],
                        'type': 'scatter',
                        'name': 'Requests'
                    }],
                    'layout': {'title': 'Activity Timeline'}
                }),
                'endpoint_heatmap': json.dumps({
                    'data': [{
                        'z': [[10, 20, 30], [20, 30, 40], [30, 40, 50]],
                        'x': ['/api', '/admin', '/login'],
                        'y': ['GET', 'POST', 'PUT'],
                        'type': 'heatmap'
                    }],
                    'layout': {'title': 'Endpoint Heatmap'}
                })
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
    summary = {
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'suspicious_endpoints': len(correlated.get('suspicious_endpoints', [])),
        'malicious_ips': len(correlated.get('malicious_ips', [])),
        'total_requests': correlated.get('total_requests', 0),
        'total_data_exposure_gb': correlated.get('total_data_exposure_mb', 0) / 1024,
        'time_period': '24h'
    }
    
    # Count risk levels
    for endpoint in correlated.get('suspicious_endpoints', []):
        risk = endpoint.get('risk_level', 'LOW')
        if risk == 'CRITICAL':
            summary['critical_count'] += 1
        elif risk == 'HIGH':
            summary['high_count'] += 1
        elif risk == 'MEDIUM':
            summary['medium_count'] += 1
        else:
            summary['low_count'] += 1
    
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
        
        # Run analysis
        collector = LogCollector(log_dir, time_range)
        logs = collector.collect_all()
        
        if logs.empty:
            return jsonify({'success': False, 'error': 'No logs found in uploaded files'})
        
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
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'summary': _create_summary(correlated),
            'dashboard': dashboard,
            'findings': correlated
        })
        
    except Exception as e:
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
    print("🚀 Starting Forensic Dashboard with Upload Support")
    print("=" * 60)
    print("📊 Dashboard URL: http://localhost:5000")
    print("📤 Upload Page: http://localhost:5000/upload")
    print("🔍 API Base URL: http://localhost:5000/api")
    print("📡 WebSocket: ws://localhost:5000")
    print("=" * 60)
    print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"📁 Temp folder: {app.config['TEMP_FOLDER']}")
    print(f"⚡ Analysis modules: {'Available' if ANALYSIS_MODULES_AVAILABLE else 'Mock Mode'}")
    print("=" * 60)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
