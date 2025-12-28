"""
Web Dashboard for Server Log Forensics Tool - WITH UPLOAD SUPPORT
"""

from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for, flash
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
import tempfile
import uuid

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
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'log', 'txt', 'gz', 'bz2', 'zip', 'tar', 'gz', 'json', 'csv'}
app.config['TEMP_FOLDER'] = './temp'

socketio = SocketIO(app)

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
    file.save(file_path)
    
    # Check if it's an archive
    is_archive = any(file_path.suffix in ['.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2'])
    
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

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    """Upload logs page"""
    if request.method == 'POST':
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
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'file_count': len(uploaded_files[session_id]),
            'message': f'Successfully uploaded {len(uploaded_files[session_id])} file(s)'
        })
    
    return render_template('upload.html')

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

# ... [rest of the existing routes remain the same] ...

# Real-time updates via WebSocket
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('status', {'message': 'Connected to forensic dashboard'})

@socketio.on('upload_progress')
def handle_upload_progress(data):
    """Handle upload progress updates"""
    socketio.emit('upload_update', {
        'session_id': data.get('session_id'),
        'progress': data.get('progress'),
        'filename': data.get('filename')
    })

if __name__ == '__main__':
    print("🚀 Starting Forensic Dashboard with Upload Support...")
    print("📊 Dashboard URL: http://localhost:5000")
    print("📤 Upload URL: http://localhost:5000/upload")
    print("🔍 API Base URL: http://localhost:5000/api")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
