#!/usr/bin/env python3
"""
Unified Launcher for Server Log Forensics Tool
Starts both CLI and Web Dashboard automatically
"""

import sys
import os
import subprocess
import threading
import time
from pathlib import Path
import webbrowser
import socket
import signal

def check_port_available(port):
    """Check if a port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', port))
        sock.close()
        return True
    except socket.error:
        return False

def start_dashboard():
    """Start the Flask web dashboard"""
    print("🚀 Starting Web Dashboard...")
    
    # Import and run the dashboard
    try:
        from dashboard.app import app, socketio
        
        # Start dashboard in a separate thread
        def run_dashboard():
            socketio.run(app, 
                        host='0.0.0.0', 
                        port=5000, 
                        debug=False, 
                        allow_unsafe_werkzeug=True)
        
        dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
        dashboard_thread.start()
        
        # Wait for dashboard to start
        for i in range(30):  # Wait up to 30 seconds
            time.sleep(1)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', 5000))
                sock.close()
                if result == 0:
                    print("✅ Dashboard started successfully!")
                    return True
            except:
                pass
            if i % 5 == 0:
                print(f"⏳ Waiting for dashboard to start... ({i+1}s)")
        
        print("❌ Dashboard failed to start")
        return False
        
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")
        return False

def start_cli_interface():
    """Start the CLI interface in a separate process"""
    print("\n📟 Starting CLI Interface...")
    print("=" * 60)
    
    # Import and run main CLI
    try:
        from main import cli
        cli()
    except KeyboardInterrupt:
        print("\n👋 Exiting...")
    except Exception as e:
        print(f"❌ Error in CLI: {e}")

def run_analysis_automatically():
    """Run automatic analysis on startup"""
    print("\n🔍 Running Automatic Analysis...")
    
    # Default paths to check
    log_paths = [
        '/var/log/nginx',
        '/var/log/apache2',
        '/var/log/httpd',
        './logs',
        '/tmp/logs'
    ]
    
    # Find existing log directory
    log_dir = None
    for path in log_paths:
        path_obj = Path(path)
        if path_obj.exists():
            print(f"📁 Found directory: {path}")
            # Check if it contains log files
            log_files = list(path_obj.glob('*.log')) + list(path_obj.glob('access.log*')) + list(path_obj.glob('error.log*'))
            if log_files:
                log_dir = path
                print(f"✅ Found {len(log_files)} log files in: {log_dir}")
                break
            else:
                print(f"⚠️  Directory exists but no log files found: {path}")
    
    if not log_dir:
        print("⚠️  No log directory with log files found. Using sample mode.")
        log_dir = "./sample_logs"
        Path(log_dir).mkdir(exist_ok=True)
        # Create sample log file
        sample_log = log_dir + "/sample_access.log"
        with open(sample_log, 'w') as f:
            f.write('127.0.0.1 - - [28/Dec/2024:23:02:15 +0000] "GET /admin HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
            f.write('192.168.1.100 - - [28/Dec/2024:23:02:16 +0000] "GET /api/data HTTP/1.1" 200 1024 "-" "sqlmap/1.0"\n')
        print(f"📝 Created sample log file: {sample_log}")
    
    # Run analysis
    try:
        from core.log_parsers import LogCollector
        from core.detectors import AbuseDetector
        from core.correlator import LogCorrelator
        from output.reporter import ReportGenerator
        
        print(f"🔍 Starting analysis of: {log_dir}")
        collector = LogCollector(log_dir, '24h')
        logs = collector.collect_all()
        
        if logs and not logs.get('nginx', pd.DataFrame()).empty:
            print(f"✅ Successfully collected {len(logs.get('nginx', pd.DataFrame()))} log entries")
            
            detector = AbuseDetector()
            findings = detector.analyze(logs)
            
            correlator = LogCorrelator()
            correlated = correlator.correlate(findings)
            
            # Generate reports
            os.makedirs('./reports', exist_ok=True)
            reporter = ReportGenerator('./reports')
            reporter.generate_all(correlated)
            
            print("✅ Automatic analysis completed!")
            print(f"📊 Reports saved to: ./reports")
            
            # Open the dashboard automatically
            time.sleep(2)  # Give dashboard time to start
            webbrowser.open('http://localhost:5000')
            
            return correlated
        else:
            print("⚠️  No logs found in the directory.")
            print("   Check file permissions or try:")
            print("   1. Run with sudo for /var/log access")
            print("   2. Copy logs to a local directory")
            print("   3. Use the web interface to upload logs")
            return None
            
    except Exception as e:
        print(f"❌ Error during automatic analysis: {e}")
        import traceback
        traceback.print_exc()
        return None

def open_browser():
    """Open web browser to dashboard"""
    time.sleep(3)  # Wait for dashboard to initialize
    webbrowser.open('http://localhost:5000')
    print("🌐 Opening dashboard in your web browser...")

def show_welcome():
    """Show welcome message and options"""
    print("\n" + "=" * 60)
    print("🔐 SERVER LOG FORENSICS & ENDPOINT ABUSE DETECTION TOOL")
    print("=" * 60)
    print("\nChoose an option:")
    print("1. Start Dashboard + CLI (Recommended)")
    print("2. Start Dashboard only")
    print("3. Start CLI only")
    print("4. Run Automatic Analysis + Dashboard")
    print("5. Exit")
    print("\n" + "-" * 60)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n🛑 Shutting down...")
    sys.exit(0)

def main():
    """Main launcher function"""
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check dependencies
    print("🔧 Checking dependencies...")
    try:
        import flask
        import plotly
        import pandas
        print("✅ All dependencies are installed!")
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return
    
    # Show welcome menu
    while True:
        show_welcome()
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                # Start both dashboard and CLI
                if start_dashboard():
                    # Start CLI in separate thread
                    cli_thread = threading.Thread(target=start_cli_interface, daemon=True)
                    cli_thread.start()
                    
                    # Open browser
                    browser_thread = threading.Thread(target=open_browser, daemon=True)
                    browser_thread.start()
                    
                    # Keep main thread alive
                    print("\n" + "=" * 60)
                    print("🎯 Both interfaces are running!")
                    print("• Dashboard: http://localhost:5000")
                    print("• CLI: Active in this terminal")
                    print("\nPress Ctrl+C to exit")
                    print("=" * 60 + "\n")
                    
                    # Keep program running
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        break
                    
            elif choice == '2':
                # Dashboard only
                if start_dashboard():
                    open_browser()
                    print("\n🎯 Dashboard is running at: http://localhost:5000")
                    print("Press Ctrl+C to exit")
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        break
            
            elif choice == '3':
                # CLI only
                start_cli_interface()
                break
            
            elif choice == '4':
                # Automatic analysis + dashboard
                if start_dashboard():
                    analysis_thread = threading.Thread(target=run_analysis_automatically, daemon=True)
                    analysis_thread.start()
                    
                    print("\n🎯 System is running!")
                    print("• Dashboard: http://localhost:5000")
                    print("• Analysis: Running in background")
                    print("\nPress Ctrl+C to exit")
                    
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        break
            
            elif choice == '5':
                print("👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == '__main__':
    main()
