#!/usr/bin/env python3
"""
One-command starter for Server Log Forensics Tool
Usage: python run.py
"""

import os
import sys
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

def main():
    print("🚀 Starting Server Log Forensics Tool...")
    
    # Start dashboard
    print("📊 Starting web dashboard...")
    dashboard_proc = subprocess.Popen(
        [sys.executable, "dashboard/app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for dashboard to start
    time.sleep(5)
    
    # Open browser
    print("🌐 Opening dashboard in browser...")
    webbrowser.open("http://localhost:5000")
    
    print("\n" + "="*60)
    print("✅ Tool is now running!")
    print("• Dashboard: http://localhost:5000")
    print("• CLI: Available in this terminal")
    print("\nPress Ctrl+C to stop everything")
    print("="*60 + "\n")
    
    # Keep running
    try:
        dashboard_proc.wait()
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")
        dashboard_proc.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
