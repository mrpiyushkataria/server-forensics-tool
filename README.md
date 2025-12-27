# server-forensics-tool
Server Log Forensics &amp; Endpoint Abuse Detection Tool



🚀 How to Use
Install dependencies:

bash
pip install -r requirements.txt
Run the tool:

bash
python main.py analyze --log-dir /var/log --output ./reports
Analyze specific endpoints:

bash
python main.py endpoint --endpoint /api/users --log-dir /var/log/nginx
Trace specific IPs:

bash
python main.py trace --ip 192.168.1.100 --log-dir /var/log







✅ Complete Implementation Summary
core/correlator.py - Log correlation engine to connect events across different log sources

core/scoring.py - Comprehensive risk scoring engine with multiple factors

processors/nginx_processor.py - Specialized Nginx log processing with advanced detection

processors/php_processor.py - PHP error log processing and correlation

processors/mysql_processor.py - MySQL slow query and general log analysis

processors/waf_processor.py - WAF/ModSecurity log processing

output/visualizer.py - Interactive data visualizations with Plotly

output/exporters.py - Multiple format exports (JSON, CSV, Excel, SQLite, XML, YAML, Markdown)

utils/helpers.py - General utility functions

utils/patterns.py - Comprehensive pattern definitions for detection

utils/validators.py - Data validation and sanitization

All __init__.py files - Package initialization files




🖥️ Dashboard Features
Once you open the dashboard, you'll see:

1. Main Dashboard Section
Summary Cards: Critical issues count, suspicious endpoints, malicious IPs, data exposure

Interactive Charts:

Risk distribution pie chart

Activity timeline

Endpoint heatmap

Top Findings Tables: Quick view of most suspicious endpoints and IPs

2. Endpoints Section
Detailed table of all suspicious endpoints

Search and filter capabilities

Click to view detailed endpoint analysis

3. IP Analysis Section
Table of malicious IP addresses

Request statistics and risk levels

Option to block IPs directly from dashboard

4. Timeline Section
Chronological view of security events

Attack progression visualization

5. Reports Section
Export options: PDF, Excel, JSON

Generate management reports

6. Settings Section
Configure analysis parameters

Set risk thresholds

Enable/disable notifications

🔄 Real-time Features
The dashboard includes:

Live updates via WebSocket

Real-time alerts when new threats are detected

Live monitoring of log files (if enabled)

Auto-refresh of analysis results

📱 Responsive Design
The dashboard is fully responsive:

Works on desktop, tablet, and mobile

Dark theme for better visibility

Interactive charts that work on all devices

🎯 Quick Start Commands



# 1. Install all dependencies
pip install -r requirements.txt flask flask-socketio

# 2. Run the web dashboard
cd dashboard
python app.py

# 3. Open browser and navigate to:
# http://localhost:5000

# 4. Click "New Analysis" button
# 5. Enter log directory path (e.g., /var/log)
# 6. Click "Start Analysis"
# 7. View results in the dashboard!
