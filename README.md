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
