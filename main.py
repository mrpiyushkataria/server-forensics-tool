#!/usr/bin/env python3
"""
Server Log Forensics & Endpoint Abuse Detection Tool
"""

import click
import sys
from pathlib import Path
from datetime import datetime
from core.log_parsers import LogCollector
from core.detectors import AbuseDetector
from core.correlator import LogCorrelator
from output.reporter import ReportGenerator
from storage.sqlite_manager import DatabaseManager
import warnings
warnings.filterwarnings('ignore')

@click.group()
def cli():
    """Server Log Forensics & Endpoint Abuse Detection Tool"""
    pass

@cli.command()
@click.option('--log-dir', required=True, help='Directory containing log files')
@click.option('--output', default='./forensics_report', help='Output directory for reports')
@click.option('--time-range', default='24h', help='Time range (e.g., 24h, 7d, 30d)')
@click.option('--config', default='./config/settings.yaml', help='Configuration file')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def analyze(log_dir, output, time_range, config, verbose):
    """Analyze logs for security threats"""
    
    click.echo(f"🔍 Starting forensic analysis...")
    click.echo(f"📁 Log directory: {log_dir}")
    click.echo(f"⏰ Time range: {time_range}")
    
    # Initialize components
    db = DatabaseManager(':memory:')  # Use SQLite in-memory for speed
    
    # Collect and parse logs
    collector = LogCollector(log_dir, time_range)
    logs = collector.collect_all()
    
    if not logs:
        click.echo("❌ No logs found matching criteria")
        sys.exit(1)
    
    # Detect abuses
    detector = AbuseDetector()
    findings = detector.analyze(logs)
    
    # Correlate findings
    correlator = LogCorrelator()
    correlated = correlator.correlate(findings)
    
    # Generate reports
    reporter = ReportGenerator(output)
    reporter.generate_all(correlated)
    
    click.echo(f"✅ Analysis complete! Reports saved to {output}")
    click.echo(f"📊 Findings: {len(findings['suspicious_endpoints'])} suspicious endpoints")
    click.echo(f"🌐 Suspicious IPs: {len(findings['malicious_ips'])}")

@cli.command()
@click.option('--ip', required=True, help='IP address to investigate')
@click.option('--log-dir', required=True, help='Directory containing log files')
def trace(ip, log_dir):
    """Trace activities of a specific IP address"""
    
    from processors.nginx_processor import NginxProcessor
    
    click.echo(f"🔎 Tracing IP: {ip}")
    processor = NginxProcessor()
    activities = processor.trace_ip(ip, log_dir)
    
    for activity in activities[:10]:  # Show last 10 activities
        click.echo(f"  {activity['timestamp']} - {activity['endpoint']} - {activity['status']}")

@cli.command()
@click.option('--endpoint', required=True, help='Endpoint to analyze')
@click.option('--log-dir', required=True, help='Directory containing log files')
def endpoint(endpoint, log_dir):
    """Analyze specific endpoint for abuse"""
    
    from core.detectors import EndpointAnalyzer
    
    analyzer = EndpointAnalyzer()
    result = analyzer.analyze_endpoint(endpoint, log_dir)
    
    click.echo(f"📈 Endpoint Analysis: {endpoint}")
    click.echo(f"   Total requests: {result['total_requests']}")
    click.echo(f"   Unique IPs: {result['unique_ips']}")
    click.echo(f"   Data transferred: {result['total_data_mb']:.2f} MB")
    click.echo(f"   Risk score: {result['risk_score']}/100")

if __name__ == '__main__':
    cli()
