import json
import csv
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import plotly.graph_objects as go
import plotly.io as pio

class ReportGenerator:
    """Generate forensic reports in multiple formats"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def generate_all(self, findings: Dict[str, Any]):
        """Generate all report formats"""
        
        # JSON report
        self._generate_json_report(findings)
        
        # CSV reports
        self._generate_csv_reports(findings)
        
        # PDF report
        self._generate_pdf_report(findings)
        
        # HTML dashboard
        self._generate_html_dashboard(findings)
        
        # Summary report
        self._generate_summary(findings)
    
    def _generate_json_report(self, findings: Dict):
        """Generate comprehensive JSON report"""
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'analysis_type': 'server_log_forensics'
            },
            'summary': self._create_summary(findings),
            'findings': findings
        }
        
        output_file = self.output_dir / f'forensic_report_{self.timestamp}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"JSON report saved to: {output_file}")
    
    def _generate_csv_reports(self, findings: Dict):
        """Generate CSV reports for different findings"""
        
        # Suspicious endpoints
        if 'suspicious_endpoints' in findings:
            endpoints_df = pd.DataFrame(findings['suspicious_endpoints'])
            endpoints_file = self.output_dir / f'suspicious_endpoints_{self.timestamp}.csv'
            endpoints_df.to_csv(endpoints_file, index=False)
        
        # Malicious IPs
        if 'malicious_ips' in findings:
            ips_df = pd.DataFrame(findings['malicious_ips'])
            ips_file = self.output_dir / f'malicious_ips_{self.timestamp}.csv'
            ips_df.to_csv(ips_file, index=False)
        
        # Data dumps
        if 'data_dumps' in findings:
            dumps_df = pd.DataFrame(findings['data_dumps'])
            dumps_file = self.output_dir / f'data_dumps_{self.timestamp}.csv'
            dumps_df.to_csv(dumps_file, index=False)
        
        print(f"CSV reports saved to: {self.output_dir}")
    
    def _generate_pdf_report(self, findings: Dict):
        """Generate management-friendly PDF report"""
        
        pdf_file = self.output_dir / f'forensic_summary_{self.timestamp}.pdf'
        doc = SimpleDocTemplate(str(pdf_file), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph("Server Log Forensic Analysis Report", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Metadata
        meta_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        meta = Paragraph(meta_text, styles['Normal'])
        story.append(meta)
        story.append(Spacer(1, 24))
        
        # Executive Summary
        summary = self._create_summary(findings)
        
        exec_summary = Paragraph("<b>Executive Summary</b>", styles['Heading2'])
        story.append(exec_summary)
        
        summary_text = f"""
        Total Findings: {summary['total_findings']}
        Critical Issues: {summary['critical_count']}
        High Risk Issues: {summary['high_count']}
        Estimated Data Exposure: {summary['total_data_exposure_gb']:.2f} GB
        Time Range Analyzed: {summary['time_range_hours']:.1f} hours
        """
        
        summary_para = Paragraph(summary_text.replace('\n', '<br/>'), styles['Normal'])
        story.append(summary_para)
        story.append(Spacer(1, 24))
        
        # Top Findings Table
        story.append(Paragraph("<b>Top 10 Suspicious Endpoints</b>", styles['Heading2']))
        
        if 'suspicious_endpoints' in findings and findings['suspicious_endpoints']:
            data = [['Endpoint', 'Requests', 'Data (MB)', 'Risk Level']]
            
            for endpoint in sorted(findings['suspicious_endpoints'], 
                                 key=lambda x: x.get('risk_score', 0), reverse=True)[:10]:
                data.append([
                    endpoint.get('endpoint', 'N/A')[:40],
                    str(endpoint.get('total_requests', 0)),
                    f"{endpoint.get('total_data_mb', 0):.2f}",
                    endpoint.get('risk_level', 'N/A')
                ])
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        
        story.append(Spacer(1, 24))
        
        # Recommendations
        rec_text = """
        <b>Recommended Actions:</b><br/>
        1. Review all CRITICAL and HIGH risk endpoints<br/>
        2. Block identified malicious IPs<br/>
        3. Implement rate limiting on sensitive endpoints<br/>
        4. Review data exposure and implement access controls<br/>
        5. Monitor identified endpoints for continued abuse<br/>
        """
        
        rec_para = Paragraph(rec_text, styles['Normal'])
        story.append(rec_para)
        
        # Build PDF
        doc.build(story)
        print(f"PDF report saved to: {pdf_file}")
    
    def _generate_html_dashboard(self, findings: Dict):
        """Generate interactive HTML dashboard"""
        
        html_file = self.output_dir / f'dashboard_{self.timestamp}.html'
        
        # Create visualizations
        fig1 = self._create_endpoint_heatmap(findings)
        fig2 = self._create_timeline_chart(findings)
        fig3 = self._create_risk_distribution(findings)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Analysis Dashboard</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
                .summary-card {{ background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 5px; }}
                .chart {{ margin: 30px 0; height: 500px; }}
                .critical {{ color: #dc3545; font-weight: bold; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Server Log Forensic Analysis Dashboard</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                {self._create_summary_html(findings)}
            </div>
            
            <h2>Risk Distribution</h2>
            <div class="chart" id="riskChart"></div>
            
            <h2>Endpoint Activity Timeline</h2>
            <div class="chart" id="timelineChart"></div>
            
            <h2>Top Suspicious Endpoints</h2>
            {self._create_endpoints_table(findings)}
            
            <h2>Top Malicious IPs</h2>
            {self._create_ips_table(findings)}
            
            <script>
                {fig3.to_html(full_html=False, include_plotlyjs=False)}
                {fig2.to_html(full_html=False, include_plotlyjs=False)}
            </script>
        </body>
        </html>
        """
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML dashboard saved to: {html_file}")
    
    def _create_summary(self, findings: Dict) -> Dict:
        """Create analysis summary"""
        
        total_endpoints = len(findings.get('suspicious_endpoints', []))
        total_ips = len(findings.get('malicious_ips', []))
        total_data_dumps = len(findings.get('data_dumps', []))
        
        # Calculate risk distribution
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for endpoint in findings.get('suspicious_endpoints', []):
            risk_level = endpoint.get('risk_level', 'INFO')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        # Calculate total data exposure
        total_data = sum(ep.get('total_data_mb', 0) 
                        for ep in findings.get('suspicious_endpoints', []))
        
        return {
            'total_findings': total_endpoints + total_ips + total_data_dumps,
            'suspicious_endpoints': total_endpoints,
            'malicious_ips': total_ips,
            'data_dumps': total_data_dumps,
            'risk_distribution': risk_counts,
            'critical_count': risk_counts['CRITICAL'],
            'high_count': risk_counts['HIGH'],
            'medium_count': risk_counts['MEDIUM'],
            'low_count': risk_counts['LOW'],
            'total_data_exposure_gb': total_data / 1024,
            'time_range_hours': 24  # Default, should be calculated from logs
        }
    
    def _create_summary_html(self, findings: Dict) -> str:
        """Create HTML summary cards"""
        
        summary = self._create_summary(findings)
        
        cards = [
            f'<div class="summary-card"><h3>Total Findings</h3><h2>{summary["total_findings"]}</h2></div>',
            f'<div class="summary-card"><h3>Critical Issues</h3><h2 class="critical">{summary["critical_count"]}</h2></div>',
            f'<div class="summary-card"><h3>High Risk</h3><h2 class="high">{summary["high_count"]}</h2></div>',
            f'<div class="summary-card"><h3>Data Exposure</h3><h2>{summary["total_data_exposure_gb"]:.1f} GB</h2></div>',
            f'<div class="summary-card"><h3>Suspicious IPs</h3><h2>{summary["malicious_ips"]}</h2></div>'
        ]
        
        return '\n'.join(cards)
    
    def _create_endpoints_table(self, findings: Dict) -> str:
        """Create HTML table for suspicious endpoints"""
        
        if not findings.get('suspicious_endpoints'):
            return "<p>No suspicious endpoints found.</p>"
        
        html = ['<table>', '<tr><th>Endpoint</th><th>Requests</th><th>Data (MB)</th><th>Unique IPs</th><th>Risk Level</th></tr>']
        
        for endpoint in sorted(findings['suspicious_endpoints'], 
                             key=lambda x: x.get('risk_score', 0), reverse=True)[:20]:
            risk_class = endpoint.get('risk_level', '').lower()
            html.append(f"""
            <tr>
                <td>{endpoint.get('endpoint', 'N/A')[:60]}</td>
                <td>{endpoint.get('total_requests', 0)}</td>
                <td>{endpoint.get('total_data_mb', 0):.2f}</td>
                <td>{endpoint.get('unique_ips', 0)}</td>
                <td class="{risk_class}">{endpoint.get('risk_level', 'N/A')}</td>
            </tr>
            """)
        
        html.append('</table>')
        return '\n'.join(html)
    
    def _create_ips_table(self, findings: Dict) -> str:
        """Create HTML table for malicious IPs"""
        
        if not findings.get('malicious_ips'):
            return "<p>No malicious IPs found.</p>"
        
        html = ['<table>', '<tr><th>IP Address</th><th>Requests</th><th>Request Rate</th><th>404 Errors</th><th>Risk Level</th></tr>']
        
        for ip in sorted(findings['malicious_ips'], 
                        key=lambda x: x.get('risk_score', 0), reverse=True)[:15]:
            risk_class = ip.get('risk_level', '').lower()
            html.append(f"""
            <tr>
                <td>{ip.get('ip', 'N/A')}</td>
                <td>{ip.get('total_requests', 0)}</td>
                <td>{ip.get('request_rate_per_sec', 0):.2f}/s</td>
                <td>{ip.get('not_found_requests', 0)}</td>
                <td class="{risk_class}">{ip.get('risk_level', 'N/A')}</td>
            </tr>
            """)
        
        html.append('</table>')
        return '\n'.join(html)
    
    def _create_risk_distribution(self, findings: Dict) -> go.Figure:
        """Create risk distribution pie chart"""
        
        summary = self._create_summary(findings)
        risk_counts = summary['risk_distribution']
        
        labels = list(risk_counts.keys())
        values = list(risk_counts.values())
        
        colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.3,
            marker_colors=colors
        )])
        
        fig.update_layout(
            title='Risk Level Distribution',
            showlegend=True
        )
        
        return fig
    
    def _create_timeline_chart(self, findings: Dict) -> go.Figure:
        """Create timeline chart of suspicious activity"""
        
        # This would require timestamp data from findings
        # Placeholder implementation
        fig = go.Figure()
        
        fig.update_layout(
            title='Suspicious Activity Timeline',
            xaxis_title='Time',
            yaxis_title='Request Count',
            showlegend=True
        )
        
        return fig
    
    def _create_endpoint_heatmap(self, findings: Dict) -> go.Figure:
        """Create endpoint heatmap"""
        
        # Placeholder implementation
        fig = go.Figure(data=go.Heatmap(
            z=[[1, 20, 30], [20, 1, 60], [30, 60, 1]],
            colorscale='Viridis'
        ))
        
        fig.update_layout(
            title='Endpoint Activity Heatmap'
        )
        
        return fig
    
    def _generate_summary(self, findings: Dict):
        """Generate a text summary report"""
        
        summary_file = self.output_dir / f'summary_{self.timestamp}.txt'
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SERVER LOG FORENSIC ANALYSIS SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 80 + "\n\n")
            
            summary = self._create_summary(findings)
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Findings: {summary['total_findings']}\n")
            f.write(f"Critical Issues: {summary['critical_count']}\n")
            f.write(f"High Risk Issues: {summary['high_count']}\n")
            f.write(f"Estimated Data Exposure: {summary['total_data_exposure_gb']:.2f} GB\n\n")
            
            f.write("TOP SUSPICIOUS ENDPOINTS\n")
            f.write("-" * 40 + "\n")
            
            if findings.get('suspicious_endpoints'):
                for i, endpoint in enumerate(
                    sorted(findings['suspicious_endpoints'], 
                          key=lambda x: x.get('risk_score', 0), reverse=True)[:10], 1):
                    
                    f.write(f"\n{i}. {endpoint.get('endpoint', 'N/A')}\n")
                    f.write(f"   Requests: {endpoint.get('total_requests', 0)}\n")
                    f.write(f"   Data Transferred: {endpoint.get('total_data_mb', 0):.2f} MB\n")
                    f.write(f"   Unique IPs: {endpoint.get('unique_ips', 0)}\n")
                    f.write(f"   Risk Level: {endpoint.get('risk_level', 'N/A')}\n")
                    f.write(f"   Risk Score: {endpoint.get('risk_score', 0)}/100\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"Summary report saved to: {summary_file}")
