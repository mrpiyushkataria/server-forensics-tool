"""
Data Visualization Module
Creates visual representations of forensic findings
"""

import plotly.graph_objects as go
import plotly.express as px
import plotly.subplots as sp
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import json
import base64
from io import BytesIO

class ForensicVisualizer:
    """Create visualizations for forensic analysis results"""
    
    def __init__(self, theme: str = 'plotly_dark'):
        self.theme = theme
        self.color_palette = {
            'critical': '#FF0000',
            'high': '#FF6B6B',
            'medium': '#FFD93D',
            'low': '#6BCF7F',
            'info': '#4D96FF',
            'background': '#2C3E50',
            'grid': '#34495E'
        }
    
    def create_dashboard(self, findings: Dict[str, Any]) -> Dict[str, str]:
        """Create comprehensive dashboard with multiple visualizations"""
        
        dashboard = {}
        
        # 1. Risk Distribution Pie Chart
        dashboard['risk_distribution'] = self._create_risk_distribution_chart(findings)
        
        # 2. Timeline Visualization
        dashboard['timeline'] = self._create_timeline_chart(findings)
        
        # 3. Endpoint Heatmap
        dashboard['endpoint_heatmap'] = self._create_endpoint_heatmap(findings)
        
        # 4. IP Threat Network
        dashboard['ip_network'] = self._create_ip_network_chart(findings)
        
        # 5. Data Exposure Chart
        dashboard['data_exposure'] = self._create_data_exposure_chart(findings)
        
        # 6. Attack Pattern Sankey
        dashboard['attack_patterns'] = self._create_attack_pattern_sankey(findings)
        
        # 7. Hourly Activity
        dashboard['hourly_activity'] = self._create_hourly_activity_chart(findings)
        
        # 8. Geographic Map (if IP geolocation available)
        dashboard['geo_map'] = self._create_geographic_map(findings)
        
        return dashboard
    
    def _create_risk_distribution_chart(self, findings: Dict) -> str:
        """Create risk distribution pie chart"""
        
        if 'suspicious_endpoints' not in findings:
            return self._create_empty_chart("No Risk Data Available")
        
        # Count risk levels
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for endpoint in findings['suspicious_endpoints']:
            risk_level = endpoint.get('risk_level', 'INFO')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        # Prepare data
        labels = list(risk_counts.keys())
        values = list(risk_counts.values())
        colors = [
            self.color_palette['critical'],
            self.color_palette['high'],
            self.color_palette['medium'],
            self.color_palette['low'],
            self.color_palette['info']
        ]
        
        # Create figure
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.4,
            marker_colors=colors,
            textinfo='label+percent',
            textposition='inside',
            hoverinfo='label+value+percent',
            pull=[0.1 if label == 'CRITICAL' else 0 for label in labels]
        )])
        
        fig.update_layout(
            title={
                'text': 'Risk Level Distribution',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        return self._fig_to_html(fig)
    
    def _create_timeline_chart(self, findings: Dict) -> str:
        """Create timeline visualization of suspicious activities"""
        
        if 'timeline' not in findings or not findings['timeline']:
            return self._create_empty_chart("No Timeline Data Available")
        
        timeline_data = findings['timeline']
        
        # Convert to DataFrame for easier processing
        df = pd.DataFrame(timeline_data)
        
        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Create timeline traces for different event types
        fig = go.Figure()
        
        event_types = df['event_type'].unique() if 'event_type' in df.columns else []
        color_map = {
            'sqli': self.color_palette['critical'],
            'scanner': self.color_palette['high'],
            'brute_force': self.color_palette['medium'],
            'data_dump': self.color_palette['low'],
            'request': self.color_palette['info'],
            'error': '#FFA500'
        }
        
        for event_type in event_types:
            event_data = df[df['event_type'] == event_type]
            
            fig.add_trace(go.Scatter(
                x=event_data['timestamp'],
                y=[event_type] * len(event_data),
                mode='markers',
                name=event_type.replace('_', ' ').title(),
                marker=dict(
                    size=10,
                    color=color_map.get(event_type, self.color_palette['info']),
                    symbol='circle',
                    line=dict(width=2, color='white')
                ),
                hoverinfo='text',
                hovertext=[
                    f"<b>{event_type.upper()}</b><br>"
                    f"Time: {ts}<br>"
                    f"IP: {row.get('ip', 'N/A')}<br>"
                    f"Endpoint: {row.get('endpoint', 'N/A')}"
                    for _, row in event_data.iterrows()
                ]
            ))
        
        fig.update_layout(
            title={
                'text': 'Suspicious Activity Timeline',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            xaxis_title="Time",
            yaxis_title="Event Type",
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            showlegend=True,
            hovermode='closest'
        )
        
        return self._fig_to_html(fig)
    
    def _create_endpoint_heatmap(self, findings: Dict) -> str:
        """Create endpoint activity heatmap"""
        
        if 'suspicious_endpoints' not in findings or not findings['suspicious_endpoints']:
            return self._create_empty_chart("No Endpoint Data Available")
        
        endpoints_data = findings['suspicious_endpoints']
        
        # Extract top endpoints by risk score
        top_endpoints = sorted(
            endpoints_data,
            key=lambda x: x.get('risk_score', 0),
            reverse=True
        )[:20]
        
        # Prepare data for heatmap
        endpoints = [ep['endpoint'][:30] + '...' if len(ep['endpoint']) > 30 
                    else ep['endpoint'] for ep in top_endpoints]
        risk_scores = [ep.get('risk_score', 0) for ep in top_endpoints]
        request_counts = [ep.get('total_requests', 0) for ep in top_endpoints]
        data_transferred = [ep.get('total_data_mb', 0) for ep in top_endpoints]
        
        # Create subplots
        fig = make_subplots(
            rows=1, cols=3,
            subplot_titles=('Risk Score', 'Request Count', 'Data Transferred (MB)'),
            horizontal_spacing=0.1
        )
        
        # Risk Score heatmap
        fig.add_trace(
            go.Heatmap(
                z=[risk_scores],
                y=['Risk Score'],
                x=endpoints,
                colorscale='Reds',
                showscale=False,
                hoverongaps=False,
                text=[risk_scores],
                texttemplate='%{text:.0f}',
                textfont={"size": 10}
            ),
            row=1, col=1
        )
        
        # Request Count heatmap
        fig.add_trace(
            go.Heatmap(
                z=[request_counts],
                y=['Requests'],
                x=endpoints,
                colorscale='Blues',
                showscale=False,
                hoverongaps=False,
                text=[request_counts],
                texttemplate='%{text:.0f}',
                textfont={"size": 10}
            ),
            row=1, col=2
        )
        
        # Data Transferred heatmap
        fig.add_trace(
            go.Heatmap(
                z=[data_transferred],
                y=['Data MB'],
                x=endpoints,
                colorscale='Greens',
                showscale=False,
                hoverongaps=False,
                text=[f"{x:.1f}" for x in data_transferred],
                texttemplate='%{text}',
                textfont={"size": 10}
            ),
            row=1, col=3
        )
        
        fig.update_layout(
            title={
                'text': 'Top Endpoint Activity Heatmap',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            showlegend=False,
            height=300
        )
        
        fig.update_xaxes(tickangle=45)
        
        return self._fig_to_html(fig)
    
    def _create_ip_network_chart(self, findings: Dict) -> str:
        """Create IP threat network visualization"""
        
        if 'malicious_ips' not in findings or not findings['malicious_ips']:
            return self._create_empty_chart("No IP Threat Data Available")
        
        ips_data = findings['malicious_ips']
        
        # Take top IPs by risk score
        top_ips = sorted(
            ips_data,
            key=lambda x: x.get('risk_score', 0),
            reverse=True
        )[:15]
        
        if not top_ips:
            return self._create_empty_chart("No IP Threat Data Available")
        
        # Create nodes and edges
        nodes = []
        edges = []
        
        # Add IP nodes
        for idx, ip_data in enumerate(top_ips):
            ip = ip_data.get('ip', f'IP_{idx}')
            risk_score = ip_data.get('risk_score', 0)
            
            # Determine node size based on risk
            node_size = 15 + (risk_score / 100 * 30)
            
            # Determine node color based on risk level
            if risk_score >= 80:
                color = self.color_palette['critical']
            elif risk_score >= 60:
                color = self.color_palette['high']
            elif risk_score >= 40:
                color = self.color_palette['medium']
            elif risk_score >= 20:
                color = self.color_palette['low']
            else:
                color = self.color_palette['info']
            
            nodes.append({
                'id': ip,
                'label': ip,
                'size': node_size,
                'color': color,
                'risk_score': risk_score,
                'requests': ip_data.get('total_requests', 0)
            })
        
        # Create edges based on shared endpoints (simplified)
        for i, ip1_data in enumerate(top_ips):
            ip1 = ip1_data.get('ip', f'IP_{i}')
            endpoints1 = set(ip1_data.get('accessed_endpoints_sample', []))
            
            for j, ip2_data in enumerate(top_ips[i+1:], i+1):
                ip2 = ip2_data.get('ip', f'IP_{j}')
                endpoints2 = set(ip2_data.get('accessed_endpoints_sample', []))
                
                shared_endpoints = endpoints1.intersection(endpoints2)
                if shared_endpoints:
                    weight = len(shared_endpoints)
                    edges.append({
                        'source': ip1,
                        'target': ip2,
                        'weight': weight,
                        'color': f'rgba(255, 255, 255, {min(0.3 + weight/10, 0.8)})'
                    })
        
        # Create network graph
        fig = go.Figure()
        
        # Add edges
        edge_x = []
        edge_y = []
        edge_text = []
        
        for edge in edges:
            # Find node positions (simplified circular layout)
            source_idx = [idx for idx, node in enumerate(nodes) if node['id'] == edge['source']][0]
            target_idx = [idx for idx, node in enumerate(nodes) if node['id'] == edge['target']][0]
            
            # Circular layout positions
            angle_step = 2 * np.pi / len(nodes)
            source_angle = source_idx * angle_step
            target_angle = target_idx * angle_step
            
            source_pos = (np.cos(source_angle), np.sin(source_angle))
            target_pos = (np.cos(target_angle), np.sin(target_angle))
            
            edge_x.extend([source_pos[0], target_pos[0], None])
            edge_y.extend([source_pos[1], target_pos[1], None])
            edge_text.extend([None, None, None])
        
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='rgba(255, 255, 255, 0.5)'),
            hoverinfo='none',
            mode='lines',
            showlegend=False
        ))
        
        # Add nodes
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        node_size = []
        node_hover = []
        
        for idx, node in enumerate(nodes):
            angle = idx * (2 * np.pi / len(nodes))
            x = np.cos(angle)
            y = np.sin(angle)
            
            node_x.append(x)
            node_y.append(y)
            node_text.append(node['label'])
            node_color.append(node['color'])
            node_size.append(node['size'])
            node_hover.append(
                f"IP: {node['label']}<br>"
                f"Risk Score: {node['risk_score']:.0f}<br>"
                f"Requests: {node['requests']}"
            )
        
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            textposition="top center",
            hovertext=node_hover,
            hoverinfo='text',
            marker=dict(
                size=node_size,
                color=node_color,
                line=dict(width=2, color='white')
            ),
            showlegend=False
        ))
        
        fig.update_layout(
            title={
                'text': 'IP Threat Network',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=500
        )
        
        return self._fig_to_html(fig)
    
    def _create_data_exposure_chart(self, findings: Dict) -> str:
        """Create data exposure visualization"""
        
        if 'suspicious_endpoints' not in findings or not findings['suspicious_endpoints']:
            return self._create_empty_chart("No Data Exposure Data Available")
        
        endpoints_data = findings['suspicious_endpoints']
        
        # Filter endpoints with data exposure
        data_endpoints = [
            ep for ep in endpoints_data 
            if ep.get('total_data_mb', 0) > 0
        ]
        
        if not data_endpoints:
            return self._create_empty_chart("No Significant Data Exposure Detected")
        
        # Sort by data exposure
        data_endpoints = sorted(
            data_endpoints,
            key=lambda x: x.get('total_data_mb', 0),
            reverse=True
        )[:10]
        
        endpoints = []
        data_mb = []
        risk_scores = []
        request_counts = []
        
        for ep in data_endpoints:
            endpoints.append(ep['endpoint'][:40] + '...' if len(ep['endpoint']) > 40 else ep['endpoint'])
            data_mb.append(ep.get('total_data_mb', 0))
            risk_scores.append(ep.get('risk_score', 0))
            request_counts.append(ep.get('total_requests', 0))
        
        # Create bubble chart
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=request_counts,
            y=data_mb,
            mode='markers+text',
            text=endpoints,
            textposition="top center",
            marker=dict(
                size=[score / 10 for score in risk_scores],  # Size based on risk score
                color=risk_scores,
                colorscale='RdYlGn_r',  # Red to Green (reversed)
                showscale=True,
                colorbar=dict(title="Risk Score"),
                line=dict(width=2, color='white')
            ),
            hovertext=[
                f"Endpoint: {ep}<br>"
                f"Data: {data:.1f} MB<br>"
                f"Requests: {req}<br>"
                f"Risk Score: {risk:.0f}"
                for ep, data, req, risk in zip(endpoints, data_mb, request_counts, risk_scores)
            ],
            hoverinfo='text'
        ))
        
        fig.update_layout(
            title={
                'text': 'Data Exposure Analysis',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            xaxis_title="Total Requests",
            yaxis_title="Data Transferred (MB)",
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            showlegend=False,
            height=500
        )
        
        # Log scale if data range is large
        if max(data_mb) > 10 * min(data_mb) and min(data_mb) > 0:
            fig.update_yaxes(type="log")
        
        return self._fig_to_html(fig)
    
    def _create_attack_pattern_sankey(self, findings: Dict) -> str:
        """Create Sankey diagram for attack patterns"""
        
        if 'attack_chains' not in findings or not findings['attack_chains']:
            return self._create_empty_chart("No Attack Chain Data Available")
        
        attack_chains = findings['attack_chains']
        
        # Extract attack steps
        nodes = []
        links = []
        node_labels = {}
        link_counts = {}
        
        for chain in attack_chains:
            steps = chain.get('chain', [])
            for step in steps:
                source = step.get('from', '').upper()
                target = step.get('to', '').upper()
                
                if source and target:
                    # Add nodes
                    if source not in node_labels:
                        node_labels[source] = len(node_labels)
                    if target not in node_labels:
                        node_labels[target] = len(node_labels)
                    
                    # Count links
                    link_key = (node_labels[source], node_labels[target])
                    link_counts[link_key] = link_counts.get(link_key, 0) + 1
        
        # Prepare data for Sankey
        source_indices = []
        target_indices = []
        values = []
        labels = list(node_labels.keys())
        
        for (source_idx, target_idx), count in link_counts.items():
            source_indices.append(source_idx)
            target_indices.append(target_idx)
            values.append(count)
        
        if not source_indices:
            return self._create_empty_chart("No Attack Patterns Detected")
        
        # Create Sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="white", width=0.5),
                label=labels,
                color=[self._get_attack_color(label) for label in labels]
            ),
            link=dict(
                source=source_indices,
                target=target_indices,
                value=values,
                color=[f"rgba(255, 107, 107, {0.2 + 0.8 * (v/max(values))})" for v in values]
            )
        )])
        
        fig.update_layout(
            title={
                'text': 'Attack Pattern Flow',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            height=500
        )
        
        return self._fig_to_html(fig)
    
    def _create_hourly_activity_chart(self, findings: Dict) -> str:
        """Create hourly activity visualization"""
        
        if 'timeline' not in findings or not findings['timeline']:
            return self._create_empty_chart("No Timeline Data Available")
        
        timeline_data = findings['timeline']
        df = pd.DataFrame(timeline_data)
        
        if 'timestamp' not in df.columns:
            return self._create_empty_chart("No Timestamp Data Available")
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        
        # Group by hour and event type
        if 'event_type' in df.columns:
            hourly_counts = df.groupby(['hour', 'event_type']).size().unstack(fill_value=0)
            
            fig = go.Figure()
            
            for event_type in hourly_counts.columns:
                fig.add_trace(go.Bar(
                    x=hourly_counts.index,
                    y=hourly_counts[event_type],
                    name=event_type.replace('_', ' ').title(),
                    marker_color=self._get_attack_color(event_type)
                ))
            
            fig.update_layout(
                barmode='stack',
                title={
                    'text': 'Hourly Activity Distribution',
                    'y': 0.95,
                    'x': 0.5,
                    'xanchor': 'center',
                    'yanchor': 'top',
                    'font': {'size': 20, 'color': 'white'}
                },
                xaxis_title="Hour of Day",
                yaxis_title="Event Count",
                plot_bgcolor=self.color_palette['background'],
                paper_bgcolor=self.color_palette['background'],
                font_color='white',
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=400
            )
        else:
            # Simple hourly count
            hourly_counts = df.groupby('hour').size()
            
            fig = go.Figure(data=[go.Bar(
                x=hourly_counts.index,
                y=hourly_counts.values,
                marker_color=self.color_palette['info']
            )])
            
            fig.update_layout(
                title={
                    'text': 'Hourly Activity',
                    'y': 0.95,
                    'x': 0.5,
                    'xanchor': 'center',
                    'yanchor': 'top',
                    'font': {'size': 20, 'color': 'white'}
                },
                xaxis_title="Hour of Day",
                yaxis_title="Event Count",
                plot_bgcolor=self.color_palette['background'],
                paper_bgcolor=self.color_palette['background'],
                font_color='white',
                height=400
            )
        
        return self._fig_to_html(fig)
    
    def _create_geographic_map(self, findings: Dict) -> str:
        """Create geographic map of IP locations"""
        
        if 'malicious_ips' not in findings or not findings['malicious_ips']:
            return self._create_empty_chart("No IP Data Available for Geolocation")
        
        # This is a placeholder - actual implementation would require IP geolocation
        # For now, create a simulated map
        
        fig = go.Figure()
        
        # Add a placeholder message
        fig.add_annotation(
            text="IP Geolocation requires GeoIP2 database<br>"
                 "Install with: pip install geoip2<br>"
                 "Download GeoLite2 database from MaxMind",
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=14, color="white"),
            align="center"
        )
        
        fig.update_layout(
            title={
                'text': 'Geographic Threat Map',
                'y': 0.95,
                'x': 0.5,
                'xanchor': 'center',
                'yanchor': 'top',
                'font': {'size': 20, 'color': 'white'}
            },
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            font_color='white',
            showlegend=False,
            height=400,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        
        return self._fig_to_html(fig)
    
    # Helper methods
    def _get_attack_color(self, attack_type: str) -> str:
        """Get color for attack type"""
        
        attack_colors = {
            'SQLI': self.color_palette['critical'],
            'SCANNER': self.color_palette['high'],
            'BRUTE_FORCE': self.color_palette['medium'],
            'DATA_DUMP': self.color_palette['low'],
            'RECONNAISSANCE': '#FFA500',
            'EXPLOIT': '#FF0000',
            'EXFILTRATION': '#00FF00'
        }
        
        attack_upper = attack_type.upper()
        for key, color in attack_colors.items():
            if key in attack_upper:
                return color
        
        return self.color_palette['info']
    
    def _create_empty_chart(self, message: str) -> str:
        """Create an empty chart with a message"""
        
        fig = go.Figure()
        
        fig.add_annotation(
            text=message,
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=14, color="white"),
            align="center"
        )
        
        fig.update_layout(
            plot_bgcolor=self.color_palette['background'],
            paper_bgcolor=self.color_palette['background'],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=300
        )
        
        return self._fig_to_html(fig)
    
    def _fig_to_html(self, fig) -> str:
        """Convert figure to HTML string"""
        
        # Update layout with theme
        fig.update_layout(template=self.theme)
        
        # Convert to HTML
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def create_interactive_report(self, findings: Dict) -> str:
        """Create complete interactive HTML report"""
        
        dashboard = self.create_dashboard(findings)
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Analysis Dashboard</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: {bg_color};
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    text-align: center;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5em;
                    font-weight: 300;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                    font-size: 1.1em;
                }}
                .grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .chart-container {{
                    background: {card_bg};
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }}
                .chart-container h2 {{
                    margin-top: 0;
                    color: #64b5f6;
                    border-bottom: 2px solid #64b5f6;
                    padding-bottom: 10px;
                }}
                .summary-cards {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .summary-card {{
                    background: {card_bg};
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    transition: transform 0.2s;
                }}
                .summary-card:hover {{
                    transform: translateY(-5px);
                }}
                .summary-card h3 {{
                    margin: 0 0 10px 0;
                    font-size: 1em;
                    color: #bbbbbb;
                }}
                .summary-card .value {{
                    font-size: 2em;
                    font-weight: bold;
                    margin: 10px 0;
                }}
                .critical {{ color: {critical_color}; }}
                .high {{ color: {high_color}; }}
                .medium {{ color: {medium_color}; }}
                .low {{ color: {low_color}; }}
                .info {{ color: {info_color}; }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #444;
                    color: #888;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Server Log Forensic Analysis</h1>
                    <p>Generated: {timestamp}</p>
                </div>
                
                <div class="summary-cards">
                    {summary_cards}
                </div>
                
                <div class="grid">
                    {charts}
                </div>
                
                <div class="footer">
                    <p>Forensic Analysis Tool v1.0 | Security Audit Report</p>
                    <p>This report contains sensitive information. Handle with care.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create summary cards
        summary_cards_html = self._create_summary_cards(findings)
        
        # Create charts HTML
        charts_html = ""
        for chart_name, chart_html in dashboard.items():
            charts_html += f"""
            <div class="chart-container">
                <h2>{chart_name.replace('_', ' ').title()}</h2>
                <div class="chart">{chart_html}</div>
            </div>
            """
        
        # Fill template
        html_content = html_template.format(
            bg_color=self.color_palette['background'],
            card_bg='#3a506b',
            critical_color=self.color_palette['critical'],
            high_color=self.color_palette['high'],
            medium_color=self.color_palette['medium'],
            low_color=self.color_palette['low'],
            info_color=self.color_palette['info'],
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            summary_cards=summary_cards_html,
            charts=charts_html
        )
        
        return html_content
    
    def _create_summary_cards(self, findings: Dict) -> str:
        """Create summary cards HTML"""
        
        # Calculate summary statistics
        total_endpoints = len(findings.get('suspicious_endpoints', []))
        total_ips = len(findings.get('malicious_ips', []))
        total_data_dumps = len(findings.get('data_dumps', []))
        total_sqli = len(findings.get('sqli_attempts', []))
        
        # Calculate risk distribution
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for endpoint in findings.get('suspicious_endpoints', []):
            risk_level = endpoint.get('risk_level', 'INFO')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        # Calculate total data exposure
        total_data_mb = sum(
            ep.get('total_data_mb', 0) 
            for ep in findings.get('suspicious_endpoints', [])
        )
        
        cards = [
            f"""
            <div class="summary-card">
                <h3>Suspicious Endpoints</h3>
                <div class="value">{total_endpoints}</div>
            </div>
            """,
            f"""
            <div class="summary-card">
                <h3>Malicious IPs</h3>
                <div class="value">{total_ips}</div>
            </div>
            """,
            f"""
            <div class="summary-card">
                <h3>Critical Risks</h3>
                <div class="value critical">{risk_counts['CRITICAL']}</div>
            </div>
            """,
            f"""
            <div class="summary-card">
                <h3>Data Exposure</h3>
                <div class="value">{total_data_mb:.1f} MB</div>
            </div>
            """,
            f"""
            <div class="summary-card">
                <h3>SQL Injection Attempts</h3>
                <div class="value high">{total_sqli}</div>
            </div>
            """,
            f"""
            <div class="summary-card">
                <h3>Data Dumps</h3>
                <div class="value">{total_data_dumps}</div>
            </div>
            """
        ]
        
        return '\n'.join(cards)
