import json
import csv
import xml.etree.ElementTree as ET
import html
from datetime import datetime
from collections import Counter

class EnhancedReporting:
    """Enhanced reporting dengan multiple formats dan visualizations"""
    
    def __init__(self, vulnerabilities, scan_info):
        self.vulnerabilities = vulnerabilities
        self.scan_info = scan_info
        
    def generate_all_reports(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return {
            'html': self.generate_html_report_enhanced(timestamp),
            'json': self.generate_json_report(timestamp),
            'csv': self.generate_csv_report(timestamp),
            'markdown': self.generate_markdown_report(timestamp),
            'xml': self.generate_xml_report(timestamp)
        }
    
    def generate_json_report(self, timestamp):
        filename = f"scan_report_{timestamp}.json"
        report_data = {
            'scan_info': self.scan_info,
            'vulnerabilities': self.vulnerabilities,
            'statistics': self.calculate_statistics(),
            'risk_assessment': self.calculate_risk_assessment()
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        return filename

    def generate_csv_report(self, timestamp):
        filename = f"scan_report_{timestamp}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Type', 'Severity', 'URL', 'Parameter', 'Confidence', 'Proof'])
            for vuln in self.vulnerabilities:
                writer.writerow([
                    vuln.get('id', ''), vuln.get('type', vuln.get('vuln_type', 'Unknown')), vuln.get('level', ''),
                    vuln.get('url', ''), vuln.get('parameter', ''), f"{vuln.get('confidence', 0):.2%}",
                    str(vuln.get('proof', ''))[:100]
                ])
        return filename

    def generate_markdown_report(self, timestamp):
        filename = f"scan_report_{timestamp}.md"
        content = f"# Vulnerability Scan Report\n\nTarget: {self.scan_info.get('target', 'N/A')}\n" \
                  f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n" \
                  f"Duration: {self.scan_info.get('duration', 0):.2f}s\n\n"
        stats = self.calculate_statistics()
        for level, count in stats.items():
            content += f"- **{level}**: {count}\n"
        content += "\n## Findings\n"
        for v in self.vulnerabilities:
            v_type = v.get('type', v.get('vuln_type', 'Unknown'))
            v_level = v.get('level', 'Medium')
            content += f"### {v_type} ({v_level})\n- URL: {v['url']}\n- Parameter: {v.get('parameter', 'N/A')}\n- Proof: {v.get('proof', 'N/A')}\n\n"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        return filename

    def generate_xml_report(self, timestamp):
        filename = f"scan_report_{timestamp}.xml"
        root = ET.Element('report')
        for vuln in self.vulnerabilities:
            v_elem = ET.SubElement(root, 'vulnerability')
            for k, v in vuln.items():
                ET.SubElement(v_elem, k).text = str(v)
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8')
        return filename

    def generate_html_report_enhanced(self, timestamp):
        filename = f"scan_report_{timestamp}.html"
        stats = self.calculate_statistics()
        risk_info = self.calculate_risk_assessment()
        
        # Color mapping for severities
        colors = {
            'Critical': '#ff0000',
            'High': '#ff6600',
            'Medium': '#ffcc00',
            'Low': '#3399ff',
            'Safe': '#2eb82e'
        }
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Honey Scanner Report - {self.scan_info['target']}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
                header {{ border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
                h1 {{ color: #1a237e; margin: 0; }}
                .risk-badge {{ padding: 10px 20px; border-radius: 50px; color: white; font-weight: bold; text-transform: uppercase; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
                .stat-card {{ background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #eee; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .stat-card h3 {{ margin: 0; color: #666; font-size: 14px; text-transform: uppercase; }}
                .stat-card .value {{ font-size: 28px; font-weight: bold; margin: 10px 0; }}
                .finding-card {{ border: 1px solid #eee; border-radius: 8px; margin-bottom: 20px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
                .finding-header {{ padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
                .finding-body {{ padding: 20px; background: #fafafa; border-top: 1px solid #eee; }}
                .severity-tag {{ padding: 4px 12px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }}
                .code-block {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 13px; }}
                .meta-info {{ display: grid; grid-template-columns: 100px 1fr; gap: 10px; margin-bottom: 10px; }}
                .meta-label {{ font-weight: bold; color: #666; }}
                .tech-tag {{ display: inline-block; background: #e3f2fd; color: #1976d2; padding: 3px 10px; border-radius: 15px; font-size: 12px; margin: 2px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div>
                        <h1>🍯 Honey Scanner Report</h1>
                        <p style="color: #666; margin-top: 5px;">Target: <strong>{self.scan_info['target']}</strong></p>
                    </div>
                    <div class="risk-badge" style="background-color: {colors.get(risk_info['level'], '#666')}">
                        Overall Risk: {risk_info['level']}
                    </div>
                </header>

                <div class="stats-grid">
                    <div class="stat-card" style="border-top: 4px solid {colors['Critical']}">
                        <h3>Critical</h3>
                        <div class="value">{stats.get('Critical', 0)}</div>
                    </div>
                    <div class="stat-card" style="border-top: 4px solid {colors['High']}">
                        <h3>High</h3>
                        <div class="value">{stats.get('High', 0)}</div>
                    </div>
                    <div class="stat-card" style="border-top: 4px solid {colors['Medium']}">
                        <h3>Medium</h3>
                        <div class="value">{stats.get('Medium', 0)}</div>
                    </div>
                    <div class="stat-card" style="border-top: 4px solid {colors['Low']}">
                        <h3>Low</h3>
                        <div class="value">{stats.get('Low', 0)}</div>
                    </div>
                </div>

                <h2>Vulnerability Findings</h2>
        """

        if not self.vulnerabilities:
            html_template += "<p style='text-align: center; padding: 40px; color: #666;'>No vulnerabilities found during this scan.</p>"
        else:
            for v in self.vulnerabilities:
                sev = v.get('level', 'Medium')
                color = colors.get(sev, '#666')
                v_type = v.get('type', v.get('vuln_type', 'Unknown Vulnerability'))
                html_template += f"""
                <div class="finding-card">
                    <div class="finding-header" style="background-color: {color}11">
                        <span style="font-weight: bold; font-size: 18px;">{html.escape(v_type)}</span>
                        <span class="severity-tag" style="background-color: {color}">{sev}</span>
                    </div>
                    <div class="finding-body">
                        <div class="meta-info">
                            <span class="meta-label">URL:</span>
                            <span>{html.escape(v['url'])}</span>
                        </div>
                        <div class="meta-info">
                            <span class="meta-label">Parameter:</span>
                            <span><code>{html.escape(v.get('parameter', 'N/A'))}</code></span>
                        </div>
                        <div class="meta-info">
                            <span class="meta-label">Method:</span>
                            <span>{html.escape(v.get('method', 'GET'))}</span>
                        </div>
                        <div class="meta-info">
                            <span class="meta-label">Confidence:</span>
                            <span>{(v.get('confidence', 0) * 100):.1f}%</span>
                        </div>
                        <div style="margin-top: 15px;">
                            <p class="meta-label" style="margin-bottom: 8px;">Proof of Concept / Payload:</p>
                            <div class="code-block">{html.escape(v.get('payload', v.get('proof', '')))}</div>
                        </div>
                    </div>
                </div>
                """

        html_template += """
            </div>
            <footer style="text-align: center; margin-top: 40px; color: #999; font-size: 12px;">
                Generated by Honey Scanner | &copy; 2026 Modular Security Assessment Tool
            </footer>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_template)
        return filename

    def calculate_statistics(self):
        stats = Counter(v.get('level', 'Low') for v in self.vulnerabilities)
        return dict(stats)

    def calculate_risk_assessment(self):
        if not self.vulnerabilities: return {'score': 0, 'level': 'Safe'}
        # Simple weighted score
        score = sum({'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}.get(v['level'], 1) for v in self.vulnerabilities)
        return {'score': score, 'level': 'High' if score > 10 else 'Medium'}
