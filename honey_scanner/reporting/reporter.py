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
                    vuln.get('id', ''), vuln.get('type', ''), vuln.get('level', ''),
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
            content += f"### {v['type']} ({v['level']})\n- URL: {v['url']}\n- Parameter: {v['parameter']}\n- Proof: {v['proof']}\n\n"
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
        # Summary HTML template with Chart.js integration
        html_content = f"<html><body><h1>Scan Report {timestamp}</h1><p>Target: {self.scan_info['target']}</p></body></html>"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filename

    def calculate_statistics(self):
        stats = Counter(v.get('level', 'Low') for v in self.vulnerabilities)
        return dict(stats)

    def calculate_risk_assessment(self):
        if not self.vulnerabilities: return {'score': 0, 'level': 'Safe'}
        # Simple weighted score
        score = sum({'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}.get(v['level'], 1) for v in self.vulnerabilities)
        return {'score': score, 'level': 'High' if score > 10 else 'Medium'}
