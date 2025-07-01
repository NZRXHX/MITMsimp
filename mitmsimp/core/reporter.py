from jinja2 import Environment, FileSystemLoader
import json
import os
from datetime import datetime
from ..utils.output_formatter import format_vulnerability, format_scan_result
import webbrowser

class ReportGenerator:
    def __init__(self, scan_results, vulnerabilities):
        self.scan_results = scan_results
        self.vulnerabilities = vulnerabilities
        self.template_dir = os.path.join(os.path.dirname(__file__), '../../templates')
        self.template_env = Environment(loader=FileSystemLoader(self.template_dir))
        self.template_env.filters['severity_color'] = self._severity_color
    
    def generate_html_report(self, output_file):
        """Generate comprehensive HTML report"""
        template = self.template_env.get_template('report.html')
        
        # Prepare data for template
        report_data = {
            'scan': self.scan_results,
            'vulnerabilities': self.vulnerabilities,
            'summary': self._generate_summary(),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'host_count': len(self.scan_results.get('hosts', [])),
            'vuln_count': len(self.vulnerabilities)
        }
        
        html = template.render(report_data)
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        # Open in browser if possible
        try:
            webbrowser.open(f'file://{os.path.abspath(output_file)}')
        except:
            pass
    
    def generate_json_report(self, output_file):
        """Generate machine-readable JSON report"""
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'MITMsimp',
                'version': '0.1.0'
            },
            'scan': self.scan_results,
            'vulnerabilities': self.vulnerabilities,
            'summary': self._generate_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def generate_text_report(self, output_file):
        """Generate simple text report"""
        with open(output_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("MITMsimp Network Vulnerability Report\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Scan performed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanned network: {self.scan_results.get('target', 'unknown')}\n")
            f.write(f"Hosts discovered: {len(self.scan_results.get('hosts', []))}\n\n")
            
            f.write("Vulnerabilities Found:\n")
            f.write("="*60 + "\n")
            for vuln in self.vulnerabilities:
                f.write(format_vulnerability(vuln) + "\n")
                f.write("-"*60 + "\n")
            
            f.write("\nScan Details:\n")
            f.write("="*60 + "\n")
            for host, data in self.scan_results.get('nmap', {}).items():
                f.write(f"Host: {host}\n")
                f.write(f"Status: {data.get('status', 'unknown')}\n")
                f.write(f"OS Guess: {', '.join(data.get('os', {}).keys()) or 'unknown'}\n")
                
                f.write("\nOpen Ports:\n")
                for port in data.get('ports', []):
                    f.write(f"  {port['port']}/{port['protocol']}: {port['service']}")
                    if port['version']:
                        f.write(f" ({port['version']})")
                    f.write("\n")
                
                f.write("\n")
    
    def _generate_summary(self):
        """Generate summary statistics"""
        summary = {
            'total_hosts': len(self.scan_results.get('hosts', [])),
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'by_type': {}
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
            
            vuln_type = vuln.get('type', 'unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
        
        return summary
    
    @staticmethod
    def _severity_color(severity):
        """Jinja2 filter for severity color coding"""
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        }
        return colors.get(severity.lower(), 'secondary')
