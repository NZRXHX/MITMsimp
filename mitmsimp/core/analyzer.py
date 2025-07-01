from ..modules import (
    ssl_stripping,
    https_capture,
    tcp_hijacking,
    dns_impersonation,
    arp_spoofing,
    dhcp_starvation
)

class VulnerabilityAnalyzer:
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.vulnerabilities = []
        self.interface = scan_results.get('interface')
    
    def analyze(self):
        """Run all vulnerability detection modules"""
        print("[*] Starting vulnerability analysis...")
        
        # Get all unique IPs from scan results
        hosts = self._get_all_hosts()
        
        # Initialize all detectors
        detectors = [
            ssl_stripping.SSLStrippingDetector(hosts),
            https_capture.HTTPSCaptureDetector(self.scan_results.get('nmap', {})),
            tcp_hijacking.TCPHijackingDetector(hosts, self.interface),
            dns_impersonation.DNSImpersonationDetector(hosts, self.interface),
            arp_spoofing.ARPSpoofingDetector(hosts, self.interface),
            dhcp_starvation.DHCPStarvationDetector(self.interface)
        ]
        
        # Run all detectors
        for detector in detectors:
            try:
                method_name = f"check_{detector.__class__.__name__.lower().replace('detector', '')}"
                if hasattr(detector, method_name):
                    results = getattr(detector, method_name)()
                    self.vulnerabilities.extend(results)
            except Exception as e:
                print(f"[-] Error running {detector.__class__.__name__}: {str(e)}")
        
        return self._prioritize_vulnerabilities()
    
    def _get_all_hosts(self):
        """Extract all unique IP addresses from scan results"""
        hosts = set()
        
        # Add all discovered hosts
        if 'hosts' in self.scan_results:
            hosts.update(self.scan_results['hosts'])
        
        # Add hosts from Nmap results
        if 'nmap' in self.scan_results:
            hosts.update(self.scan_results['nmap'].keys())
        
        return list(hosts)
    
    def _prioritize_vulnerabilities(self):
        """Sort vulnerabilities by severity"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        return sorted(self.vulnerabilities, 
                    key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
