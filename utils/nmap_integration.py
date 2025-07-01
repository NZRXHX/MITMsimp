import nmap
import json
from xml.etree import ElementTree
import time

def run_nmap_scan(target, arguments="-sV -O --script vulners,banner"):
    """Run Nmap scan with specified arguments and return parsed results"""
    nm = nmap.PortScanner()
    
    try:
        print(f"[*] Starting Nmap scan on {target} with arguments: {arguments}")
        start_time = time.time()
        
        nm.scan(hosts=target, arguments=arguments)
        
        scan_time = time.time() - start_time
        print(f"[+] Nmap scan completed in {scan_time:.2f} seconds")
        
        return parse_nmap_results(nm)
    except nmap.PortScannerError as e:
        print(f"[-] Nmap scan failed: {str(e)}")
        return {}
    except Exception as e:
        print(f"[-] Unexpected error during Nmap scan: {str(e)}")
        return {}

def parse_nmap_results(nm):
    """Parse Nmap results into structured format"""
    results = {}
    
    for host in nm.all_hosts():
        host_info = {
            'status': nm[host].state(),
            'hostnames': nm[host].hostnames(),
            'os': {},
            'ports': [],
            'scripts': {},
            'vulnerabilities': []
        }
        
        # OS detection results
        if 'osmatch' in nm[host]:
            for osmatch in nm[host]['osmatch']:
                host_info['os'][osmatch['name']] = osmatch['accuracy']
        
        # Port and service information
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                service_info = {
                    'port': port,
                    'protocol': proto,
                    'state': port_info['state'],
                    'service': port_info['name'],
                    'version': port_info.get('version', 'unknown'),
                    'product': port_info.get('product', ''),
                    'extra': port_info.get('extrainfo', '')
                }
                
                # Script output
                if 'script' in port_info:
                    service_info['scripts'] = port_info['script']
                    self._parse_vulnerabilities(host_info, port_info['script'])
                
                host_info['ports'].append(service_info)
        
        results[host] = host_info
    
    return results

def _parse_vulnerabilities(host_info, script_output):
    """Parse NSE script output for vulnerabilities"""
    if isinstance(script_output, dict):
        for script_name, output in script_output.items():
            if script_name == 'vulners':
                lines = output.split('\n')
                for line in lines:
                    if 'CVE-' in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            host_info['vulnerabilities'].append({
                                'id': parts[0],
                                'score': parts[1],
                                'description': ' '.join(parts[2:])
                            })
