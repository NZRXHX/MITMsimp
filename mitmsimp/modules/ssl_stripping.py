import requests
from urllib.parse import urlparse
from OpenSSL import SSL
import socket
import re
from scapy.all import *
from scapy.layers.http import HTTPRequest
import concurrent.futures
from bs4 import BeautifulSoup

class SSLStrippingDetector:
    def __init__(self, hosts, timeout=5):
        self.hosts = hosts
        self.timeout = timeout
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = 0
        
    def check_ssl_stripping(self):
        """Check for SSL stripping vulnerabilities"""
        print("[*] Checking for SSL stripping vulnerabilities...")
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for host in self.hosts:
                if ':' in host:
                    host, port = host.split(':')
                else:
                    port = 80
                futures.append(executor.submit(self._check_host, host, port))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.vulnerabilities.extend(result)
        
        return self.vulnerabilities
    
    def _check_host(self, host, port):
        """Check a single host for SSL stripping vulnerabilities"""
        host_vulns = []
        
        # Check 1: HTTP to HTTPS redirect
        http_url = f"http://{host}:{port}"
        try:
            response = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    host_vulns.append({
                        'host': host,
                        'type': 'ssl_stripping_redirect',
                        'severity': 'high',
                        'description': f'HTTP to HTTPS redirect found ({location})',
                        'remediation': 'Implement HSTS and disable HTTP redirects'
                    })
        except:
            pass
        
        # Check 2: Mixed content detection
        https_url = f"https://{host}:{port}"
        try:
            response = self.session.get(https_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for HTTP resources in HTTPS page
            insecure_resources = []
            for tag in soup.find_all(['img', 'script', 'iframe', 'link']):
                url = tag.get('src') or tag.get('href')
                if url and url.startswith('http://'):
                    insecure_resources.append(url)
            
            if insecure_resources:
                host_vulns.append({
                    'host': host,
                    'type': 'mixed_content',
                    'severity': 'medium',
                    'description': f'Mixed content found: {len(insecure_resources)} HTTP resources loaded over HTTPS',
                    'remediation': 'Ensure all resources are loaded via HTTPS or relative URLs'
                })
        except:
            pass
        
        # Check 3: HSTS header missing
        try:
            response = self.session.head(https_url, timeout=self.timeout)
            if 'strict-transport-security' not in response.headers:
                host_vulns.append({
                    'host': host,
                    'type': 'hsts_missing',
                    'severity': 'high',
                    'description': 'HSTS header not present',
                    'remediation': 'Implement HSTS header with appropriate max-age'
                })
        except:
            pass
        
        # Check 4: SSL certificate validation
        try:
            context = SSL.Context(SSL.TLSv1_2_METHOD)
            conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.connect((host, 443 if port == 80 else port))
            conn.do_handshake()
            cert = conn.get_peer_certificate()
            
            # Check certificate validity
            if cert.has_expired():
                host_vulns.append({
                    'host': host,
                    'type': 'expired_certificate',
                    'severity': 'high',
                    'description': 'SSL certificate has expired',
                    'remediation': 'Renew SSL certificate immediately'
                })
        except SSL.Error as e:
            host_vulns.append({
                'host': host,
                'type': 'ssl_error',
                'severity': 'high',
                'description': f'SSL handshake failed: {str(e)}',
                'remediation': 'Check SSL/TLS configuration'
            })
        finally:
            if 'conn' in locals():
                conn.close()
        
        return host_vulns
