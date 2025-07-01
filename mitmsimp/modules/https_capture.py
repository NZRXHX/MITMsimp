import socket
import OpenSSL
from datetime import datetime
import ssl
import requests
from urllib.parse import urlparse
from ..utils.network_utils import get_default_gateway

class HTTPSCaptureDetector:
    def __init__(self, hosts):
        self.hosts = hosts
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        self.session.timeout = 5
    
    def check_https_capture(self):
        """Check for HTTPS interception vulnerabilities"""
        print("[*] Checking for HTTPS capture vulnerabilities...")
        
        # First identify HTTPS services
        https_services = []
        for host in self.hosts:
            if isinstance(host, dict) and 'ports' in host:
                for port in host['ports']:
                    if port['service'] in ('https', 'ssl') and port['state'] == 'open':
                        https_services.append({
                            'host': host['host'],
                            'port': port['port']
                        })
        
        if not https_services:
            self.vulnerabilities.append({
                'type': 'https_services',
                'severity': 'info',
                'description': 'No HTTPS services found',
                'remediation': 'None required'
            })
            return self.vulnerabilities
        
        # Test each HTTPS service
        for service in https_services:
            service_vulns = self._test_https_service(service['host'], service['port'])
            self.vulnerabilities.extend(service_vulns)
        
        return self.vulnerabilities
    
    def _test_https_service(self, host, port):
        """Test an HTTPS service for various vulnerabilities"""
        vulnerabilities = []
        
        # Test 1: Certificate validation
        cert_vulns = self._test_certificate_validation(host, port)
        vulnerabilities.extend(cert_vulns)
        
        # Test 2: HTTP Strict Transport Security
        hsts_vulns = self._test_hsts(host, port)
        vulnerabilities.extend(hsts_vulns)
        
        # Test 3: SSL/TLS protocol support
        ssl_vulns = self._test_ssl_protocols(host, port)
        vulnerabilities.extend(ssl_vulns)
        
        # Test 4: Mixed content
        mixed_vulns = self._test_mixed_content(host, port)
        vulnerabilities.extend(mixed_vulns)
        
        return vulnerabilities
    
    def _test_certificate_validation(self, host, port):
        """Test for certificate validation vulnerabilities"""
        vulnerabilities = []
        
        try:
            # First get the real certificate
            real_cert = self._get_certificate(host, port)
            
            # Now try with a fake certificate
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            context.set_verify(OpenSSL.SSL.VERIFY_NONE, None)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = OpenSSL.SSL.Connection(context, sock)
            ssl_sock.connect((host, port))
            ssl_sock.do_handshake()
            fake_cert = ssl_sock.get_peer_certificate()
            ssl_sock.close()
            
            # If we got this far, server accepted our connection without proper validation
            vulnerabilities.append({
                'host': f"{host}:{port}",
                'type': 'certificate_validation',
                'severity': 'high',
                'description': 'Server accepts invalid SSL certificates',
                'remediation': 'Implement strict certificate validation'
            })
            
        except Exception as e:
            # Connection failed - server likely validates certificates properly
            pass
        
        # Check certificate expiration
        try:
            cert = self._get_certificate(host, port)
            expiry_date = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            if expiry_date < datetime.now():
                vulnerabilities.append({
                    'host': f"{host}:{port}",
                    'type': 'certificate_expired',
                    'severity': 'high',
                    'description': f'SSL certificate expired on {expiry_date}',
                    'remediation': 'Renew SSL certificate immediately'
                })
        except:
            pass
        
        return vulnerabilities
    
    def _test_hsts(self, host, port):
        """Test for HSTS implementation"""
        vulnerabilities = []
        
        try:
            url = f"https://{host}:{port}"
            response = self.session.head(url, allow_redirects=True)
            
            if 'strict-transport-security' not in response.headers:
                vulnerabilities.append({
                    'host': f"{host}:{port}",
                    'type': 'hsts_missing',
                    'severity': 'medium',
                    'description': 'HTTP Strict Transport Security header missing',
                    'remediation': 'Implement HSTS with appropriate max-age and includeSubDomains'
                })
            else:
                hsts_header = response.headers['strict-transport-security']
                if 'max-age=0' in hsts_header:
                    vulnerabilities.append({
                        'host': f"{host}:{port}",
                        'type': 'hsts_disabled',
                        'severity': 'high',
                        'description': 'HSTS is disabled (max-age=0)',
                        'remediation': 'Set appropriate max-age value (e.g., 63072000 for 2 years)'
                    })
        except:
            pass
        
        return vulnerabilities
    
    def _test_ssl_protocols(self, host, port):
        """Test for weak SSL/TLS protocols and ciphers"""
        vulnerabilities = []
        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        
        for protocol in weak_protocols:
            try:
                context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{protocol}"))
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # If we get here, the protocol is supported
                        vulnerabilities.append({
                            'host': f"{host}:{port}",
                            'type': 'weak_ssl_protocol',
                            'severity': 'high',
                            'description': f'Server supports weak {protocol} protocol',
                            'remediation': f'Disable {protocol} in server configuration'
                        })
            except:
                pass
        
        return vulnerabilities
    
    def _test_mixed_content(self, host, port):
        """Test for mixed content vulnerabilities"""
        vulnerabilities = []
        
        try:
            url = f"https://{host}:{port}"
            response = self.session.get(url)
            
            if '<iframe ' in response.text and 'http://' in response.text:
                vulnerabilities.append({
                    'host': f"{host}:{port}",
                    'type': 'mixed_content',
                    'severity': 'medium',
                    'description': 'Mixed content (HTTP resources in HTTPS page) detected',
                    'remediation': 'Ensure all resources are loaded via HTTPS'
                })
        except:
            pass
        
        return vulnerabilities
    
    def _get_certificate(self, host, port):
        """Get the server's SSL certificate"""
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        context.set_verify(OpenSSL.SSL.VERIFY_PEER, None)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = OpenSSL.SSL.Connection(context, sock)
        ssl_sock.connect((host, port))
        ssl_sock.do_handshake()
        cert = ssl_sock.get_peer_certificate()
        ssl_sock.close()
        
        return cert
