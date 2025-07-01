import dns.resolver
import dns.message
import dns.query
import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import random
import time

class DNSImpersonationDetector:
    def __init__(self, hosts, interface=None):
        self.hosts = hosts
        self.interface = interface
        self.vulnerabilities = []
        self.dns_servers = []
    
    def check_dns_impersonation(self):
        """Check for DNS spoofing vulnerabilities"""
        print("[*] Checking for DNS impersonation vulnerabilities...")
        
        # Identify DNS servers first
        self._identify_dns_servers()
        
        if not self.dns_servers:
            self.vulnerabilities.append({
                'type': 'dns_server_discovery',
                'severity': 'medium',
                'description': 'No DNS servers discovered on the network',
                'remediation': 'Ensure DNS service is properly configured'
            })
            return self.vulnerabilities
        
        # Test each DNS server
        for server in self.dns_servers:
            server_vulns = self._test_dns_server(server)
            self.vulnerabilities.extend(server_vulns)
        
        return self.vulnerabilities
    
    def _identify_dns_servers(self):
        """Identify DNS servers in the network"""
        # Check common DNS ports (53)
        for host in self.hosts:
            try:
                # Try standard DNS query
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [host]
                resolver.timeout = 2
                resolver.lifetime = 2
                
                try:
                    resolver.query("example.com", "A")
                    self.dns_servers.append(host)
                    continue
                except:
                    pass
                
                # Try TCP DNS query
                try:
                    query = dns.message.make_query("example.com", dns.rdatatype.A)
                    response = dns.query.tcp(query, host, timeout=2)
                    if response:
                        self.dns_servers.append(host)
                except:
                    pass
                
            except Exception as e:
                print(f"[-] DNS check failed for {host}: {str(e)}")
    
    def _test_dns_server(self, server_ip):
        """Test a DNS server for various vulnerabilities"""
        vulnerabilities = []
        
        # Test 1: Check for DNSSEC support
        if not self._check_dnssec(server_ip):
            vulnerabilities.append({
                'host': server_ip,
                'type': 'dnssec_missing',
                'severity': 'medium',
                'description': 'DNSSEC not implemented',
                'remediation': 'Implement DNSSEC for DNS records'
            })
        
        # Test 2: Check for cache poisoning vulnerability
        if self._test_cache_poisoning(server_ip):
            vulnerabilities.append({
                'host': server_ip,
                'type': 'dns_cache_poisoning',
                'severity': 'high',
                'description': 'DNS server vulnerable to cache poisoning',
                'remediation': 'Implement DNS transaction ID randomization and port randomization'
            })
        
        # Test 3: Check for recursive queries
        if self._test_recursive_queries(server_ip):
            vulnerabilities.append({
                'host': server_ip,
                'type': 'dns_recursion_allowed',
                'severity': 'medium',
                'description': 'DNS server allows recursive queries from external clients',
                'remediation': 'Restrict recursive queries to authorized clients only'
            })
        
        return vulnerabilities
    
    def _check_dnssec(self, server_ip):
        """Check if DNS server supports DNSSEC"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server_ip]
            resolver.timeout = 2
            
            # Check a known DNSSEC-signed domain
            answer = resolver.query("dnssec-failed.org", "A")
            for rrset in answer.response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    return True
            return False
        except:
            return False
    
    def _test_cache_poisoning(self, server_ip):
        """Test if DNS server is vulnerable to cache poisoning"""
        # Generate random subdomain to test
        test_domain = f"{random.randint(100000, 999999)}.example.com"
        
        # Send legitimate query first
        legit_pkt = IP(dst=server_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=test_domain))
        send(legit_pkt, verbose=0)
        
        # Now send spoofed response with fake transaction ID
        spoofed_pkt = IP(src=server_ip, dst=server_ip)/UDP(sport=53, dport=53)/DNS(
            id=1234,  # Fixed transaction ID
            qr=1,     # Response
            qd=DNSQR(qname=test_domain),
            an=DNSRR(rrname=test_domain, type="A", rdata="1.2.3.4", ttl=3600)
        )
        send(spoofed_pkt, verbose=0)
        
        # Check if the fake response was cached
        time.sleep(1)
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server_ip]
            resolver.timeout = 2
            answer = resolver.query(test_domain, "A")
            for rr in answer:
                if rr.address == "1.2.3.4":
                    return True
        except:
            pass
        
        return False
    
    def _test_recursive_queries(self, server_ip):
        """Test if DNS server allows recursive queries"""
        try:
            query = dns.message.make_query("google.com", dns.rdatatype.A)
            response = dns.query.udp(query, server_ip, timeout=2)
            
            # If we get an answer, recursion is allowed
            if response.answer:
                return True
            
            # Check if recursion available flag is set
            return response.flags & dns.flags.RA != 0
        except:
            return False
