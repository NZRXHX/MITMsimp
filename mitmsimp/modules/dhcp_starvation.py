from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import random
import time
from ..utils.network_utils import get_if_hwaddr

class DHCPStarvationDetector:
    def __init__(self, interface=None, timeout=10):
        self.interface = interface
        self.timeout = timeout
        self.vulnerabilities = []
        self.dhcp_servers = set()
    
    def check_dhcp_starvation(self):
        """Check for DHCP starvation vulnerabilities"""
        print("[*] Checking for DHCP starvation vulnerabilities...")
        
        # First, identify DHCP servers
        self._discover_dhcp_servers()
        
        if not self.dhcp_servers:
            self.vulnerabilities.append({
                'type': 'dhcp_server_discovery',
                'severity': 'medium',
                'description': 'No DHCP servers discovered on the network',
                'remediation': 'Ensure DHCP service is running if required'
            })
            return self.vulnerabilities
        
        # Test each DHCP server
        for server in self.dhcp_servers:
            if self._test_dhcp_starvation(server):
                self.vulnerabilities.append({
                    'host': server,
                    'type': 'dhcp_starvation',
                    'severity': 'high',
                    'description': 'DHCP server vulnerable to starvation attacks',
                    'remediation': 'Implement DHCP snooping or limit lease requests'
                })
        
        return self.vulnerabilities
    
    def _discover_dhcp_servers(self):
        """Discover DHCP servers on the network"""
        # Send DHCP discover packet
        hwaddr = get_if_hwaddr(self.interface)
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=hwaddr) / \
                       IP(src="0.0.0.0", dst="255.255.255.255") / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=hwaddr) / \
                       DHCP(options=[("message-type", "discover"), "end"])
        
        # Sniff for DHCP offers
        def handle_packet(pkt):
            if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # DHCP Offer
                server_ip = pkt[IP].src
                self.dhcp_servers.add(server_ip)
        
        print("[*] Discovering DHCP servers...")
        sniff(prn=handle_packet, timeout=self.timeout, filter="udp and (port 67 or 68)",
              iface=self.interface, store=0)
    
    def _test_dhcp_starvation(self, server_ip):
        """Test if DHCP server is vulnerable to starvation"""
        print(f"[*] Testing DHCP server {server_ip} for starvation vulnerability")
        
        try:
            # Try to exhaust the DHCP pool with 10 requests
            for i in range(10):
                mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / \
                             IP(src="0.0.0.0", dst="255.255.255.255") / \
                             UDP(sport=68, dport=67) / \
                             BOOTP(chaddr=mac) / \
                             DHCP(options=[("message-type", "request"), 
                                         ("requested_addr", f"192.168.1.{100+i}"),
                                         "end"])
                
                sendp(dhcp_request, iface=self.interface, verbose=0)
                time.sleep(0.5)
            
            # Check if server still responds to new requests
            test_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
            test_dhcp = Ether(dst="ff:ff:ff:ff:ff:ff", src=test_mac) / \
                       IP(src="0.0.0.0", dst="255.255.255.255") / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=test_mac) / \
                       DHCP(options=[("message-type", "discover"), "end"])
            
            # Sniff for response with timeout
            response = None
            def handle_response(pkt):
                nonlocal response
                if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # DHCP Offer
                    response = pkt
            
            sniff(prn=handle_response, timeout=5, filter=f"udp and src host {server_ip} and port 68",
                  iface=self.interface, store=0)
            
            return response is None  # Vulnerable if no response
        
        except Exception as e:
            print(f"[-] DHCP test failed: {str(e)}")
            return False
