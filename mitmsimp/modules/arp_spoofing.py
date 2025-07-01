from scapy.all import *
from scapy.layers.l2 import ARP, Ether, getmacbyip
import time
import netifaces
from ..utils.network_utils import get_default_gateway

class ARPSpoofingDetector:
    def __init__(self, hosts, interface=None):
        self.hosts = hosts
        self.interface = interface or netifaces.gateways()['default'][netifaces.AF_INET][1]
        self.gateway = get_default_gateway()
        self.vulnerabilities = []
        self.mac_cache = {}
    
    def check_arp_spoofing(self):
        """Check for ARP spoofing vulnerabilities"""
        print("[*] Checking for ARP spoofing vulnerabilities...")
        
        # Get gateway MAC address
        try:
            gw_mac = getmacbyip(self.gateway)
            if gw_mac is None:
                raise Exception("Could not resolve gateway MAC")
            self.mac_cache[self.gateway] = gw_mac
        except Exception as e:
            self.vulnerabilities.append({
                'host': self.gateway,
                'type': 'arp_gateway_unreachable',
                'severity': 'critical',
                'description': f'Could not resolve gateway MAC: {str(e)}',
                'remediation': 'Check network connectivity to gateway'
            })
            return self.vulnerabilities
        
        # Test each host
        for host in self.hosts:
            if host == self.gateway:
                continue
                
            try:
                host_mac = getmacbyip(host)
                if host_mac is None:
                    raise Exception("Could not resolve host MAC")
                self.mac_cache[host] = host_mac
                
                # Test 1: Check if host accepts gratuitous ARP
                if self._test_gratuitous_arp(host, host_mac):
                    self.vulnerabilities.append({
                        'host': host,
                        'type': 'arp_spoofing',
                        'severity': 'high',
                        'description': 'Host accepts gratuitous ARP packets',
                        'remediation': 'Enable ARP inspection or use static ARP entries'
                    })
                
                # Test 2: Check for ARP cache poisoning
                if self._test_arp_cache_poisoning(host, host_mac):
                    self.vulnerabilities.append({
                        'host': host,
                        'type': 'arp_cache_poisoning',
                        'severity': 'high',
                        'description': 'Host ARP cache can be poisoned',
                        'remediation': 'Enable ARP inspection or use static ARP entries'
                    })
                
            except Exception as e:
                self.vulnerabilities.append({
                    'host': host,
                    'type': 'arp_test_failed',
                    'severity': 'medium',
                    'description': f'ARP test failed: {str(e)}',
                    'remediation': 'Check host connectivity'
                })
        
        return self.vulnerabilities
    
    def _test_gratuitous_arp(self, target_ip, target_mac):
        """Test if target accepts gratuitous ARP packets"""
        # Send fake ARP announcement claiming gateway IP has our MAC
        our_mac = get_if_hwaddr(self.interface)
        pkt = Ether(src=our_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(
            op=2, psrc=self.gateway, hwsrc=our_mac, pdst=target_ip)
        
        sendp(pkt, iface=self.interface, verbose=0)
        time.sleep(1)
        
        # Check if target now associates gateway IP with our MAC
        ans = srp1(Ether(dst=target_mac)/ARP(pdst=target_ip, psrc=self.gateway),
                  timeout=2, iface=self.interface, verbose=0)
        
        return ans and ans.hwsrc == our_mac
    
    def _test_arp_cache_poisoning(self, target_ip, target_mac):
        """Test if target's ARP cache can be poisoned"""
        # Send fake ARP reply claiming gateway IP has our MAC
        our_mac = get_if_hwaddr(self.interface)
        pkt = Ether(src=our_mac, dst=target_mac)/ARP(
            op=2, psrc=self.gateway, hwsrc=our_mac, pdst=target_ip)
        
        sendp(pkt, iface=self.interface, verbose=0)
        time.sleep(1)
        
        # Check if target now associates gateway IP with our MAC
        ans = srp1(Ether(dst=target_mac)/ARP(pdst=target_ip, psrc=self.gateway),
                  timeout=2, iface=self.interface, verbose=0)
        
        return ans and ans.hwsrc == our_mac
