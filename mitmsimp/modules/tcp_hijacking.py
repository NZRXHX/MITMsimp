from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import time
from ..utils.network_utils import get_if_hwaddr

class TCPHijackingDetector:
    def __init__(self, hosts, interface=None):
        self.hosts = hosts
        self.interface = interface
        self.vulnerabilities = []
        self.active_connections = {}
    
    def check_tcp_hijacking(self):
        """Check for TCP hijacking vulnerabilities"""
        print("[*] Checking for TCP hijacking vulnerabilities...")
        
        # First, identify active TCP connections
        self._sniff_tcp_connections()
        
        if not self.active_connections:
            self.vulnerabilities.append({
                'type': 'tcp_connections',
                'severity': 'info',
                'description': 'No active TCP connections observed',
                'remediation': 'None required'
            })
            return self.vulnerabilities
        
        # Test each connection for hijacking vulnerability
        for conn_id, conn in self.active_connections.items():
            if self._test_tcp_sequence_prediction(conn):
                self.vulnerabilities.append({
                    'host': f"{conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}",
                    'type': 'tcp_hijacking',
                    'severity': 'high',
                    'description': 'TCP connection vulnerable to sequence number prediction',
                    'remediation': 'Enable TCP sequence number randomization'
                })
        
        return self.vulnerabilities
    
    def _sniff_tcp_connections(self):
        """Sniff for active TCP connections"""
        print("[*] Sniffing for TCP connections...")
        
        def packet_callback(pkt):
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                
                # Create connection identifier (bidirectional)
                conn_id = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))
                
                if pkt[TCP].flags & 0x02:  # SYN flag
                    # New connection
                    self.active_connections[conn_id] = {
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'seq': pkt[TCP].seq,
                        'last_seen': time.time()
                    }
                elif pkt[TCP].flags & 0x10:  # ACK flag
                    # Existing connection
                    if conn_id in self.active_connections:
                        self.active_connections[conn_id]['last_seen'] = time.time()
                        self.active_connections[conn_id]['seq'] = pkt[TCP].seq
        
        # Sniff for 10 seconds
        sniff(prn=packet_callback, timeout=10, filter="tcp", 
              iface=self.interface, store=0)
        
        # Remove stale connections
        current_time = time.time()
        stale_conns = [k for k, v in self.active_connections.items() 
                      if current_time - v['last_seen'] > 5]
        for k in stale_conns:
            del self.active_connections[k]
    
    def _test_tcp_sequence_prediction(self, conn):
        """Test if TCP connection is vulnerable to sequence prediction"""
        print(f"[*] Testing TCP connection {conn['src_ip']}:{conn['src_port']} -> "
              f"{conn['dst_ip']}:{conn['dst_port']}")
        
        # Craft fake packet with predicted sequence number
        predicted_seq = conn['seq'] + 100  # Simple prediction
        
        ip_layer = IP(src=conn['src_ip'], dst=conn['dst_ip'])
        tcp_layer = TCP(sport=conn['src_port'], dport=conn['dst_port'],
                       seq=predicted_seq, flags="A")
        fake_pkt = ip_layer/tcp_layer/"TEST"
        
        # Send the fake packet
        send(fake_pkt, verbose=0)
        
        # Sniff for RST response (indicates our packet was accepted)
        def response_callback(pkt):
            if (IP in pkt and TCP in pkt and
                pkt[IP].src == conn['dst_ip'] and
                pkt[IP].dst == conn['src_ip'] and
                pkt[TCP].sport == conn['dst_port'] and
                pkt[TCP].dport == conn['src_port'] and
                pkt[TCP].flags & 0x04):  # RST flag
                return True
            return False
        
        # Wait for response
        response = sniff(count=1, timeout=2, filter=f"tcp and host {conn['dst_ip']}",
                        iface=self.interface, stop_filter=response_callback)
        
        return bool(response)  # Vulnerable if we got a RST response
