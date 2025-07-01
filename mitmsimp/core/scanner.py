def _capture_initial_traffic(self):
    """Capture initial traffic patterns for analysis"""
    print("[*] Capturing initial traffic patterns...")
    sniff_timeout = 15
    
    def packet_callback(pkt):
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = 'TCP' if TCP in pkt else 'UDP'
            port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            
            # Record traffic patterns
            self.results.setdefault('traffic', {}).setdefault(src, {}).setdefault(dst, {
                'protocols': set(),
                'ports': set()
            })
            self.results['traffic'][src][dst]['protocols'].add(proto)
            self.results['traffic'][src][dst]['ports'].add(port)
    
    print(f"[*] Sniffing traffic for {sniff_timeout} seconds...")
    sniff(iface=self.interface, prn=packet_callback, timeout=sniff_timeout)
    
    # Convert sets to lists for JSON serialization
    for src in self.results.get('traffic', {}):
        for dst in self.results['traffic'][src]:
            self.results['traffic'][src][dst]['protocols'] = list(self.results['traffic'][src][dst]['protocols'])
            self.results['traffic'][src][dst]['ports'] = list(self.results['traffic'][src][dst]['ports'])
