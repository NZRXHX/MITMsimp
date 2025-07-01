import netifaces
import socket
import psutil

def get_network_interfaces():
    """Get all active network interfaces"""
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        if any(addr.family == socket.AF_INET for addr in addrs):
            interfaces.append(interface)
    return interfaces

def get_default_gateway():
    """Get the default gateway IP"""
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]
