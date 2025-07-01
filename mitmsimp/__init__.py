__version__ = "0.2.0"
__author__ = "NZRXHX"

from .core.scanner import NetworkScanner
from .core.analyzer import VulnerabilityAnalyzer
from .core.reporter import ReportGenerator

# Import all modules to ensure they're registered
from .modules import (
    ssl_stripping,
    https_capture,
    tcp_hijacking,
    dns_impersonation,
    arp_spoofing,
    dhcp_starvation
)

__all__ = [
    'NetworkScanner',
    'VulnerabilityAnalyzer',
    'ReportGenerator'
]
