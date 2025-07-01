# MITMsimp Design Document

## Architecture Overview

MITMsimp follows a modular architecture with three main components:

1. **Scanner**: Discovers network topology and active hosts
2. **Analyzer**: Checks each host for specific MITM vulnerabilities
3. **Reporter**: Generates comprehensive reports in multiple formats

## Core Modules

### Network Scanner
- Uses Nmap for initial discovery
- Identifies active hosts, open ports, services
- Maps network topology

### Vulnerability Detectors
- SSL Stripping: Checks for HTTPS downgrade opportunities
- HTTPS Capture: Identifies interceptable HTTPS traffic
- TCP Hijacking: Detects predictable sequence numbers
- DNS Impersonation: Checks DNS security configurations
- ARP Spoofing: Verifies ARP security mechanisms
- DHCP Starvation: Checks DHCP server vulnerabilities

### Reporting Engine
- Generates human-readable HTML reports
- Provides machine-readable JSON output
- Includes severity ratings and remediation advice
