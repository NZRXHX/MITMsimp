#  NZRXHX MITMsimp - Automated MITM Weak Point Detection Tool

MITMsimp is an offensive network penetration testing tool designed to automatically detect all possible Man-in-the-Middle (MITM) attack vectors in a network. Unlike comprehensive pentest tools, MITMsimp focuses specifically on identifying vulnerabilities that could lead to MITM attacks.

## Features

- **Comprehensive Network Scanning**:
  - ARP spoofing detection
  - DHCP starvation testing
  - DNS impersonation checks
  - TCP hijacking vulnerability assessment

- **SSL/TLS Analysis**:
  - SSL stripping detection
  - HTTPS interception points
  - Certificate validation testing
  - Mixed content detection

- **Advanced Detection**:
  - Passive traffic analysis
  - Protocol vulnerability assessment
  - Service-specific testing
  - Network topology mapping

## Installation

### Prerequisites
- Python 3.8+
- Root/Administrative privileges (for raw socket operations)
- Nmap (for comprehensive scanning)

### Installation Options
```bash
git clone https://github.com/NZRXHX/MITMsimp.git
cd MITMsimp
pip install -r requirements.txt
sudo python setup.py install
```
Usage
Basic Scan
```bash
sudo mitmsimp --target 192.168.1.0/24 --output report.html
```
Advanced Options
```bash
sudo mitmsimp \
  --target 10.0.0.1-100 \
  --interface eth0 \
  --scan-depth aggressive \
  --output /reports/network_scan_$(date +%Y%m%d).html
```
Command Line Arguments
```bash
  -h, --help            show help message and exit
  --target TARGET       Target IP range (e.g., 192.168.1.0/24 or 10.0.0.1-100)
  --interface INTERFACE Network interface to use
  --scan-depth {quick,standard,aggressive}
                        Scan intensity level
  --output OUTPUT       Output file path (supports .html, .json, .txt)
  --quiet               Suppress console output
  --no-open             Don't automatically open HTML report
```
