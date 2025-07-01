from colorama import Fore, Style

def format_vulnerability(vuln):
    """Format vulnerability for console output"""
    color = {
        'critical': Fore.RED,
        'high': Fore.YELLOW,
        'medium': Fore.BLUE,
        'low': Fore.GREEN
    }.get(vuln['severity'].lower(), Fore.WHITE)
    
    return (
        f"{color}[{vuln['severity'].upper()}]{Style.RESET_ALL} "
        f"{vuln['host']} - {vuln['type']}\n"
        f"  Description: {vuln['description']}\n"
        f"  Remediation: {vuln['remediation']}"
    )

def format_scan_result(result):
    """Format scan result for console output"""
    # THIS WAS PART OF AN OLDER VERSION, the new result formatter is at /mitmsimp/core/reporter.py
    pass
