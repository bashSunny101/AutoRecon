#!/usr/bin/env python3
"""
PORT SCANNING MODULE
====================

Purpose: Discover open ports and identify running services on live hosts

Security Concept:
- Ports are entry points to services running on a host
- Each open port represents a potential attack vector
- Service versions may have known vulnerabilities (CVEs)
- Misconfigurations (exposed databases, admin panels) are common

Technique: TCP Port Scanning with Service Detection
- Probe common ports to check if they're open
- Identify service name and version (e.g., "Apache 2.4.41")
- Map the attack surface for each target
- Tool used: Nmap (industry-standard network scanner)

Why This Phase is Critical:
- Reveals what services are accessible on each host
- Identifies outdated/vulnerable software versions
- Finds misconfigured services (databases exposed to internet)
- Discovers hidden admin panels and development interfaces
- Prioritizes targets based on exposed services

Legal Warning:
- Port scanning without authorization may be ILLEGAL
- Only scan systems you own or have explicit permission to test
- Respect bug bounty program scope and rules
- Aggressive scanning can be detected and result in IP bans

Author: Sunny Pal
Date: January 2026
"""

import subprocess
import os
import sys
import re
from urllib.parse import urlparse

# Color codes for output
class Colors:
    """ANSI color codes for professional terminal output"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'


def print_banner():
    """Display module banner"""
    banner = f"""
{Colors.MAGENTA}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║         PORT SCANNING MODULE                 ║
║    Service Discovery & Version Detection     ║
╚══════════════════════════════════════════════╝
{Colors.RESET}
{Colors.RED}⚠️  WARNING: Only scan authorized targets!{Colors.RESET}
    """
    print(banner)


def check_live_hosts_file(live_hosts_file):
    """
    Verify live hosts file exists and contains data
    
    Args:
        live_hosts_file (str): Path to live hosts file
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not os.path.exists(live_hosts_file):
        print(f"{Colors.RED}[!] Error: Live hosts file not found: {live_hosts_file}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Run live host detection first!{Colors.RESET}")
        return False
    
    if os.path.getsize(live_hosts_file) == 0:
        print(f"{Colors.RED}[!] Error: Live hosts file is empty{Colors.RESET}")
        return False
    
    return True


def extract_hosts_from_urls(live_hosts_file):
    """
    Extract hostnames/IPs from URLs in live hosts file
    
    Args:
        live_hosts_file (str): Path to file containing URLs
    
    Returns:
        list: List of hostnames without protocol/path
    
    Why we need this:
        Nmap expects hostnames, not full URLs
        - Input: "https://api.example.com/path"
        - Output: "api.example.com"
    
    URL Parsing:
        urlparse() breaks down URLs into components:
        - scheme: https
        - netloc: api.example.com
        - path: /path
    """
    hosts = []
    
    try:
        with open(live_hosts_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Parse URL to extract hostname
            # Example: "https://api.example.com" -> "api.example.com"
            if line.startswith('http://') or line.startswith('https://'):
                parsed = urlparse(line)
                hostname = parsed.netloc
            else:
                # If no protocol, assume it's already just a hostname
                hostname = line.split()[0]  # Take first part (ignore status codes if present)
            
            if hostname and hostname not in hosts:
                hosts.append(hostname)
        
        return hosts
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading live hosts file: {e}{Colors.RESET}")
        return []


def run_nmap_scan(target, output_file):
    """
    Execute Nmap scan on a single target
    
    Args:
        target (str): Hostname or IP to scan
        output_file (str): File to save scan results
    
    Returns:
        bool: True if successful, False otherwise
    
    Nmap Command Breakdown:
        nmap -sV -T3 --top-ports 1000 -oN output.txt target
        
        -sV              : Service version detection (identifies software versions)
        -T3              : Timing template (0=paranoid, 3=normal, 5=insane)
                           T3 = reasonable speed without being aggressive
        --top-ports 1000 : Scan the 1000 most common ports (vs all 65,535)
                           Covers 99% of services while being much faster
        -oN              : Normal output format (human-readable)
        target           : The hostname/IP to scan
    
    Why these flags?
        - Beginner-friendly: Not overly aggressive
        - Professional: Gets useful information (versions)
        - Efficient: 1000 ports is a good balance
        - Safe: T3 timing won't trigger most IDS/IPS systems
    
    Alternative flags (for your learning):
        -sS              : SYN scan (stealthier, requires sudo)
        -sC              : Run default scripts (more info, but slower)
        -p-              : Scan ALL 65,535 ports (VERY slow, use carefully)
        -A               : Aggressive scan (OS detection, scripts, traceroute)
        -T4              : Faster timing (more detectable)
        --script=vuln    : Run vulnerability detection scripts
    """
    print(f"{Colors.YELLOW}[*] Scanning {target}...{Colors.RESET}")
    
    # Build nmap command
    # Note: Using -Pn to skip host discovery (we already know it's alive)
    command = [
        "nmap",
        "-sV",                  # Service version detection
        "-T3",                  # Normal timing
        "--top-ports", "1000",  # Scan top 1000 ports
        "-Pn",                  # Skip ping (we know host is alive)
        "-oN", output_file,     # Save output
        target
    ]
    
    try:
        # Run nmap
        # Note: This can take 30-60 seconds per host
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per host
        )
        
        # Nmap returns 0 even if ports are closed, so check if output file was created
        if os.path.exists(output_file):
            return True
        else:
            print(f"{Colors.RED}[!] Nmap failed to create output file{Colors.RESET}")
            return False
        
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}[!] Nmap scan timed out for {target}{Colors.RESET}")
        return False
        
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Nmap not found!{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Install it with: sudo apt install nmap{Colors.RESET}")
        return False
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error running nmap: {e}{Colors.RESET}")
        return False


def parse_nmap_output(output_file):
    """
    Parse nmap output to extract key information
    
    Args:
        output_file (str): Path to nmap output file
    
    Returns:
        dict: Parsed scan results with open ports and services
    
    What we extract:
        - Open ports (22, 80, 443, etc.)
        - Service names (ssh, http, https)
        - Service versions (OpenSSH 7.4, Apache 2.4.41)
        - Interesting findings (exposed databases, admin panels)
    """
    results = {
        'open_ports': [],
        'services': {},
        'total_open': 0
    }
    
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        # Regex to match open ports in nmap output
        # Example line: "22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)"
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)'
        
        for match in re.finditer(port_pattern, content):
            port = match.group(1)
            service = match.group(2)
            version = match.group(3).strip()
            
            results['open_ports'].append(port)
            results['services'][port] = {
                'service': service,
                'version': version
            }
        
        results['total_open'] = len(results['open_ports'])
        
        return results
        
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not parse nmap output: {e}{Colors.RESET}")
        return results


def display_scan_results(target, results):
    """
    Display formatted scan results with security analysis
    
    Args:
        target (str): Scanned hostname
        results (dict): Parsed nmap results
    
    Security Analysis:
        We highlight potentially dangerous findings:
        - Exposed databases (3306, 5432, 27017)
        - SSH on non-standard ports (possible backdoor)
        - Development servers (3000, 5000, 8000)
        - Admin panels (8080, 9090, 10000)
    """
    if results['total_open'] == 0:
        print(f"{Colors.YELLOW}[*] No open ports found on {target}{Colors.RESET}")
        print(f"{Colors.YELLOW}    (This could mean heavy firewall filtering){Colors.RESET}\n")
        return
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] {target} - {results['total_open']} open ports:{Colors.RESET}\n")
    
    # Define interesting ports with security implications
    interesting_ports = {
        '22': ('SSH', 'Check for weak credentials, outdated versions'),
        '21': ('FTP', '⚠️  Often allows anonymous login, unencrypted'),
        '23': ('Telnet', '🚨 CRITICAL: Unencrypted, should never be exposed'),
        '25': ('SMTP', 'Email server, check for open relay'),
        '80': ('HTTP', 'Web server (unencrypted)'),
        '443': ('HTTPS', 'Web server (encrypted)'),
        '3306': ('MySQL', '🚨 CRITICAL: Database should not be exposed!'),
        '5432': ('PostgreSQL', '🚨 CRITICAL: Database should not be exposed!'),
        '27017': ('MongoDB', '🚨 CRITICAL: Database should not be exposed!'),
        '6379': ('Redis', '⚠️  Cache server, often no auth'),
        '8080': ('HTTP-Proxy', 'Alternative HTTP, often admin panels'),
        '8443': ('HTTPS-Alt', 'Alternative HTTPS, less monitored'),
        '3000': ('Dev Server', '⚠️  Development server, should not be public'),
        '5000': ('Flask/Python', '⚠️  Development server, debug mode?'),
        '8000': ('Django/Alt-HTTP', '⚠️  Development server'),
        '9090': ('Cockpit', 'Admin panel'),
        '10000': ('Webmin', 'Admin panel')
    }
    
    critical_findings = []
    warnings = []
    
    for port in results['open_ports']:
        service_info = results['services'].get(port, {})
        service = service_info.get('service', 'unknown')
        version = service_info.get('version', '')
        
        # Format output
        port_line = f"    Port {port:6s} | {service:15s}"
        if version:
            port_line += f" | {version}"
        
        # Check if this is an interesting/dangerous port
        if port in interesting_ports:
            port_name, security_note = interesting_ports[port]
            port_line += f"\n                 └─ {security_note}"
            
            # Categorize findings
            if '🚨' in security_note:
                critical_findings.append(f"Port {port} ({port_name})")
            elif '⚠️' in security_note:
                warnings.append(f"Port {port} ({port_name})")
        
        print(port_line)
    
    # Display security summary
    if critical_findings:
        print(f"\n{Colors.RED}{Colors.BOLD}🚨 CRITICAL FINDINGS:{Colors.RESET}")
        for finding in critical_findings:
            print(f"    • {finding}")
    
    if warnings:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  WARNINGS:{Colors.RESET}")
        for warning in warnings:
            print(f"    • {warning}")
    
    print()  # Blank line for spacing


def scan_ports(domain, live_hosts_file=None):
    """
    Main orchestration function for port scanning
    
    Args:
        domain (str): Target domain
        live_hosts_file (str, optional): Path to live hosts file
    
    Returns:
        str: Path to directory containing scan results
    
    Workflow:
        1. Load live hosts from file
        2. Extract clean hostnames
        3. Scan each host with nmap
        4. Parse and display results
        5. Save comprehensive report
    """
    print_banner()
    
    # Determine live hosts file path
    if live_hosts_file is None:
        live_hosts_file = os.path.join("output", domain, "live_hosts_clean.txt")
    
    # Check if file exists
    if not check_live_hosts_file(live_hosts_file):
        return None
    
    # Extract hostnames
    hosts = extract_hosts_from_urls(live_hosts_file)
    
    if not hosts:
        print(f"{Colors.RED}[!] No hosts to scan{Colors.RESET}")
        return None
    
    print(f"{Colors.CYAN}[*] Loaded {len(hosts)} hosts to scan{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Scanning top 1000 ports per host...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Estimated time: {len(hosts) * 1} - {len(hosts) * 2} minutes{Colors.RESET}\n")
    
    # Create output directory for scans
    output_dir = os.path.join("output", domain, "port_scans")
    os.makedirs(output_dir, exist_ok=True)
    
    # Scan each host
    scan_count = 0
    for i, host in enumerate(hosts, 1):
        print(f"{Colors.CYAN}[{i}/{len(hosts)}]{Colors.RESET} ", end='')
        
        # Create safe filename from hostname
        safe_filename = host.replace('/', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f"{safe_filename}.txt")
        
        # Run scan
        success = run_nmap_scan(host, output_file)
        
        if success:
            scan_count += 1
            # Parse and display results
            results = parse_nmap_output(output_file)
            display_scan_results(host, results)
        else:
            print(f"{Colors.RED}[!] Scan failed for {host}{Colors.RESET}\n")
    
    # Summary
    print(f"{Colors.GREEN}{Colors.BOLD}{'='*50}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Port scanning complete!{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Successfully scanned: {scan_count}/{len(hosts)} hosts{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Results saved to: {output_dir}/{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}{'='*50}{Colors.RESET}\n")
    
    return output_dir


# Standalone execution
if __name__ == "__main__":
    """
    Standalone script usage:
        python3 port_scan.py <domain> [live_hosts_file]
    
    Examples:
        python3 port_scan.py example.com
        python3 port_scan.py example.com output/example.com/live_hosts_clean.txt
    """
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python3 {sys.argv[0]} <domain> [live_hosts_file]{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} example.com{Colors.RESET}")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    live_hosts_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    scan_ports(target_domain, live_hosts_file)
