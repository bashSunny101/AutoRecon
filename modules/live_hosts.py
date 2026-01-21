#!/usr/bin/env python3
"""
LIVE HOST DETECTION MODULE
==========================

Purpose: Identify which discovered subdomains are actually alive and responding to HTTP/HTTPS

Security Concept:
- Not all discovered subdomains are actively hosting services
- DNS records may exist for decommissioned servers
- Wildcard DNS can create false positives
- Testing thousands of dead hosts wastes time and resources

Technique: HTTP Probing
- Send HTTP/HTTPS requests to each subdomain
- Check for valid responses (200, 301, 302, 403, etc.)
- Filter out non-responsive or dead hosts
- Tool used: Httpx (fast, multi-threaded HTTP probe)

Why This Phase is Critical:
- Reduces noise from dead/inactive hosts
- Focuses reconnaissance on real targets
- Saves time in subsequent scanning phases
- Professional pentesters ALWAYS verify live hosts before deep scanning

Author: Cybersecurity Student
Date: January 2026
"""

import subprocess
import os
import sys

# Import our color codes from the previous module
class Colors:
    """ANSI color codes for terminal output"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'


def print_banner():
    """Display module banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║      LIVE HOST DETECTION MODULE              ║
║      HTTP/HTTPS Probe & Verification         ║
╚══════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)


def check_subdomain_file(subdomain_file):
    """
    Verify that the subdomain file exists and is not empty
    
    Args:
        subdomain_file (str): Path to subdomain list file
    
    Returns:
        bool: True if file is valid, False otherwise
    
    Why this check matters:
        - Prevents running httpx on non-existent data
        - Gives user clear feedback if previous step failed
        - Professional error handling
    """
    if not os.path.exists(subdomain_file):
        print(f"{Colors.RED}[!] Error: Subdomain file not found: {subdomain_file}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Run subdomain enumeration first!{Colors.RESET}")
        return False
    
    # Check if file is empty
    if os.path.getsize(subdomain_file) == 0:
        print(f"{Colors.RED}[!] Error: Subdomain file is empty{Colors.RESET}")
        return False
    
    return True


def run_httpx(subdomain_file, output_file):
    """
    Execute Httpx to probe subdomains for live HTTP/HTTPS services
    
    Args:
        subdomain_file (str): Input file containing subdomains to probe
        output_file (str): Output file for live hosts
    
    Returns:
        bool: True if successful, False otherwise
    
    How Httpx Works:
        - Reads list of domains/subdomains
        - Attempts HTTP and HTTPS connections to each
        - Follows redirects and handles various response codes
        - Filters out non-responsive hosts
        - Multi-threaded for speed (probes many hosts simultaneously)
    
    Command Breakdown:
        httpx -l subdomains.txt -o live_hosts.txt -silent -status-code -title -tech-detect
        
        -l              : List/input file flag
        -o              : Output file flag
        -silent         : Suppress progress bars (cleaner for automation)
        -status-code    : Show HTTP status codes (200, 404, 403, etc.)
        -title          : Extract page titles (helps identify what's hosted)
        -tech-detect    : Detect technologies (WordPress, Apache, etc.)
    
    Professional Tip:
        Real pentesters check status codes to understand host behavior:
        - 200 OK        : Server is up and serving content
        - 301/302       : Redirects (might reveal other infrastructure)
        - 403 Forbidden : Server exists but denies access (still interesting!)
        - 401 Unauth    : Requires authentication (login panel?)
        - 404 Not Found : Server responds but no content (still live!)
    """
    print(f"{Colors.YELLOW}[*] Probing subdomains for live HTTP/HTTPS services...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] This may take 1-3 minutes depending on subdomain count...{Colors.RESET}\n")
    
    # Build command
    command = [
        "httpx",
        "-l", subdomain_file,     # Input: list of subdomains
        "-o", output_file,         # Output: live hosts
        "-silent",                 # Quiet mode
        "-status-code",            # Show HTTP status codes
        "-title",                  # Extract page titles
        "-tech-detect",            # Detect web technologies
        "-follow-redirects",       # Follow HTTP redirects
        "-random-agent",           # Use random User-Agent (more realistic)
        "-threads", "50"           # Use 50 concurrent threads (faster)
    ]
    
    try:
        # Execute httpx
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}[!] Error running Httpx: {e}{Colors.RESET}")
        return False
        
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Httpx not found!{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Install it with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest{Colors.RESET}")
        return False


def parse_and_display_results(output_file):
    """
    Read httpx results and display statistics with analysis
    
    Args:
        output_file (str): Path to httpx output file
    
    What we analyze:
        - Total live hosts found
        - HTTP vs HTTPS distribution
        - Common status codes
        - Technologies detected
    
    Why parsing matters:
        - Quick overview of attack surface
        - Identify interesting targets (admin panels, APIs)
        - Spot patterns (all on HTTPS = good security posture)
    """
    try:
        with open(output_file, 'r') as f:
            live_hosts = f.readlines()
        
        # Clean up the data
        live_hosts = [host.strip() for host in live_hosts if host.strip()]
        
        if not live_hosts:
            print(f"{Colors.YELLOW}[!] No live hosts found{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] This could mean:{Colors.RESET}")
            print(f"    • Subdomains exist in DNS but services are down")
            print(f"    • Network filtering/firewall blocking requests")
            print(f"    • Wildcard DNS creating false subdomain entries")
            return
        
        # Display results
        print(f"{Colors.GREEN}{Colors.BOLD}[+] Found {len(live_hosts)} live hosts:{Colors.RESET}\n")
        
        # Show first 10 live hosts as sample
        print(f"{Colors.CYAN}Sample Live Hosts:{Colors.RESET}")
        for host in live_hosts[:10]:
            print(f"    • {host}")
        
        if len(live_hosts) > 10:
            print(f"\n    ... and {len(live_hosts) - 10} more")
        
        # Count HTTP vs HTTPS
        https_count = sum(1 for host in live_hosts if host.startswith("https://"))
        http_count = sum(1 for host in live_hosts if host.startswith("http://"))
        
        print(f"\n{Colors.CYAN}Protocol Distribution:{Colors.RESET}")
        print(f"    • HTTPS: {https_count} hosts")
        print(f"    • HTTP:  {http_count} hosts")
        
        # Security note
        if http_count > 0:
            print(f"\n{Colors.YELLOW}[*] Security Note:{Colors.RESET}")
            print(f"    {http_count} hosts using HTTP (unencrypted)")
            print(f"    → Potential for man-in-the-middle attacks")
            print(f"    → Credentials/data transmitted in cleartext")
        
        print(f"\n{Colors.GREEN}[+] Results saved to: {output_file}{Colors.RESET}")
        
        # Professional tip
        print(f"\n{Colors.CYAN}[*] Pentester Tip:{Colors.RESET}")
        print(f"    Review the output file to identify:")
        print(f"    • Development/staging environments (dev, test, stg)")
        print(f"    • Admin panels (admin, login, dashboard)")
        print(f"    • API endpoints (api, rest, graphql)")
        print(f"    • Outdated technologies in -tech-detect results")
        
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Output file not found{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading results: {e}{Colors.RESET}")


def extract_clean_urls(output_file, domain):
    """
    Create a clean list of just URLs (without status codes, titles, etc.)
    
    Args:
        output_file (str): Httpx output file with full details
        domain (str): Target domain for naming
    
    Returns:
        str: Path to clean URLs file
    
    Why we need this:
        - Next modules (port scan, URL collector) need clean input
        - Some tools don't handle httpx's verbose output format
        - Separation of concerns: detailed results + clean list
    """
    output_dir = os.path.dirname(output_file)
    clean_file = os.path.join(output_dir, "live_hosts_clean.txt")
    
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
        
        # Extract just the URLs (first part before space/bracket)
        # Httpx format: "https://example.com [200] [Title]"
        urls = []
        for line in lines:
            line = line.strip()
            if line:
                # Split and take first part (the URL)
                url = line.split()[0] if ' ' in line else line
                urls.append(url)
        
        # Save clean URLs
        with open(clean_file, 'w') as f:
            f.write('\n'.join(urls))
        
        print(f"{Colors.GREEN}[+] Clean URL list saved to: {clean_file}{Colors.RESET}")
        return clean_file
        
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not create clean URL list: {e}{Colors.RESET}")
        return None


def detect_live_hosts(domain, subdomain_file=None):
    """
    Main orchestration function for live host detection
    
    Args:
        domain (str): Target domain
        subdomain_file (str, optional): Path to subdomain file
                                       If None, will look in default location
    
    Returns:
        str: Path to live hosts output file
    
    Workflow:
        1. Verify subdomain file exists
        2. Run httpx probe
        3. Parse and display results
        4. Create clean URL list for next phases
    """
    print_banner()
    
    # Determine subdomain file path
    if subdomain_file is None:
        subdomain_file = os.path.join("output", domain, "subdomains.txt")
    
    # Verify input file exists
    if not check_subdomain_file(subdomain_file):
        return None
    
    # Define output file
    output_dir = os.path.dirname(subdomain_file)
    output_file = os.path.join(output_dir, "live_hosts.txt")
    
    # Run httpx
    success = run_httpx(subdomain_file, output_file)
    
    if not success:
        print(f"{Colors.RED}[!] Live host detection failed{Colors.RESET}")
        return None
    
    # Display results
    parse_and_display_results(output_file)
    
    # Create clean URL list
    extract_clean_urls(output_file, domain)
    
    return output_file


# Standalone execution
if __name__ == "__main__":
    """
    Allow running as standalone script or imported module
    
    Usage examples:
        # Standalone - assumes subdomains.txt exists
        python3 live_hosts.py example.com
        
        # Standalone - with custom subdomain file
        python3 live_hosts.py example.com /path/to/subdomains.txt
        
        # As imported module
        from modules import live_hosts
        live_hosts.detect_live_hosts("example.com")
    """
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python3 {sys.argv[0]} <domain> [subdomain_file]{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} example.com{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} example.com output/example.com/subdomains.txt{Colors.RESET}")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    subdomain_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    detect_live_hosts(target_domain, subdomain_file)
