#!/usr/bin/env python3
"""
URL & ENDPOINT COLLECTION MODULE
=================================

Purpose: Discover historical URLs and endpoints using the Wayback Machine

Security Concept:
- Websites constantly add, change, and remove pages
- Old URLs may still work even if removed from navigation
- Developers forget to delete test/debug endpoints
- Backup files and configuration files may be archived
- URL parameters can reveal hidden functionality

Technique: Historical URL Enumeration
- Query Wayback Machine (web.archive.org) for archived URLs
- Extract endpoints, parameters, and file paths
- Identify interesting patterns (admin, api, debug, backup)
- Map the complete URL structure of the target
- Tool used: Waybackurls (Wayback Machine API wrapper)

Why This Phase is Critical:
- Finds forgotten/deleted endpoints still accessible
- Reveals API structure and versioning (v1, v2, v3)
- Discovers backup files and sensitive documents
- Identifies parameters for testing (IDOR, SQLi, XSS)
- Shows technology changes over time

Bug Bounty Value:
- Old admin panels: High severity
- Exposed .env files: Critical
- API parameter discovery: Medium to High
- Backup file access: Critical

Author: Cybersecurity Student
Date: January 2026
"""

import subprocess
import os
import sys
from collections import defaultdict

# Color codes
class Colors:
    """ANSI color codes for terminal output"""
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
{Colors.BLUE}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║       URL & ENDPOINT COLLECTION              ║
║     Historical URL Discovery via Wayback     ║
╚══════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)


def check_live_hosts_file(live_hosts_file):
    """
    Verify live hosts file exists
    
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


def load_domains(live_hosts_file):
    """
    Load domains from live hosts file
    
    Args:
        live_hosts_file (str): Path to file containing live hosts
    
    Returns:
        list: List of domains to collect URLs for
    
    Note: We extract just the base domain, not full URLs
    Example: "https://api.example.com" -> "api.example.com"
    """
    domains = []
    
    try:
        with open(live_hosts_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract domain from URL
            # Remove http:// or https://
            domain = line.replace('https://', '').replace('http://', '')
            # Remove path if present
            domain = domain.split('/')[0]
            
            if domain and domain not in domains:
                domains.append(domain)
        
        return domains
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error loading domains: {e}{Colors.RESET}")
        return []


def run_waybackurls(domain, output_file):
    """
    Execute waybackurls to fetch historical URLs
    
    Args:
        domain (str): Domain to query
        output_file (str): File to save URLs
    
    Returns:
        bool: True if successful, False otherwise
    
    How Waybackurls Works:
        - Queries Wayback Machine API (web.archive.org)
        - Retrieves all archived URLs for the domain
        - Returns chronological list of discovered endpoints
        - Can find URLs from years ago that still work
    
    Command:
        echo "example.com" | waybackurls > urls.txt
        
        Why pipe from echo?
        - waybackurls reads from stdin (standard input)
        - We pipe the domain name into it
        - Results written to stdout, redirected to file
    
    What You'll Find:
        - API endpoints: /api/v1/users, /api/v2/payment
        - Admin panels: /admin, /administrator, /wp-admin
        - Backup files: /backup.sql, /db.tar.gz, /.env
        - Old versions: /old-site, /v1, /legacy
        - Parameters: ?id=123, ?user=admin, ?debug=true
    """
    print(f"{Colors.YELLOW}[*] Collecting URLs for {domain}...{Colors.RESET}")
    
    try:
        # waybackurls reads from stdin, so we pipe the domain to it
        # We use shell=True to enable pipe functionality
        command = f"echo '{domain}' | waybackurls"
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        
        # Check if we got results
        if result.stdout:
            # Save to file
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            return True
        else:
            print(f"{Colors.YELLOW}[!] No URLs found for {domain}{Colors.RESET}")
            # Create empty file
            open(output_file, 'w').close()
            return True
        
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}[!] Waybackurls timed out for {domain}{Colors.RESET}")
        return False
        
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Waybackurls not found!{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Install it with: go install github.com/tomnomnom/waybackurls@latest{Colors.RESET}")
        return False
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error running waybackurls: {e}{Colors.RESET}")
        return False


def analyze_urls(url_file):
    """
    Analyze collected URLs and extract interesting patterns
    
    Args:
        url_file (str): File containing URLs
    
    Returns:
        dict: Analysis results with categorized findings
    
    What We Analyze:
        - File extensions (php, jsp, asp, sql, zip, tar.gz)
        - API endpoints (containing /api/)
        - Admin panels (containing /admin, /login, /dashboard)
        - Parameters (?id=, ?user=, ?file=)
        - Sensitive patterns (backup, config, .env, .git)
    
    Why This Matters:
        Different file types = Different vulnerabilities
        - .php → SQL injection, LFI, RFI
        - .jsp → Java exploits
        - .sql → Database dumps
        - .env → Credentials exposure
    """
    analysis = {
        'total_urls': 0,
        'extensions': defaultdict(int),
        'api_endpoints': [],
        'admin_panels': [],
        'parameters': [],
        'sensitive_files': [],
        'interesting_paths': []
    }
    
    # Interesting patterns to look for
    sensitive_patterns = ['.env', '.git', 'config', 'backup', '.sql', '.zip', 
                         '.tar.gz', 'dump', '.bak', 'credentials', 'password']
    
    admin_patterns = ['admin', 'login', 'dashboard', 'panel', 'console', 
                     'manager', 'cpanel', 'wp-admin', 'phpmyadmin']
    
    try:
        with open(url_file, 'r') as f:
            urls = f.readlines()
        
        analysis['total_urls'] = len(urls)
        
        for url in urls:
            url = url.strip()
            if not url:
                continue
            
            # Extract file extension
            if '.' in url.split('/')[-1]:
                ext = url.split('/')[-1].split('.')[-1].split('?')[0]
                if ext and len(ext) <= 10:  # Reasonable extension length
                    analysis['extensions'][ext] += 1
            
            # Check for API endpoints
            if '/api/' in url.lower() or '/api?' in url.lower():
                analysis['api_endpoints'].append(url)
            
            # Check for admin panels
            for pattern in admin_patterns:
                if pattern in url.lower():
                    analysis['admin_panels'].append(url)
                    break
            
            # Check for parameters
            if '?' in url:
                analysis['parameters'].append(url)
            
            # Check for sensitive files
            for pattern in sensitive_patterns:
                if pattern in url.lower():
                    analysis['sensitive_files'].append(url)
                    break
        
        return analysis
        
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not analyze URLs: {e}{Colors.RESET}")
        return analysis


def display_analysis(domain, analysis):
    """
    Display formatted analysis results
    
    Args:
        domain (str): Domain being analyzed
        analysis (dict): Analysis results
    """
    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Analysis for {domain}:{Colors.RESET}\n")
    
    # Total URLs
    print(f"    Total URLs: {Colors.CYAN}{analysis['total_urls']}{Colors.RESET}")
    
    # File extensions
    if analysis['extensions']:
        print(f"\n    {Colors.CYAN}Top File Extensions:{Colors.RESET}")
        # Sort by count, show top 10
        sorted_exts = sorted(analysis['extensions'].items(), key=lambda x: x[1], reverse=True)[:10]
        for ext, count in sorted_exts:
            print(f"      • .{ext}: {count}")
    
    # API endpoints
    if analysis['api_endpoints']:
        count = len(analysis['api_endpoints'])
        print(f"\n    {Colors.GREEN}API Endpoints: {count}{Colors.RESET}")
        # Show first 5 examples
        for url in analysis['api_endpoints'][:5]:
            print(f"      • {url}")
        if count > 5:
            print(f"      ... and {count - 5} more")
    
    # Admin panels
    if analysis['admin_panels']:
        count = len(analysis['admin_panels'])
        print(f"\n    {Colors.YELLOW}Admin/Login Panels: {count}{Colors.RESET}")
        # Show unique ones (avoid duplicates)
        unique_admins = list(set(analysis['admin_panels']))[:5]
        for url in unique_admins:
            print(f"      • {url}")
        if count > 5:
            print(f"      ... and {count - 5} more")
    
    # Sensitive files
    if analysis['sensitive_files']:
        count = len(analysis['sensitive_files'])
        print(f"\n    {Colors.RED}{Colors.BOLD}🚨 Sensitive Files: {count}{Colors.RESET}")
        # Show unique ones
        unique_sensitive = list(set(analysis['sensitive_files']))[:10]
        for url in unique_sensitive:
            print(f"      • {url}")
        if count > 10:
            print(f"      ... and {count - 10} more")
    
    # Parameters
    if analysis['parameters']:
        count = len(analysis['parameters'])
        print(f"\n    {Colors.CYAN}URLs with Parameters: {count}{Colors.RESET}")
        print(f"      (Test for IDOR, SQLi, XSS)")
    
    print()


def save_interesting_findings(analysis, domain, output_dir):
    """
    Save categorized findings to separate files for easy review
    
    Args:
        analysis (dict): Analysis results
        domain (str): Domain name
        output_dir (str): Output directory
    
    Why Separate Files?
        - Easier to review specific categories
        - Can feed directly into other tools
        - Organized workflow for testing
    """
    # Save API endpoints
    if analysis['api_endpoints']:
        api_file = os.path.join(output_dir, f"{domain}_api_endpoints.txt")
        with open(api_file, 'w') as f:
            f.write('\n'.join(set(analysis['api_endpoints'])))
        print(f"{Colors.GREEN}[+] API endpoints saved to: {api_file}{Colors.RESET}")
    
    # Save admin panels
    if analysis['admin_panels']:
        admin_file = os.path.join(output_dir, f"{domain}_admin_panels.txt")
        with open(admin_file, 'w') as f:
            f.write('\n'.join(set(analysis['admin_panels'])))
        print(f"{Colors.GREEN}[+] Admin panels saved to: {admin_file}{Colors.RESET}")
    
    # Save sensitive files
    if analysis['sensitive_files']:
        sensitive_file = os.path.join(output_dir, f"{domain}_sensitive.txt")
        with open(sensitive_file, 'w') as f:
            f.write('\n'.join(set(analysis['sensitive_files'])))
        print(f"{Colors.RED}[+] Sensitive files saved to: {sensitive_file}{Colors.RESET}")
    
    # Save parameters
    if analysis['parameters']:
        params_file = os.path.join(output_dir, f"{domain}_parameters.txt")
        with open(params_file, 'w') as f:
            f.write('\n'.join(set(analysis['parameters'])))
        print(f"{Colors.GREEN}[+] Parameter URLs saved to: {params_file}{Colors.RESET}")


def collect_urls(domain, live_hosts_file=None):
    """
    Main orchestration function for URL collection
    
    Args:
        domain (str): Target domain
        live_hosts_file (str, optional): Path to live hosts file
    
    Returns:
        str: Path to output directory
    
    Workflow:
        1. Load domains from live hosts
        2. Run waybackurls for each domain
        3. Analyze URLs for interesting patterns
        4. Display and save categorized findings
    """
    print_banner()
    
    # Determine live hosts file path
    if live_hosts_file is None:
        live_hosts_file = os.path.join("output", domain, "live_hosts_clean.txt")
    
    # Check if file exists
    if not check_live_hosts_file(live_hosts_file):
        return None
    
    # Load domains
    domains = load_domains(live_hosts_file)
    
    if not domains:
        print(f"{Colors.RED}[!] No domains to collect URLs for{Colors.RESET}")
        return None
    
    print(f"{Colors.CYAN}[*] Loaded {len(domains)} domains{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Querying Wayback Machine...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] This may take 2-5 minutes...{Colors.RESET}\n")
    
    # Create output directory
    output_dir = os.path.join("output", domain, "urls")
    os.makedirs(output_dir, exist_ok=True)
    
    # Collect URLs for each domain
    success_count = 0
    for i, target_domain in enumerate(domains, 1):
        print(f"{Colors.CYAN}[{i}/{len(domains)}]{Colors.RESET} ", end='')
        
        # Output file for this domain
        safe_filename = target_domain.replace('/', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f"{safe_filename}_urls.txt")
        
        # Run waybackurls
        success = run_waybackurls(target_domain, output_file)
        
        if success:
            success_count += 1
            
            # Analyze URLs
            analysis = analyze_urls(output_file)
            
            # Display analysis
            display_analysis(target_domain, analysis)
            
            # Save categorized findings
            save_interesting_findings(analysis, safe_filename, output_dir)
    
    # Summary
    print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*50}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] URL collection complete!{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Processed: {success_count}/{len(domains)} domains{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Results saved to: {output_dir}/{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}{'='*50}{Colors.RESET}\n")
    
    print(f"{Colors.CYAN}[*] Next Steps:{Colors.RESET}")
    print(f"    1. Review sensitive files for exposed credentials")
    print(f"    2. Test API endpoints for authentication bypasses")
    print(f"    3. Check admin panels for default credentials")
    print(f"    4. Test parameter URLs for IDOR, SQLi, XSS\n")
    
    return output_dir


# Standalone execution
if __name__ == "__main__":
    """
    Standalone script usage
    
    Examples:
        python3 url_collector.py example.com
        python3 url_collector.py example.com output/example.com/live_hosts_clean.txt
    """
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python3 {sys.argv[0]} <domain> [live_hosts_file]{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} example.com{Colors.RESET}")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    live_hosts_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    collect_urls(target_domain, live_hosts_file)
