#!/usr/bin/env python3
"""
RECONNAISSANCE REPORT GENERATION MODULE
========================================

Purpose: Generate comprehensive, professional reconnaissance reports

Why Reports Matter:
- Documentation of findings for stakeholders
- Evidence for bug bounty submissions
- Reference for future testing phases
- Professional presentation of work
- Portfolio piece for job interviews

Report Components:
- Executive summary with key metrics
- Detailed findings from all recon phases
- Categorized results by severity
- Actionable recommendations
- Timestamp and metadata

Author: Cybersecurity Student
Date: January 2026
"""

import os
import sys
from datetime import datetime
import glob

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


def print_banner():
    """Display module banner"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║      REPORT GENERATION MODULE                ║
║   Professional Reconnaissance Summary        ║
╚══════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)


def count_lines_in_file(filepath):
    """
    Count non-empty lines in a file
    
    Args:
        filepath (str): Path to file
    
    Returns:
        int: Number of non-empty lines
    """
    if not os.path.exists(filepath):
        return 0
    
    try:
        with open(filepath, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        return len(lines)
    except:
        return 0


def collect_statistics(domain):
    """
    Gather statistics from all reconnaissance phases
    
    Args:
        domain (str): Target domain
    
    Returns:
        dict: Statistics from all modules
    """
    stats = {
        'domain': domain,
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'subdomains_total': 0,
        'live_hosts_total': 0,
        'ports_scanned': 0,
        'urls_collected': 0,
        'api_endpoints': 0,
        'admin_panels': 0,
        'sensitive_files': 0
    }
    
    base_path = os.path.join("output", domain)
    
    # Subdomain statistics
    subdomains_file = os.path.join(base_path, "subdomains.txt")
    stats['subdomains_total'] = count_lines_in_file(subdomains_file)
    
    # Live hosts statistics
    live_hosts_file = os.path.join(base_path, "live_hosts_clean.txt")
    stats['live_hosts_total'] = count_lines_in_file(live_hosts_file)
    
    # Port scan statistics
    port_scans_dir = os.path.join(base_path, "port_scans")
    if os.path.exists(port_scans_dir):
        stats['ports_scanned'] = len(os.listdir(port_scans_dir))
    
    # URL collection statistics
    urls_dir = os.path.join(base_path, "urls")
    if os.path.exists(urls_dir):
        # Count all URL files
        url_files = glob.glob(os.path.join(urls_dir, "*_urls.txt"))
        for url_file in url_files:
            stats['urls_collected'] += count_lines_in_file(url_file)
        
        # Count categorized findings
        api_files = glob.glob(os.path.join(urls_dir, "*_api_endpoints.txt"))
        for api_file in api_files:
            stats['api_endpoints'] += count_lines_in_file(api_file)
        
        admin_files = glob.glob(os.path.join(urls_dir, "*_admin_panels.txt"))
        for admin_file in admin_files:
            stats['admin_panels'] += count_lines_in_file(admin_file)
        
        sensitive_files = glob.glob(os.path.join(urls_dir, "*_sensitive.txt"))
        for sensitive_file in sensitive_files:
            stats['sensitive_files'] += count_lines_in_file(sensitive_file)
    
    return stats


def read_sample_data(filepath, max_lines=10):
    """
    Read sample lines from a file
    
    Args:
        filepath (str): Path to file
        max_lines (int): Maximum lines to read
    
    Returns:
        list: Sample lines from file
    """
    if not os.path.exists(filepath):
        return []
    
    try:
        with open(filepath, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines[:max_lines]
    except:
        return []


def generate_report(domain):
    """
    Generate comprehensive reconnaissance report
    
    Args:
        domain (str): Target domain
    
    Returns:
        str: Path to generated report
    """
    print_banner()
    print(f"{Colors.CYAN}[*] Generating report for {domain}...{Colors.RESET}\n")
    
    # Collect statistics
    stats = collect_statistics(domain)
    
    # Create report content
    report_lines = []
    
    # Header
    report_lines.append("="*70)
    report_lines.append(" " * 15 + "AUTOMATED RECONNAISSANCE REPORT")
    report_lines.append("="*70)
    report_lines.append("")
    report_lines.append(f"Target Domain:    {stats['domain']}")
    report_lines.append(f"Scan Date:        {stats['scan_date']}")
    report_lines.append(f"Framework:        AutoRecon v1.0")
    report_lines.append(f"Analyst:          Cybersecurity Student")
    report_lines.append("")
    report_lines.append("="*70)
    
    # Executive Summary
    report_lines.append("")
    report_lines.append("EXECUTIVE SUMMARY")
    report_lines.append("-"*70)
    report_lines.append("")
    report_lines.append("This report presents the findings from an automated reconnaissance")
    report_lines.append("assessment conducted against the specified target domain using passive")
    report_lines.append("and semi-passive techniques.")
    report_lines.append("")
    
    # Key Metrics
    report_lines.append("KEY METRICS:")
    report_lines.append(f"  • Subdomains Discovered:     {stats['subdomains_total']}")
    report_lines.append(f"  • Live Hosts Confirmed:      {stats['live_hosts_total']}")
    report_lines.append(f"  • Hosts Port Scanned:        {stats['ports_scanned']}")
    report_lines.append(f"  • Historical URLs Found:     {stats['urls_collected']}")
    report_lines.append(f"  • API Endpoints Identified:  {stats['api_endpoints']}")
    report_lines.append(f"  • Admin Panels Discovered:   {stats['admin_panels']}")
    report_lines.append(f"  • Sensitive Files Found:     {stats['sensitive_files']}")
    report_lines.append("")
    
    # Risk Summary
    report_lines.append("RISK SUMMARY:")
    critical_count = stats['sensitive_files']
    high_count = stats['admin_panels']
    medium_count = stats['api_endpoints']
    
    if critical_count > 0:
        report_lines.append(f"  🚨 CRITICAL: {critical_count} sensitive files discovered")
    if high_count > 0:
        report_lines.append(f"  ⚠️  HIGH:     {high_count} admin panels identified")
    if medium_count > 0:
        report_lines.append(f"  ⚠️  MEDIUM:   {medium_count} API endpoints found")
    
    if critical_count == 0 and high_count == 0 and medium_count == 0:
        report_lines.append("  ✓ No immediate high-risk findings in automated recon")
    
    report_lines.append("")
    report_lines.append("="*70)
    
    # Phase 1: Subdomain Enumeration
    report_lines.append("")
    report_lines.append("PHASE 1: SUBDOMAIN ENUMERATION")
    report_lines.append("-"*70)
    report_lines.append("")
    report_lines.append(f"Total Subdomains Discovered: {stats['subdomains_total']}")
    report_lines.append("")
    report_lines.append("Technique: Passive subdomain enumeration using Subfinder")
    report_lines.append("Sources: Certificate Transparency logs, DNS databases, search engines")
    report_lines.append("")
    
    if stats['subdomains_total'] > 0:
        report_lines.append("Sample Subdomains (first 10):")
        subdomains_file = os.path.join("output", domain, "subdomains.txt")
        sample_subs = read_sample_data(subdomains_file, 10)
        for sub in sample_subs:
            report_lines.append(f"  • {sub}")
        
        if stats['subdomains_total'] > 10:
            report_lines.append(f"  ... and {stats['subdomains_total'] - 10} more")
    
    report_lines.append("")
    report_lines.append(f"Full List: output/{domain}/subdomains.txt")
    report_lines.append("")
    
    # Phase 2: Live Host Detection
    report_lines.append("="*70)
    report_lines.append("")
    report_lines.append("PHASE 2: LIVE HOST DETECTION")
    report_lines.append("-"*70)
    report_lines.append("")
    report_lines.append(f"Total Live Hosts: {stats['live_hosts_total']}")
    report_lines.append(f"Success Rate: {(stats['live_hosts_total']/stats['subdomains_total']*100):.1f}% of subdomains are active" if stats['subdomains_total'] > 0 else "N/A")
    report_lines.append("")
    report_lines.append("Technique: HTTP/HTTPS probing using Httpx")
    report_lines.append("Detection: Status codes, titles, technology fingerprinting")
    report_lines.append("")
    
    if stats['live_hosts_total'] > 0:
        report_lines.append("Sample Live Hosts (first 10):")
        live_hosts_file = os.path.join("output", domain, "live_hosts_clean.txt")
        sample_hosts = read_sample_data(live_hosts_file, 10)
        for host in sample_hosts:
            report_lines.append(f"  • {host}")
        
        if stats['live_hosts_total'] > 10:
            report_lines.append(f"  ... and {stats['live_hosts_total'] - 10} more")
    
    report_lines.append("")
    report_lines.append(f"Full List: output/{domain}/live_hosts.txt")
    report_lines.append("")
    
    # Phase 3: Port Scanning
    report_lines.append("="*70)
    report_lines.append("")
    report_lines.append("PHASE 3: PORT SCANNING & SERVICE DETECTION")
    report_lines.append("-"*70)
    report_lines.append("")
    report_lines.append(f"Hosts Scanned: {stats['ports_scanned']}")
    report_lines.append("")
    report_lines.append("Technique: Nmap SYN scan with service version detection")
    report_lines.append("Scope: Top 1000 most common ports")
    report_lines.append("")
    report_lines.append("Individual scan results available in:")
    report_lines.append(f"  output/{domain}/port_scans/")
    report_lines.append("")
    report_lines.append("NOTE: Review individual scan files for detailed port/service information")
    report_lines.append("")
    
    # Phase 4: URL Collection
    report_lines.append("="*70)
    report_lines.append("")
    report_lines.append("PHASE 4: URL & ENDPOINT COLLECTION")
    report_lines.append("-"*70)
    report_lines.append("")
    report_lines.append(f"Total Historical URLs: {stats['urls_collected']}")
    report_lines.append("")
    report_lines.append("Technique: Wayback Machine historical URL extraction")
    report_lines.append("Source: Internet Archive (web.archive.org)")
    report_lines.append("")
    
    # API Endpoints
    if stats['api_endpoints'] > 0:
        report_lines.append(f"API Endpoints Found: {stats['api_endpoints']}")
        report_lines.append("  → Test for: Authentication bypass, IDOR, data exposure")
        report_lines.append("")
    
    # Admin Panels
    if stats['admin_panels'] > 0:
        report_lines.append(f"Admin/Login Panels: {stats['admin_panels']}")
        report_lines.append("  → Test for: Default credentials, SQL injection, brute force")
        
        # Show sample admin panels
        urls_dir = os.path.join("output", domain, "urls")
        admin_files = glob.glob(os.path.join(urls_dir, "*_admin_panels.txt"))
        if admin_files:
            sample_admins = read_sample_data(admin_files[0], 5)
            if sample_admins:
                report_lines.append("")
                report_lines.append("  Sample Admin Panels:")
                for admin_url in sample_admins:
                    report_lines.append(f"    • {admin_url}")
        report_lines.append("")
    
    # Sensitive Files
    if stats['sensitive_files'] > 0:
        report_lines.append(f"🚨 CRITICAL - Sensitive Files: {stats['sensitive_files']}")
        report_lines.append("  → HIGH PRIORITY: Check for exposed credentials, configs, backups")
        
        # Show sample sensitive files
        urls_dir = os.path.join("output", domain, "urls")
        sensitive_files = glob.glob(os.path.join(urls_dir, "*_sensitive.txt"))
        if sensitive_files:
            sample_sensitive = read_sample_data(sensitive_files[0], 5)
            if sample_sensitive:
                report_lines.append("")
                report_lines.append("  Sample Sensitive Files:")
                for sens_url in sample_sensitive:
                    report_lines.append(f"    • {sens_url}")
        report_lines.append("")
    
    report_lines.append(f"Categorized findings: output/{domain}/urls/")
    report_lines.append("")
    
    # Recommendations
    report_lines.append("="*70)
    report_lines.append("")
    report_lines.append("RECOMMENDATIONS & NEXT STEPS")
    report_lines.append("-"*70)
    report_lines.append("")
    report_lines.append("IMMEDIATE ACTIONS:")
    report_lines.append("")
    
    if stats['sensitive_files'] > 0:
        report_lines.append("1. CRITICAL - Review Sensitive Files")
        report_lines.append("   • Check for .env files, .sql dumps, .zip backups")
        report_lines.append("   • Look for exposed credentials or API keys")
        report_lines.append("   • Verify if files are still accessible")
        report_lines.append("")
    
    if stats['admin_panels'] > 0:
        report_lines.append("2. HIGH - Test Admin Panels")
        report_lines.append("   • Verify accessibility")
        report_lines.append("   • Test for default credentials")
        report_lines.append("   • Check for SQL injection vulnerabilities")
        report_lines.append("")
    
    if stats['api_endpoints'] > 0:
        report_lines.append("3. MEDIUM - API Endpoint Testing")
        report_lines.append("   • Map API structure and versioning")
        report_lines.append("   • Test authentication mechanisms")
        report_lines.append("   • Check for IDOR vulnerabilities")
        report_lines.append("")
    
    report_lines.append("MANUAL TESTING PRIORITIES:")
    report_lines.append("")
    report_lines.append("  • Review port scan results for outdated services")
    report_lines.append("  • Test parameterized URLs for IDOR, SQLi, XSS")
    report_lines.append("  • Verify SSL/TLS configuration on HTTPS endpoints")
    report_lines.append("  • Check for subdomain takeover opportunities")
    report_lines.append("  • Analyze technology stack for known CVEs")
    report_lines.append("")
    
    # Footer
    report_lines.append("="*70)
    report_lines.append("")
    report_lines.append("DISCLAIMER:")
    report_lines.append("This reconnaissance was conducted using automated passive and semi-passive")
    report_lines.append("techniques. All findings should be manually verified before reporting.")
    report_lines.append("Only test systems you have explicit authorization to assess.")
    report_lines.append("")
    report_lines.append("="*70)
    report_lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"AutoRecon Framework v1.0")
    report_lines.append("="*70)
    
    # Save report
    output_dir = os.path.join("output", domain)
    report_file = os.path.join(output_dir, "recon_report.txt")
    
    try:
        with open(report_file, 'w') as f:
            f.write('\n'.join(report_lines))
        
        print(f"{Colors.GREEN}[+] Report generated successfully!{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Saved to: {report_file}{Colors.RESET}\n")
        
        # Display report to terminal
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}REPORT PREVIEW:{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        # Show first 30 lines as preview
        for line in report_lines[:30]:
            print(line)
        
        print(f"\n... (Full report saved to file)")
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] View full report: cat {report_file}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        return report_file
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error generating report: {e}{Colors.RESET}")
        return None


# Standalone execution
if __name__ == "__main__":
    """
    Standalone script usage
    
    Example:
        python3 report.py example.com
    """
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python3 {sys.argv[0]} <domain>{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} example.com{Colors.RESET}")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    generate_report(target_domain)
