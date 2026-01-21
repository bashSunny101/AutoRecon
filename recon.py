#!/usr/bin/env python3
"""
AUTORECON - AUTOMATED RECONNAISSANCE FRAMEWORK
===============================================

Main Controller Script

Purpose: Orchestrate all reconnaissance phases in proper order

This is the primary entry point for the AutoRecon framework. It coordinates
the execution of all reconnaissance modules in a logical sequence, ensuring
each phase completes successfully before proceeding to the next.

Reconnaissance Workflow:
    1. Subdomain Enumeration  → Discover all subdomains
    2. Live Host Detection    → Filter to active hosts
    3. Port Scanning          → Map services and ports
    4. URL Collection         → Gather historical endpoints
    5. Report Generation      → Professional summary

Why This Order Matters:
    - Each phase builds on the previous one
    - Efficient: Only scan live hosts, not dead ones
    - Professional: Standard pentesting methodology
    - Organized: Clear data flow and dependencies

Usage:
    python3 recon.py <domain>
    
Example:
    python3 recon.py example.com

Author: Cybersecurity Student
Date: January 2026
Version: 1.0
"""

import sys
import os
from datetime import datetime

# Import our reconnaissance modules
from modules import subdomain_enum
from modules import live_hosts
from modules import port_scan
from modules import url_collector
from modules import report

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


def print_main_banner():
    """
    Display the main AutoRecon banner
    
    Why a banner?
    - Professional appearance
    - Clear visual separation
    - Branding/project identity
    - Looks great in demos and screenshots
    """
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║                         AUTORECON v1.0                             ║
║              Automated Bug Bounty Reconnaissance                   ║
║                                                                    ║
║     Beginner-to-Intermediate Cybersecurity Learning Project        ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
{Colors.RESET}

{Colors.YELLOW}⚠️  WARNING: Only scan authorized targets!{Colors.RESET}
{Colors.YELLOW}   Legal authorization is required for security testing.{Colors.RESET}

"""
    print(banner)


def print_phase_header(phase_number, phase_name, description):
    """
    Print a formatted header for each reconnaissance phase
    
    Args:
        phase_number (int): Phase number (1-5)
        phase_name (str): Name of the phase
        description (str): Brief description
    
    Why separate phase headers?
    - Clear visual progress indicator
    - User knows what's happening
    - Easy to debug if something fails
    - Professional workflow presentation
    """
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}{Colors.BOLD}PHASE {phase_number}: {phase_name}{Colors.RESET}")
    print(f"{Colors.CYAN}{description}{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")


def validate_target(domain):
    """
    Validate the target domain format
    
    Args:
        domain (str): Target domain to validate
    
    Returns:
        bool: True if valid, False otherwise
    
    Basic Validation:
    - Not empty
    - Contains a dot (basic domain format)
    - No http:// or https:// (we want just the domain)
    
    Note: This is basic validation. Real validation would be more complex.
    """
    if not domain:
        print(f"{Colors.RED}[!] Error: Domain cannot be empty{Colors.RESET}")
        return False
    
    # Remove protocol if user included it
    if domain.startswith('http://') or domain.startswith('https://'):
        print(f"{Colors.YELLOW}[!] Removing protocol from domain...{Colors.RESET}")
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.split('/')[0]  # Remove path if present
    
    # Basic format check
    if '.' not in domain:
        print(f"{Colors.RED}[!] Error: Invalid domain format{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Example: example.com (not http://example.com){Colors.RESET}")
        return False
    
    return True


def run_reconnaissance(domain):
    """
    Execute the complete reconnaissance workflow
    
    Args:
        domain (str): Target domain
    
    Returns:
        bool: True if all phases completed successfully
    
    Workflow Logic:
    - Each phase depends on the previous one
    - If a phase fails, we stop (dependency chain broken)
    - Progress is saved at each step (can resume manually)
    - Final report summarizes all findings
    
    Error Handling:
    - Graceful failure messages
    - Clear indication of which phase failed
    - Suggestions for troubleshooting
    """
    start_time = datetime.now()
    
    print(f"{Colors.GREEN}[*] Target: {domain}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Starting reconnaissance workflow...{Colors.RESET}\n")
    
    # ========================================================================
    # PHASE 1: SUBDOMAIN ENUMERATION
    # ========================================================================
    print_phase_header(
        1, 
        "SUBDOMAIN ENUMERATION",
        "Discovering all subdomains using passive reconnaissance"
    )
    
    try:
        subdomain_file = subdomain_enum.enumerate_subdomains(domain)
        
        if not subdomain_file:
            print(f"\n{Colors.RED}[!] Phase 1 failed: Subdomain enumeration unsuccessful{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Troubleshooting:{Colors.RESET}")
            print(f"    • Is subfinder installed? (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)")
            print(f"    • Is the domain valid?")
            print(f"    • Check your internet connection")
            return False
        
        print(f"\n{Colors.GREEN}✓ Phase 1 Complete{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        return False
    except Exception as e:
        print(f"\n{Colors.RED}[!] Phase 1 failed with error: {e}{Colors.RESET}")
        return False
    
    # ========================================================================
    # PHASE 2: LIVE HOST DETECTION
    # ========================================================================
    print_phase_header(
        2,
        "LIVE HOST DETECTION",
        "Identifying which subdomains are actively responding"
    )
    
    try:
        live_hosts_file = live_hosts.detect_live_hosts(domain)
        
        if not live_hosts_file:
            print(f"\n{Colors.RED}[!] Phase 2 failed: Live host detection unsuccessful{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Troubleshooting:{Colors.RESET}")
            print(f"    • Is httpx installed? (go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)")
            print(f"    • Were any subdomains found in Phase 1?")
            print(f"    • Check firewall/network settings")
            return False
        
        print(f"\n{Colors.GREEN}✓ Phase 2 Complete{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        return False
    except Exception as e:
        print(f"\n{Colors.RED}[!] Phase 2 failed with error: {e}{Colors.RESET}")
        return False
    
    # ========================================================================
    # PHASE 3: PORT SCANNING
    # ========================================================================
    print_phase_header(
        3,
        "PORT SCANNING & SERVICE DETECTION",
        "Mapping open ports and identifying running services"
    )
    
    try:
        port_scan_dir = port_scan.scan_ports(domain)
        
        if not port_scan_dir:
            print(f"\n{Colors.YELLOW}[!] Phase 3 warning: Port scanning incomplete{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Continuing with remaining phases...{Colors.RESET}")
            # Don't fail - port scanning is optional for final report
        else:
            print(f"\n{Colors.GREEN}✓ Phase 3 Complete{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Skipping port scanning, continuing with URL collection...{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.YELLOW}[!] Phase 3 warning: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Continuing with remaining phases...{Colors.RESET}")
    
    # ========================================================================
    # PHASE 4: URL & ENDPOINT COLLECTION
    # ========================================================================
    print_phase_header(
        4,
        "URL & ENDPOINT COLLECTION",
        "Gathering historical URLs from the Wayback Machine"
    )
    
    try:
        url_dir = url_collector.collect_urls(domain)
        
        if not url_dir:
            print(f"\n{Colors.YELLOW}[!] Phase 4 warning: URL collection incomplete{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] This may mean no historical data exists{Colors.RESET}")
            # Don't fail - URL collection is optional
        else:
            print(f"\n{Colors.GREEN}✓ Phase 4 Complete{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Skipping URL collection, generating report...{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.YELLOW}[!] Phase 4 warning: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Continuing to report generation...{Colors.RESET}")
    
    # ========================================================================
    # PHASE 5: REPORT GENERATION
    # ========================================================================
    print_phase_header(
        5,
        "REPORT GENERATION",
        "Creating professional reconnaissance summary"
    )
    
    try:
        report_file = report.generate_report(domain)
        
        if not report_file:
            print(f"\n{Colors.YELLOW}[!] Phase 5 warning: Report generation incomplete{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✓ Phase 5 Complete{Colors.RESET}")
        
    except Exception as e:
        print(f"\n{Colors.YELLOW}[!] Phase 5 warning: {e}{Colors.RESET}")
    
    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}RECONNAISSANCE COMPLETE!{Colors.RESET}")
    print(f"{Colors.GREEN}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}Target:        {domain}{Colors.RESET}")
    print(f"{Colors.CYAN}Duration:      {duration}{Colors.RESET}")
    print(f"{Colors.CYAN}End Time:      {end_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.GREEN}{'='*70}{Colors.RESET}\n")
    
    print(f"{Colors.CYAN}[*] Results saved to: output/{domain}/{Colors.RESET}\n")
    
    print(f"{Colors.YELLOW}NEXT STEPS:{Colors.RESET}")
    print(f"  1. Review the report:     cat output/{domain}/recon_report.txt")
    print(f"  2. Check sensitive files: cat output/{domain}/urls/*_sensitive.txt")
    print(f"  3. Review admin panels:   cat output/{domain}/urls/*_admin_panels.txt")
    print(f"  4. Analyze port scans:    ls output/{domain}/port_scans/")
    print(f"\n{Colors.GREEN}Happy Hunting! 🎯{Colors.RESET}\n")
    
    return True


def main():
    """
    Main entry point for AutoRecon
    
    Handles:
    - Command-line argument parsing
    - Input validation
    - Workflow orchestration
    - Error handling
    - User feedback
    """
    print_main_banner()
    
    # Check command-line arguments
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python3 recon.py <domain>{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 recon.py example.com{Colors.RESET}\n")
        print(f"{Colors.CYAN}Description:{Colors.RESET}")
        print(f"  AutoRecon performs comprehensive passive reconnaissance on a target domain.")
        print(f"  It executes five phases: subdomain enumeration, live host detection,")
        print(f"  port scanning, URL collection, and report generation.\n")
        print(f"{Colors.YELLOW}Legal Notice:{Colors.RESET}")
        print(f"  Only scan targets you have explicit authorization to test.")
        print(f"  Unauthorized scanning may be illegal in your jurisdiction.\n")
        sys.exit(1)
    
    # Get target domain
    target_domain = sys.argv[1].strip()
    
    # Validate target
    if not validate_target(target_domain):
        sys.exit(1)
    
    # Clean domain (remove protocol if present)
    target_domain = target_domain.replace('https://', '').replace('http://', '')
    target_domain = target_domain.split('/')[0]
    
    # Confirmation prompt
    print(f"{Colors.YELLOW}You are about to scan: {Colors.BOLD}{target_domain}{Colors.RESET}")
    confirmation = input(f"{Colors.YELLOW}Do you have authorization to test this target? (yes/no): {Colors.RESET}")
    
    if confirmation.lower() not in ['yes', 'y']:
        print(f"\n{Colors.RED}[!] Scan cancelled. Always obtain proper authorization before testing.{Colors.RESET}\n")
        sys.exit(0)
    
    print()  # Blank line for spacing
    
    # Run the reconnaissance workflow
    try:
        success = run_reconnaissance(target_domain)
        
        if success:
            sys.exit(0)
        else:
            print(f"{Colors.RED}[!] Reconnaissance workflow did not complete successfully{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Check error messages above for details{Colors.RESET}\n")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Reconnaissance interrupted by user{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Partial results may be saved in output/{target_domain}/{Colors.RESET}\n")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Please report this issue on GitHub{Colors.RESET}\n")
        sys.exit(1)


# Script entry point
if __name__ == "__main__":
    """
    Execute main function when script is run directly
    
    This is the standard Python pattern for executable scripts.
    It ensures the script only runs when executed directly,
    not when imported as a module.
    """
    main()
