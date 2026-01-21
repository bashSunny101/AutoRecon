#!/usr/bin/env python3
"""
SUBDOMAIN ENUMERATION MODULE
============================

Purpose: Discover all subdomains for a given target domain using passive reconnaissance

Security Concept:
- Subdomains often contain forgotten or less-secured applications
- Developers may deploy staging/dev environments as subdomains with weaker security
- Finding subdomains = Finding more potential attack vectors

Technique: Passive Reconnaissance
- We query PUBLIC sources (Certificate Transparency logs, DNS databases, search engines)
- We do NOT directly interact with the target (stealthier, legal in most contexts)
- Tool used: Subfinder (industry-standard subdomain enumeration tool)

Author: Sunny Pal
Date: January 2026
"""

import subprocess
import os
import sys

# ANSI color codes for pretty terminal output (makes our tool look professional!)
class Colors:
    """
    These are special codes that make text colorful in the terminal
    Example: Colors.GREEN + "Success!" + Colors.RESET
    """
    BLUE = '\033[94m'      # For informational messages
    GREEN = '\033[92m'     # For success messages
    YELLOW = '\033[93m'    # For warnings
    RED = '\033[91m'       # For errors
    RESET = '\033[0m'      # Reset to default color
    BOLD = '\033[1m'       # Make text bold


def print_banner():
    """
    Print a professional-looking banner for the module
    Why? Makes the tool look polished and professional
    """
    banner = f"""
{Colors.BLUE}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║     SUBDOMAIN ENUMERATION MODULE             ║
║     Passive Reconnaissance Phase             ║
╚══════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)


def create_output_directory(domain):
    """
    Create a directory to store results for the target domain
    
    Args:
        domain (str): The target domain (e.g., "example.com")
    
    Returns:
        str: Path to the created directory
    
    Why we need this:
        - Keep results organized per target
        - Prevent mixing data from different scans
        - Professional file organization
    """
    # os.path.join() creates proper file paths (works on Linux, Windows, Mac)
    output_dir = os.path.join("output", domain)
    
    # os.makedirs() creates the directory
    # exist_ok=True means "don't error if directory already exists"
    os.makedirs(output_dir, exist_ok=True)
    
    return output_dir


def run_subfinder(domain, output_file):
    """
    Execute Subfinder tool to discover subdomains
    
    Args:
        domain (str): Target domain to enumerate
        output_file (str): File path where results will be saved
    
    Returns:
        bool: True if successful, False if failed
    
    How Subfinder Works:
        - Queries Certificate Transparency logs (SSL certificates are public!)
        - Searches DNS databases (passive DNS)
        - Checks search engine results
        - Uses multiple APIs (if configured)
    
    Command we're running:
        subfinder -d example.com -o output/example.com/subdomains.txt -silent
        
        Breakdown:
        -d       : domain flag
        -o       : output file flag
        -silent  : suppress extra messages (cleaner output)
    """
    print(f"{Colors.YELLOW}[*] Running Subfinder on {domain}...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] This may take 30-60 seconds...{Colors.RESET}\n")
    
    # Build the command as a list (safer than string concatenation)
    command = [
        "subfinder",      # The tool name
        "-d", domain,     # -d flag with domain value
        "-o", output_file,# -o flag with output file path
        "-silent"         # Make output cleaner
    ]
    
    try:
        # subprocess.run() executes external commands
        # capture_output=True captures stdout and stderr
        # text=True converts output from bytes to string
        # check=True raises exception if command fails
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        return True
        
    except subprocess.CalledProcessError as e:
        # This catches errors if subfinder fails or returns non-zero exit code
        print(f"{Colors.RED}[!] Error running Subfinder: {e}{Colors.RESET}")
        return False
        
    except FileNotFoundError:
        # This catches the error if subfinder is not installed
        print(f"{Colors.RED}[!] Error: Subfinder not found!{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Install it with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest{Colors.RESET}")
        return False


def read_and_display_results(output_file):
    """
    Read the results file and display subdomains found
    
    Args:
        output_file (str): Path to the file containing subdomains
    
    Why separate this function:
        - Separation of concerns (one function = one job)
        - Can reuse this to display any subdomain list
        - Easier to test and debug
    """
    try:
        # Open file in read mode
        with open(output_file, 'r') as f:
            # Read all lines into a list
            subdomains = f.readlines()
        
        # Strip whitespace and newlines from each subdomain
        # List comprehension: [expression for item in list if condition]
        subdomains = [sub.strip() for sub in subdomains if sub.strip()]
        
        if subdomains:
            print(f"{Colors.GREEN}{Colors.BOLD}[+] Found {len(subdomains)} subdomains:{Colors.RESET}\n")
            
            # Print each subdomain with a bullet point
            for subdomain in subdomains:
                print(f"    • {subdomain}")
            
            print(f"\n{Colors.GREEN}[+] Results saved to: {output_file}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] No subdomains found{Colors.RESET}")
    
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Output file not found{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading results: {e}{Colors.RESET}")


def enumerate_subdomains(domain):
    """
    Main function that orchestrates the subdomain enumeration process
    
    This is the function other scripts will call
    
    Args:
        domain (str): Target domain
    
    Returns:
        str: Path to output file containing results
    
    Process Flow:
        1. Create output directory
        2. Run subfinder
        3. Display results
        4. Return path to results file
    """
    print_banner()
    
    # Step 1: Create directory for this target
    output_dir = create_output_directory(domain)
    
    # Step 2: Define output file path
    output_file = os.path.join(output_dir, "subdomains.txt")
    
    # Step 3: Run subfinder
    success = run_subfinder(domain, output_file)
    
    if not success:
        print(f"{Colors.RED}[!] Subdomain enumeration failed{Colors.RESET}")
        return None
    
    # Step 4: Display results
    read_and_display_results(output_file)
    
    return output_file


# This block runs ONLY if the script is executed directly
# (Not when imported as a module)
if __name__ == "__main__":
    """
    This allows the module to work in two ways:
    
    1. As a standalone script:
       python3 subdomain_enum.py example.com
    
    2. As an imported module:
       from modules import subdomain_enum
       subdomain_enum.enumerate_subdomains("example.com")
    """
    
    # Check if user provided a domain argument
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python3 {sys.argv[0]} <domain>{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} example.com{Colors.RESET}")
        sys.exit(1)
    
    # Get domain from command line argument
    # sys.argv[0] = script name
    # sys.argv[1] = first argument (the domain)
    target_domain = sys.argv[1]
    
    # Run the enumeration
    enumerate_subdomains(target_domain)
