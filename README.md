# AutoRecon

**Automated Reconnaissance Framework for Bug Bounty Hunters**

A modular Python framework that automates the reconnaissance phase of security assessments using industry-standard tools and methodologies.

## Features

- **5-Phase Automated Pipeline** - Subdomain enumeration → Live host detection → Port scanning → URL collection → Report generation
- **Passive Reconnaissance** - Stealthy information gathering using public sources
- **Modular Architecture** - Each phase runs independently or as part of the full workflow
- **Professional Reports** - Comprehensive findings with risk categorization and recommendations
- **Educational** - Extensively commented code for learning cybersecurity concepts

## Quick Start

```bash
# Clone repository
git clone <your-repo-url>
cd AutoRecon

# Install dependencies
sudo apt update && sudo apt install -y nmap golang-go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
export PATH=$PATH:~/go/bin

# Run reconnaissance
python3 recon.py target.com
```

## Sample Output

### Input
```bash
$ python3 recon.py hackerone.com
├── modules/
│   ├── subdomain_enum.py   # Subdomain enumeration module
│   ├── live_hosts.py       # Live host detection module
│   ├── port_scan.py        # Port scanning module
│   ├── url_collector.py    # URL collection module
│   └── report.py           # Report generation module
├── output/
│   └── <target>/           # Results organized by target domain
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## ⚙️ Installation

```

### Output
```
╔════════════════════════════════════════════════════════════════════╗
║                         AUTORECON v1.0                             ║
║              Automated Bug Bounty Reconnaissance                   ║
╚════════════════════════════════════════════════════════════════════╝

[*] Target: hackerone.com
[*] Starting reconnaissance workflow...

======================================================================
PHASE 1: SUBDOMAIN ENUMERATION
======================================================================

[+] Found 247 subdomains
[+] Results saved to: output/hackerone.com/subdomains.txt

======================================================================
PHASE 2: LIVE HOST DETECTION
======================================================================

[+] Found 189 live hosts
Protocol Distribution:
  • HTTPS: 185 hosts
  • HTTP:  4 hosts

======================================================================
PHASE 3: PORT SCANNING & SERVICE DETECTION
======================================================================

[+] api.hackerone.com - 5 open ports:
    Port 80     | http            | Cloudflare http proxy
    Port 443    | ssl/http        | Cloudflare http proxy
    Port 8080   | http            | Cloudflare http proxy
    
⚠️  WARNINGS:
    • Port 8080 (HTTP-Proxy) - Alternative HTTP, often admin panels

======================================================================
PHASE 4: URL & ENDPOINT COLLECTION
======================================================================

[+] Total Historical URLs: 12,453

API Endpoints Found: 47
  → Test for: Authentication bypass, IDOR, data exposure

Admin/Login Panels: 23
  → Test for: Default credentials, SQL injection

🚨 CRITICAL - Sensitive Files: 8
  → HIGH PRIORITY: Check for exposed credentials, configs

======================================================================
PHASE 5: REPORT GENERATION
======================================================================

[+] Report generated successfully!
[+] Saved to: output/hackerone.com/recon_report.txt

======================================================================
RECONNAISSANCE COMPLETE!
======================================================================
Duration: 0:08:34
```

### Generated Report Preview
```
======================================================================
               AUTOMATED RECONNAISSANCE REPORT
======================================================================

Target Domain:    hackerone.com
Scan Date:        2026-01-21 14:22:54
Framework:        AutoRecon v1.0

EXECUTIVE SUMMARY
----------------------------------------------------------------------

KEY METRICS:
  • Subdomains Discovered:     247
  • Live Hosts Confirmed:      189
  • Hosts Port Scanned:        189
  • Historical URLs Found:     12,453
  • API Endpoints Identified:  47
  • Admin Panels Discovered:   23
  • Sensitive Files Found:     8

RISK SUMMARY:
  🚨 CRITICAL: 8 sensitive files discovered
  ⚠️  HIGH:     23 admin panels identified
  ⚠️  MEDIUM:   47 API endpoints found

RECOMMENDATIONS & NEXT STEPS
----------------------------------------------------------------------

1. CRITICAL - Review Sensitive Files
   • Check for .env files, .sql dumps, .zip backups
   • Look for exposed credentials or API keys

2. HIGH - Test Admin Panels
   • Verify accessibility
   • Test for default credentials
   • Check for SQL injection vulnerabilities

3. MEDIUM - API Endpoint Testing
   • Map API structure and versioning
   • Test authentication mechanisms
   • Check for IDOR vulnerabilities
```

## Architecture

```
AutoRecon/
├── recon.py                # Main orchestrator
├── modules/
│   ├── subdomain_enum.py   # Phase 1: Subdomain discovery
│   ├── live_hosts.py       # Phase 2: HTTP/HTTPS probing
│   ├── port_scan.py        # Phase 3: Port/service detection
│   ├── url_collector.py    # Phase 4: Wayback Machine URLs
│   └── report.py           # Phase 5: Report generation
└── output/
    └── <target>/           # Organized results per target
```

## Reconnaissance Workflow

1. **Subdomain Enumeration** - Passive discovery via Certificate Transparency logs, DNS databases
2. **Live Host Detection** - Multi-threaded HTTP/HTTPS probing with technology detection
3. **Port Scanning** - Nmap service version detection on top 1000 ports
4. **URL Collection** - Historical endpoint discovery via Wayback Machine
5. **Report Generation** - Professional summary with risk categorization

## Technologies

| Tool | Purpose | Type |
|------|---------|------|
| **Subfinder** | Subdomain enumeration | Passive |
| **Httpx** | Live host detection | Semi-passive |
| **Nmap** | Port & service scanning | Active |
| **Waybackurls** | Historical URL discovery | Passive |
| **Python 3** | Orchestration & automation | - |

## Installation

```bash
# Install system dependencies
sudo apt update
sudo apt install -y nmap golang-go

# Install Go-based security tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest

# Add Go binaries to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

## Usage

**Full automated scan:**
```bash
python3 recon.py target.com
```

**Individual modules:**
```bash
python3 modules/subdomain_enum.py target.com
python3 modules/live_hosts.py target.com
python3 modules/port_scan.py target.com
python3 modules/url_collector.py target.com
python3 modules/report.py target.com
```

**Output structure:**
```
output/target.com/
├── subdomains.txt              # All discovered subdomains
├── live_hosts.txt              # Active hosts with metadata
├── live_hosts_clean.txt        # Clean URL list
├── port_scans/                 # Individual Nmap results
│   └── *.txt
├── urls/                       # Categorized URL findings
│   ├── *_urls.txt
│   ├── *_api_endpoints.txt
│   ├── *_admin_panels.txt
│   ├── *_sensitive.txt
│   └── *_parameters.txt
└── recon_report.txt            # Comprehensive summary
```

## Legal Disclaimer

This tool is for **authorized security testing only**. Usage requires explicit written permission from the target owner. Unauthorized reconnaissance may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar international regulations.

**Authorized use cases:**
- Personal infrastructure and websites
- Bug bounty programs (within stated scope)
- Penetration testing engagements with signed contracts
- Educational lab environments

## Learning Outcomes

- Reconnaissance methodology and attack surface mapping
- Python automation and subprocess management
- Integration of multiple security tools
- Professional security reporting
- Ethical hacking principles and legal considerations

## License

MIT License - For educational and authorized security testing purposes

---

**Built for cybersecurity learners and bug bounty hunters**
