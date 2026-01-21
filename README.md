<div align="center">

# 🔍 AutoRecon

**Automated Reconnaissance Framework for Bug Bounty Hunters**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.linux.org/)

A modular Python framework that automates the reconnaissance phase of security assessments using industry-standard tools.

</div>

---

## ✨ Features

- 🎯 **5-Phase Automated Pipeline** - Complete reconnaissance workflow
- 🔍 **Passive Reconnaissance** - Stealthy OSINT techniques
- 📊 **Professional Reports** - Risk categorization & recommendations
- 🧩 **Modular Architecture** - Run phases independently or together
- 📁 **Organized Results** - Structured data per target

---

## 🚀 Quick Start

```bash
# Install dependencies
sudo apt update && sudo apt install -y nmap golang-go

# Install security tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest

# Configure PATH
export PATH=$PATH:~/go/bin

# Run reconnaissance
python3 recon.py target.com
```

---

## 🎬 Demo

### Terminal Output
<div align="center">
<img src="screenshots/terminal-output.png" alt="AutoRecon Terminal Output" width="800"/>
</div>

### Generated Report
<div align="center">
<img src="screenshots/report-sample.png" alt="AutoRecon Report" width="800"/>
</div>

---

## 🔄 Workflow

<table>
<tr>
<th>Phase</th>
<th>Module</th>
<th>Tool</th>
<th>Description</th>
</tr>
<tr>
<td>1️⃣</td>
<td>Subdomain Enumeration</td>
<td><code>Subfinder</code></td>
<td>Discover subdomains via Certificate Transparency</td>
</tr>
<tr>
<td>2️⃣</td>
<td>Live Host Detection</td>
<td><code>Httpx</code></td>
<td>Multi-threaded HTTP/HTTPS probing</td>
</tr>
<tr>
<td>3️⃣</td>
<td>Port Scanning</td>
<td><code>Nmap</code></td>
<td>Service version detection on top 1000 ports</td>
</tr>
<tr>
<td>4️⃣</td>
<td>URL Collection</td>
<td><code>Waybackurls</code></td>
<td>Historical endpoint discovery</td>
</tr>
<tr>
<td>5️⃣</td>
<td>Report Generation</td>
<td><code>Python</code></td>
<td>Professional summary with risk analysis</td>
</tr>
</table>

### 📁 Project Structure

```
AutoRecon/
├── recon.py                       # Main orchestrator
├── modules/
│   ├── subdomain_enum.py          # Phase 1: Subdomain discovery
│   ├── live_hosts.py              # Phase 2: HTTP/HTTPS probing
│   ├── port_scan.py               # Phase 3: Port/service detection
│   ├── url_collector.py           # Phase 4: Wayback Machine URLs
│   └── report.py                  # Phase 5: Report generation
├── output/
│   └── <target>/                  # Organized results per target
└── screenshots/                   # Demo images
```

---

## � Usage

### Full Scan

```bash
python3 recon.py target.com
```

### Output Structure

```
output/target.com/
├── subdomains.txt              # All discovered subdomains
├── live_hosts.txt              # Active hosts with metadata
├── live_hosts_clean.txt        # Clean URL list
├── port_scans/                 # Nmap results per host
├── urls/                       # Categorized URL findings
│   ├── all_urls.txt
│   ├── api_endpoints.txt
│   ├── admin_panels.txt
│   ├── sensitive.txt
│   └── parameters.txt
└── recon_report.txt            # Comprehensive final report
```

---

## ⚠️ Legal Disclaimer

**AUTHORIZED USE ONLY** - This tool is designed for educational purposes and authorized security testing exclusively.

**✅ Authorized Use:**
- Personal infrastructure you own
- Bug bounty programs (within scope)
- Penetration testing with signed contract

**❌ Prohibited:**
- Scanning without explicit written permission
- Unauthorized network reconnaissance
- Violating terms of service or laws

> Unauthorized scanning is illegal. Always obtain proper authorization before testing.

---

## 📜 License

MIT License - See LICENSE file for details.

---

<div align="center">

**Built for Security Learning**

⭐ Star this repo if you find it helpful!

</div>
