# 🔍 AutoRecon - Automated Bug Bounty Reconnaissance Framework

> **A professional reconnaissance automation tool for bug bounty hunters and penetration testers**

## 📋 Overview

AutoRecon is a modular Python framework that automates the reconnaissance phase of security assessments. It performs subdomain enumeration, live host detection, port scanning, URL collection, and vulnerability scanning in a systematic, industry-standard workflow.

**Target Audience:** Beginner to intermediate cybersecurity professionals, bug bounty hunters, and aspiring penetration testers.

## ✨ Features

- **Automated Recon Pipeline** - Executes reconnaissance phases in logical order
- **Modular Architecture** - Each recon phase is isolated and reusable
- **Organized Output** - Results saved per target in structured directories
- **Beginner-Friendly** - Clean, commented code with educational explanations
- **Interview-Ready** - Professional project showcasing pentesting knowledge

## 🎯 Recon Workflow

```
Input Domain (example.com)
    ↓
1. Subdomain Enumeration    → Discovers all subdomains
    ↓
2. Live Host Detection      → Identifies active hosts
    ↓
3. Port Scanning            → Maps open ports and services
    ↓
4. URL Collection           → Gathers historical endpoints
    ↓
5. Vulnerability Scanning   → Basic security checks
    ↓
6. Report Generation        → Consolidated findings
```

## 🛠️ Tech Stack

- **Python 3** - Core scripting language
- **Subfinder** - Subdomain discovery
- **Httpx** - HTTP probing and live host detection
- **Nmap** - Port scanning
- **Waybackurls** - Historical URL enumeration
- **Nuclei** - Vulnerability scanning

## 📁 Project Structure

```
AutoRecon/
├── recon.py                # Main controller script
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

### 1. Install System Dependencies (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Go (required for some tools)
sudo apt install golang-go -y

# Install Nmap
sudo apt install nmap -y
```

### 2. Install Security Tools

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add Go bin to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH=$PATH:~/go/bin
```

### 3. Clone and Setup AutoRecon

```bash
# Clone repository
git clone <your-repo-url>
cd AutoRecon

# Verify tools are installed
subfinder -version
httpx -version
nmap --version
waybackurls -h
nuclei -version
```

## 🚀 Usage

### Basic Usage

```bash
# Run full reconnaissance on a target
python3 recon.py example.com
```

### Module-Specific Usage

```bash
# Run only subdomain enumeration
python3 modules/subdomain_enum.py example.com

# Run only live host detection
python3 modules/live_hosts.py example.com

# Run only port scanning
python3 modules/port_scan.py example.com
```

### Output Location

All results are saved in `output/<target-domain>/`:
```
output/example.com/
├── subdomains.txt          # Discovered subdomains
├── live_hosts.txt          # Active hosts
├── port_scan.txt           # Port scan results
├── urls.txt                # Collected URLs
└── recon_report.txt        # Final report
```

## ⚠️ Legal Disclaimer

**This tool is for educational purposes and authorized security testing only.**

- ✅ Use on your own systems
- ✅ Use in authorized bug bounty programs (within scope)
- ✅ Use with written permission from target owner
- ❌ **DO NOT** use on systems without authorization

Unauthorized scanning is illegal and unethical. Always obtain proper authorization before testing.

## 🎓 Learning Objectives

By building and using this project, you'll learn:

- **Reconnaissance methodology** used in real pentesting
- **Python automation** for security tasks
- **Linux command-line** security tools
- **Attack surface mapping** techniques
- **Professional reporting** and documentation
- **Ethical hacking** workflow and mindset

## 🤝 Contributing

This is a learning project. Feel free to:
- Add new reconnaissance modules
- Improve existing functionality
- Enhance documentation
- Report bugs or suggest features

## 📚 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/KathanP19/HowToHunt)
- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)

## 📝 License

MIT License - Educational purposes

---

**Built with 🔐 by cybersecurity learners, for cybersecurity learners**
Automated Bug Bounty Recon Framework
