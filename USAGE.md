# 🚀 AUTORECON USAGE GUIDE

## Quick Start

### Basic Usage
```bash
python3 recon.py example.com
```

The framework will automatically run all 5 phases and generate a comprehensive report.

---

## 📋 Prerequisites

### Required Tools

Install these security tools before running AutoRecon:

```bash
# Update package list
sudo apt update

# Install Go (if not installed)
sudo apt install golang-go -y

# Install Nmap
sudo apt install nmap -y

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Add Go bin to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

---

## 🎯 Running AutoRecon

### Full Automated Scan

```bash
python3 recon.py target.com
```

**You will be prompted for confirmation:**
```
Do you have authorization to test this target? (yes/no):
```

**What happens:**
1. ✅ Subdomain enumeration (30-60 seconds)
2. ✅ Live host detection (1-2 minutes)
3. ✅ Port scanning (2-5 minutes per host)
4. ✅ URL collection (2-5 minutes)
5. ✅ Report generation (instant)

**Total Time:** 10-30 minutes depending on target size

---

### Running Individual Modules

You can run each phase separately for testing or targeted reconnaissance:

#### Phase 1: Subdomain Enumeration Only
```bash
python3 modules/subdomain_enum.py example.com
```
**Output:** `output/example.com/subdomains.txt`

#### Phase 2: Live Host Detection Only
```bash
python3 modules/live_hosts.py example.com
```
**Output:** `output/example.com/live_hosts.txt`

#### Phase 3: Port Scanning Only
```bash
python3 modules/port_scan.py example.com
```
**Output:** `output/example.com/port_scans/`

#### Phase 4: URL Collection Only
```bash
python3 modules/url_collector.py example.com
```
**Output:** `output/example.com/urls/`

#### Phase 5: Report Generation Only
```bash
python3 modules/report.py example.com
```
**Output:** `output/example.com/recon_report.txt`

---

## 📁 Understanding Output Structure

After running AutoRecon, your results are organized:

```
output/example.com/
├── subdomains.txt              # All discovered subdomains
├── live_hosts.txt              # Detailed live host information
├── live_hosts_clean.txt        # Clean list of URLs
├── port_scans/                 # Individual nmap scans per host
│   ├── api.example.com.txt
│   ├── www.example.com.txt
│   └── ...
├── urls/                       # URL collection results
│   ├── api.example.com_urls.txt
│   ├── api.example.com_api_endpoints.txt
│   ├── api.example.com_admin_panels.txt
│   ├── api.example.com_sensitive.txt
│   └── ...
└── recon_report.txt            # Comprehensive final report
```

---

## 🔍 Analyzing Results

### 1. Start with the Report
```bash
cat output/example.com/recon_report.txt
```

This gives you an executive summary and highlights critical findings.

### 2. Review Sensitive Files (PRIORITY!)
```bash
cat output/example.com/urls/*_sensitive.txt
```

Look for:
- `.env` files (credentials!)
- `.sql` dumps (database backups)
- `.zip`/`.tar.gz` (source code)
- `config.php` (configurations)

### 3. Check Admin Panels
```bash
cat output/example.com/urls/*_admin_panels.txt
```

Test these for:
- Default credentials
- SQL injection
- Authentication bypass

### 4. Analyze API Endpoints
```bash
cat output/example.com/urls/*_api_endpoints.txt
```

Test for:
- IDOR (change IDs)
- Authentication bypass
- Data exposure

### 5. Review Port Scans
```bash
ls output/example.com/port_scans/
cat output/example.com/port_scans/interesting-host.txt
```

Look for:
- Exposed databases (3306, 5432, 27017)
- Outdated SSH versions
- Development servers (3000, 5000, 8000)

---

## 💡 Pro Tips

### Interrupt and Resume

You can stop AutoRecon anytime with **Ctrl+C**. The framework saves progress after each phase, so you can:

```bash
# Run just the remaining phases manually
python3 modules/port_scan.py example.com
python3 modules/url_collector.py example.com
python3 modules/report.py example.com
```

### Target Specific Subdomains

If you want to scan specific hosts instead of all discovered subdomains:

```bash
# Create custom list
echo "api.example.com" > output/example.com/custom_targets.txt
echo "admin.example.com" >> output/example.com/custom_targets.txt

# Run specific phases on custom list
python3 modules/live_hosts.py example.com output/example.com/custom_targets.txt
```

### Optimize Scan Speed

For faster scans with fewer hosts:

1. Edit `modules/port_scan.py` and change:
   ```python
   "--top-ports", "1000"  # Change to "100" for faster scans
   ```

2. Edit `modules/live_hosts.py` and change:
   ```python
   "-threads", "50"  # Increase to "100" for faster probing
   ```

---

## 🚨 Common Issues & Troubleshooting

### "Tool not found" errors

**Symptom:** `FileNotFoundError: subfinder not found`

**Solution:**
```bash
# Verify Go bin is in PATH
echo $PATH | grep go/bin

# If not, add it:
export PATH=$PATH:~/go/bin

# Make it permanent:
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### No subdomains found

**Possible causes:**
- Target has very few subdomains
- Certificate Transparency logs don't have data
- Network/firewall blocking

**Solution:** Try a well-known target first (tesla.com, hackerone.com) to verify tools work.

### Port scanning too slow

**Solution:** Port scanning is the slowest phase. You can:
- Skip it: Don't run Phase 3
- Scan fewer hosts: Edit live_hosts.txt before running
- Reduce port count: Change to --top-ports 100

### Waybackurls timeout

**Symptom:** "Waybackurls timed out"

**Solution:** This happens with large domains. The timeout is set to 2 minutes per domain. Increase it in `url_collector.py`:
```python
timeout=120  # Change to 300 (5 minutes)
```

---

## ⚖️ Legal & Ethical Usage

### ✅ AUTHORIZED Use Cases

- Your own websites/infrastructure
- Bug bounty programs (within stated scope)
- Penetration testing with signed contract
- Educational lab environments

### ❌ NEVER Do This

- Scan random companies without permission
- Test government/military targets
- Ignore bug bounty scope restrictions
- Scan after being told to stop

### 📝 Best Practices

1. **Always get written authorization**
2. **Respect rate limits and scope**
3. **Follow responsible disclosure**
4. **Document everything**
5. **Stop if asked**

---

## 📚 What You've Learned

By building and using AutoRecon, you now understand:

### Technical Skills
- Python automation and scripting
- Linux command-line tools
- Subprocess execution and error handling
- File I/O and data parsing
- Regular expressions
- Module organization

### Security Concepts
- Reconnaissance methodology
- Attack surface mapping
- Subdomain enumeration techniques
- Service fingerprinting
- Historical data analysis
- Professional reporting

### Professional Skills
- Bug bounty workflow
- Pentesting methodology
- Tool integration
- Documentation
- Ethical hacking principles

---

## 🎯 Interview Talking Points

When discussing this project in interviews:

**"What did you build?"**
> "I built AutoRecon, a modular Python reconnaissance framework that automates the first phase of penetration testing. It performs subdomain enumeration, live host detection, port scanning, and historical URL analysis, then generates professional reports. I designed it to follow industry-standard methodology while being beginner-friendly and legally compliant."

**"What makes it different?"**
> "It focuses on passive reconnaissance techniques, making it safer and stealthier than aggressive scanners. Each module is independent and well-documented, demonstrating software engineering principles like separation of concerns and error handling. The framework produces interview-ready reports that showcase both technical findings and business impact."

**"What did you learn?"**
> "I learned the complete reconnaissance phase of pentesting, how to integrate multiple security tools, and the importance of automation in cybersecurity. I also gained experience with Python's subprocess module, regex parsing, and creating professional documentation. Most importantly, I learned the ethical and legal considerations of security testing."

---

## 🤝 Contributing & Next Steps

### Potential Enhancements

- Add nuclei vulnerability scanning
- Implement concurrent scanning
- Create HTML/PDF report export
- Add screenshot capture of live hosts
- Integrate with security APIs (Shodan, SecurityTrails)

### Learning Path

After mastering AutoRecon:
1. Study the OWASP Top 10
2. Learn manual exploitation techniques
3. Practice on HackTheBox / TryHackMe
4. Join bug bounty platforms (HackerOne, Bugcrowd)
5. Get certified (CEH, OSCP, eJPT)

---

## 📞 Support

If you encounter issues:
1. Check this guide first
2. Review module comments and docstrings
3. Test individual modules separately
4. Verify all tools are installed correctly

---

**Happy Hunting! 🎯**

Remember: *With great power comes great responsibility. Always hack ethically.*
