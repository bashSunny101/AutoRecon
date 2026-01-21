# Screenshots Guide

## Required Screenshots for README

To complete the professional README, please capture the following screenshots:

### 1. Terminal Output (`terminal-output.png`)
**What to capture:** Full terminal window showing AutoRecon execution

**Steps:**
1. Run the command: `python3 recon.py hackerone.com` (or use a test domain)
2. Let it complete at least Phase 1 and Phase 2
3. Take a screenshot of the terminal showing:
   - The banner
   - Phase outputs with color coding
   - Progress indicators
   - Results summary

**Recommended tool:** 
- Linux: `gnome-screenshot` or `flameshot`
- Command: `flameshot gui` (select area and save as `terminal-output.png`)

**Size:** Resize to ~800-1000px width for optimal README display

---

### 2. Report Sample (`report-sample.png`)
**What to capture:** The generated reconnaissance report

**Steps:**
1. After running a scan, open the report file:
   ```bash
   cat output/hackerone.com/recon_report.txt
   ```
2. Take a screenshot showing:
   - Executive Summary section
   - Key Metrics
   - Risk Summary
   - Recommendations

**Alternative:** 
- Open the file in a text editor with syntax highlighting
- Or use `bat` for colored output: `bat output/hackerone.com/recon_report.txt`

**Size:** Resize to ~800-1000px width

---

## Screenshot Tips

### Best Practices:
1. **Clear Background:** Use a clean terminal theme (dark themes work best)
2. **Readable Font Size:** Increase terminal font size before capturing (16-18pt recommended)
3. **Full Context:** Show complete outputs, avoid cutting off important information
4. **Professional Look:** 
   - Remove personal information (if any)
   - Use consistent color schemes
   - Ensure text is sharp and readable

### Recommended Terminal Theme:
```bash
# For a professional look, use one of these themes:
- Dracula
- Nord
- Gruvbox Dark
- Tomorrow Night
```

### Image Optimization:
After capturing, optimize images for web:
```bash
# Install if needed
sudo apt install optipng

# Optimize PNG files
optipng -o7 terminal-output.png
optipng -o7 report-sample.png
```

---

## Alternative: Use Screen Recording

If screenshots don't capture the dynamic nature well:

1. Record terminal session:
   ```bash
   asciinema rec demo.cast
   # Run your commands
   # Press Ctrl+D to stop
   ```

2. Convert to GIF:
   ```bash
   sudo npm install -g asciicast2gif
   asciicast2gif demo.cast demo.gif
   ```

3. Add GIF to README instead of static images

---

## Current Status

- [ ] `terminal-output.png` - Terminal execution screenshot
- [ ] `report-sample.png` - Generated report screenshot

Once you add these images to the `screenshots/` folder, they will automatically display in the README!
