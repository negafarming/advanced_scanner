# 🚀 Quick Start Guide - Windows Security Auditor

## Installation (5 minutes)

### Step 1: Prerequisites
- Windows 10/11 or Windows Server 2016+
- Python 3.8+ installed ([Download here](https://www.python.org/downloads/))
- Make sure "Add Python to PATH" was checked during installation

### Step 2: Download and Setup
```bash
# Extract the ZIP file to a folder (e.g., C:\WinSecAuditor)
cd C:\WinSecAuditor

# Run the installation script
install.bat
```

### Step 3: Verify Installation
```bash
python --version
# Should show Python 3.8 or later
```

## First Scan (2 minutes)

### Option A: Using GUI (Easiest)
1. Double-click `start_gui.bat`
2. Click "Browse..." and select your project folder
3. Keep all analyzers checked
4. Click "▶️ Start Scan"
5. Wait for completion
6. Click "💾 Export Report"

### Option B: Using CLI
```bash
# Simple scan
start_cli.bat scan "C:\path\to\your\project"

# The report will be in the 'reports' folder
```

## Understanding Results

### Severity Levels
- 🔴 **CRITICAL**: Immediate security risk - Fix ASAP!
- 🟠 **HIGH**: Significant vulnerability - Fix soon
- 🟡 **MEDIUM**: Moderate issue - Plan to fix
- 🔵 **LOW**: Minor concern - Good to fix
- ⚪ **INFO**: Informational - Consider improving

### Report Files
After scanning, you'll find in the `reports` folder:
- `security_report_TIMESTAMP.html` - Beautiful, interactive report (open in browser)
- `security_report_TIMESTAMP.json` - Machine-readable data (for automation)

## Common Scenarios

### Scenario 1: Quick Security Check
```bash
# Just security issues
python src/cli_app.py scan "C:\MyProject" --security --format html
```

### Scenario 2: Full Analysis
```bash
# All analyzers + all reports
python src/cli_app.py scan "C:\MyProject" --all
```

### Scenario 3: CI/CD Integration
```bash
# Fail build if critical/high issues found
python src/cli_app.py scan . --all --fail-on-high
```

### Scenario 4: Specific File Types Only
Edit the configuration (see Configuration section below) to include/exclude specific files.

## What Gets Scanned?

### ✅ Included
- Source code (.cs, .cpp, .py, .js, etc.)
- Configuration files (.config, .json, .xml)
- Scripts (.ps1, .bat, .sh)
- Docker files
- Project files (.csproj, .sln)

### ❌ Excluded (by default)
- Binary files (.exe, .dll, .pdb)
- Build artifacts (bin/, obj/, Debug/, Release/)
- Dependencies (node_modules/, packages/)
- Version control (.git/, .svn/)

## Customization

### Exclude Additional Folders
Create/edit `config/user_config.json`:
```json
{
  "excluded_dirs": [
    ".git",
    "node_modules",
    "bin",
    "obj",
    "MyLargeFolderToSkip"
  ]
}
```

## Troubleshooting

### "Python not found"
- Reinstall Python with "Add to PATH" option
- Or manually add Python to PATH

### "Tkinter module not found" (GUI only)
- Reinstall Python
- Check "tcl/tk and IDLE" during installation

### Scan is slow
- Exclude large folders (see Customization above)
- Close other applications
- Use SSD instead of HDD

### Permission errors
- Run as Administrator (right-click → "Run as administrator")
- Check folder permissions

## Next Steps

1. 📖 Read the full [README.md](README.md) for detailed documentation
2. 🧪 Test on the sample file: `tests/sample_vulnerable_code.cs`
3. 🔧 Integrate with your CI/CD pipeline
4. 📊 Review and fix identified issues
5. 🔄 Run periodic scans (weekly recommended)

## Getting Help

- Check [README.md](README.md) for detailed docs
- Review [FAQ](docs/FAQ.md) (if available)
- Check the `docs/` folder for more guides

## Best Practices

1. **Run scans regularly**: Weekly or before major releases
2. **Prioritize by severity**: Fix CRITICAL → HIGH → MEDIUM → LOW
3. **Track progress**: Compare reports over time
4. **Automate**: Integrate into CI/CD
5. **Review ALL findings**: Even LOW severity issues can be important

## Security Notice

This tool helps identify security issues but doesn't guarantee complete security. Always:
- Have security experts review critical applications
- Perform penetration testing
- Keep software updated
- Follow secure coding guidelines
- Use defense in depth

---

**Ready to scan?** 🚀

Run: `start_gui.bat` (for GUI) or `start_cli.bat scan "your-project"` (for CLI)

**Questions?** Check README.md or the documentation folder!
