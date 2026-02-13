# Windows Testing Guide

**Version:** 7.0  
**Date:** February 11, 2026  
**Purpose:** Step-by-step guide for testing Phase 1 on Windows

---

## Prerequisites

### Required Software
- [ ] Windows 10/11 or Server 2016+
- [ ] Python 3.7 or higher ([download here](https://www.python.org/downloads/))
  - ✅ **Important:** Check "Add Python to PATH" during installation
- [ ] Git for Windows ([download here](https://git-scm.com/download/win))
- [ ] Network access to Check Point TE appliance (for full testing)

### Optional but Recommended
- [ ] Windows PowerShell 5.1+ or PowerShell Core 7+
- [ ] Visual Studio Code (for easier editing)
- [ ] Administrative access (for testing service features in Phase 3)

---

## Setup Instructions

### Step 1: Clone Repository

Open PowerShell or Command Prompt:

```powershell
# Navigate to desired location
cd C:\

# Clone the repository
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git

# Enter the directory
cd quantum-gateway-te-api-file-scanner

# Switch to development branch (v7.0 Phase 1)
git checkout v7.0-dev

# Verify you're on the correct branch
git branch

# Verify files are present
dir
```

**Expected output:** 
- Current branch should be `v7.0-dev`
- You should see:
- `te_api.py`
- `te_file_handler.py`
- `path_handler.py`
- `config_manager.py`
- `requirements.txt`
- `README.md`
- etc.

---

### Step 2: Create Virtual Environment

```powershell
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate

# Verify activation (prompt should show (venv))
python --version
```

**Expected output:**
```
Python 3.x.x
```

---

### Step 3: Install Dependencies

```powershell
# Install required packages
pip install -r requirements.txt

# Verify installation
pip list
```

**Expected packages:**
- requests
- urllib3
- pywin32 (Windows only)

---

### Step 4: Create Test Configuration

```powershell
# Copy default config
copy config.ini.default config.ini

# Edit config (opens in Notepad)
notepad config.ini
```

**Sample Windows Configuration:**

```ini
[DEFAULT]
input_directory = C:\TEScans\Input
reports_directory = C:\TEScans\Reports
appliance_ip = 192.168.1.100
benign_directory = C:\TEScans\Benign
quarantine_directory = C:\TEScans\Quarantine
error_directory = C:\TEScans\Errors
concurrency = 2
```

**For UNC Path Testing:**
```ini
[DEFAULT]
input_directory = \\fileserver\scans\input
reports_directory = C:\TEScans\Reports
appliance_ip = 192.168.1.100
benign_directory = \\fileserver\scans\benign
quarantine_directory = C:\Quarantine
error_directory = C:\TEScans\Errors
concurrency = 2
```

---

### Step 5: Create Test Directory Structure

```powershell
# Create test directories
mkdir C:\TEScans\Input
mkdir C:\TEScans\Input\SubDir1
mkdir C:\TEScans\Input\SubDir2

# Create test files
echo "Test file 1" > C:\TEScans\Input\test1.txt
echo "Test file 2" > C:\TEScans\Input\SubDir1\test2.txt
echo "Test file 3" > C:\TEScans\Input\SubDir2\test3.txt

# Create a test archive (if you have 7-Zip or WinRAR)
# Or just download a sample .zip file

# Verify structure
tree /F C:\TEScans\Input
```

---

## Test Procedures

### Test 1: Verify Installation

```powershell
# Should show help without errors
python te_api.py --help
```

**Expected Result:** Help text displays with all options

**Status:** [ ] PASS [ ] FAIL

---

### Test 2: Configuration Loading

```powershell
# Test configuration loading
python -c "from config_manager import ScannerConfig; config = ScannerConfig.from_sources('config.ini'); config.print_summary()"
```

**Expected Result:** Configuration summary displays with Windows paths

**Status:** [ ] PASS [ ] FAIL

---

### Test 3: Path Handler - Windows Paths

```powershell
python -c "from path_handler import PathHandler; from pathlib import Path; print('Is Windows:', PathHandler.is_windows()); print('Long paths:', PathHandler.supports_long_paths())"
```

**Expected Results:**
- `Is Windows: True`
- `Long paths: True` or `False` (depending on registry setting)

**Status:** [ ] PASS [ ] FAIL

---

### Test 4: Path Handler - UNC Detection

```powershell
python -c "from path_handler import PathHandler; from pathlib import Path; print('UNC test:', PathHandler.is_unc_path(Path('\\\\server\\share'))); print('Local test:', PathHandler.is_unc_path(Path('C:\\test')))"
```

**Expected Results:**
- `UNC test: True`
- `Local test: False`

**Status:** [ ] PASS [ ] FAIL

---

### Test 5: Local Path Scanning (Dry Run)

**Note:** This test requires a real TE appliance. If not available, skip to Test 8.

```powershell
# Run scanner with local paths
python te_api.py
```

**Expected Behavior:**
1. Configuration loads successfully
2. Scans input directory recursively
3. Displays file count (archives vs. non-archives)
4. Attempts to connect to TE appliance
5. Processes files based on verdict
6. Moves files to appropriate directories
7. Downloads reports for malicious files

**Check:**
- [ ] Files moved from Input to Benign/Quarantine/Error
- [ ] Subdirectory structure preserved
- [ ] Response files created in Reports directory
- [ ] Empty subdirectories deleted from Input

**Status:** [ ] PASS [ ] FAIL [ ] SKIPPED (no appliance)

**Notes/Errors:**

---

### Test 6: Cross-Drive File Movement

**Setup:** Create input on D:\ (or another drive) and output on C:\

```powershell
# Only if you have multiple drives
mkdir D:\TestInput
echo "Cross-drive test" > D:\TestInput\test.txt

python te_api.py -in D:\TestInput -out C:\TestOutput -ip 192.168.1.100
```

**Expected Behavior:**
- Files copied from D:\ to C:\ successfully (not just renamed)
- No errors about cross-filesystem moves

**Status:** [ ] PASS [ ] FAIL [ ] SKIPPED (single drive)

---

### Test 7: UNC Path Testing

**Prerequisites:** Access to Windows file share

```powershell
# Test with UNC input path
python te_api.py -in "\\server\share\input" -out "C:\TEScans\Benign" -ip 192.168.1.100

# Test with UNC output path
python te_api.py -in "C:\TEScans\Input" -out "\\server\share\output" -ip 192.168.1.100

# Test with both UNC
python te_api.py -in "\\server\share\input" -out "\\server\share\output" -ip 192.168.1.100
```

**Expected Behavior:**
- UNC paths detected correctly
- Retry logic activates for network latency
- Checksum verification enabled automatically
- Files transferred successfully

**Status:** [ ] PASS [ ] FAIL [ ] SKIPPED (no file server)

---

### Test 8: File Locking Test

**Setup:** Simulate Windows file locking

```powershell
# Create test file
echo "Locked file test" > C:\TEScans\Input\locked.txt

# Open the file in Notepad (keeps it locked)
notepad C:\TEScans\Input\locked.txt

# In another PowerShell window, run scanner
python te_api.py
```

**Expected Behavior:**
- Scanner detects file is locked
- Retries up to 3 times with exponential backoff
- Eventually either succeeds or moves to error directory
- Helpful error message displayed

**Status:** [ ] PASS [ ] FAIL

**Retry attempts observed:** ___

---

### Test 9: Long Path Support (if enabled)

**Prerequisites:** Windows long path support enabled in registry

```powershell
# Check if enabled
python -c "from path_handler import PathHandler; print('Long paths supported:', PathHandler.supports_long_paths())"
```

If `True`, test with deeply nested path:

```powershell
# Create very long path (>260 characters)
$longPath = "C:\TEScans\Input\$('a' * 50)\$('b' * 50)\$('c' * 50)\$('d' * 50)\$('e' * 50)"
mkdir $longPath -Force
echo "Long path test" > "$longPath\test.txt"

# Run scanner
python te_api.py
```

**Expected Behavior:**
- No path length errors
- File processed successfully

**Status:** [ ] PASS [ ] FAIL [ ] SKIPPED (long paths not enabled)

---

### Test 10: Archive File Processing

```powershell
# Create test archive (if 7-Zip installed)
# Or download sample .zip from internet
# Place in C:\TEScans\Input\

python te_api.py
```

**Expected Behavior:**
- Archive detected and processed separately
- Processed sequentially (not in parallel)
- All files within archive scanned by TE appliance

**Status:** [ ] PASS [ ] FAIL [ ] SKIPPED (no archive)

---

## Results Summary

### Test Results

| Test | Status | Notes |
|------|--------|-------|
| 1. Help Display | [ ] PASS [ ] FAIL | |
| 2. Config Loading | [ ] PASS [ ] FAIL | |
| 3. Path Handler | [ ] PASS [ ] FAIL | |
| 4. UNC Detection | [ ] PASS [ ] FAIL | |
| 5. Local Scanning | [ ] PASS [ ] FAIL [ ] SKIP | |
| 6. Cross-Drive | [ ] PASS [ ] FAIL [ ] SKIP | |
| 7. UNC Paths | [ ] PASS [ ] FAIL [ ] SKIP | |
| 8. File Locking | [ ] PASS [ ] FAIL | |
| 9. Long Paths | [ ] PASS [ ] FAIL [ ] SKIP | |
| 10. Archives | [ ] PASS [ ] FAIL [ ] SKIP | |

### Issues Found

**Issue 1:**
- Description:
- Error message:
- Workaround:
- Fix needed: [ ] Yes [ ] No

**Issue 2:**
- Description:
- Error message:
- Workaround:
- Fix needed: [ ] Yes [ ] No

---

## Cleanup

After testing:

```powershell
# Deactivate virtual environment
deactivate

# Optional: Remove test files
Remove-Item -Recurse C:\TEScans
```

---

## Reporting Results

After completing tests:

1. **Document results** in TEST_RESULTS.md:
   - Add Windows section with pass/fail for each test
   - Include any error messages or stack traces
   - Note Windows version and Python version tested

2. **Report issues** (if any):
   - Open GitHub issue with details
   - Include full error output
   - Mention specific Windows version and configuration

3. **Update status**:
   - Mark Windows testing as complete in PHASE1_COMPLETE.md
   - If all tests pass, ready for Phase 2 implementation

---

## Next Steps After Testing

### If All Tests Pass ✅
- Update TEST_RESULTS.md with Windows results
- Commit and push updates to GitHub
- Ready to proceed with Phase 2 (watch mode)

### If Issues Found ❌
- Document issues thoroughly
- Provide error logs and system details
- Wait for fixes before proceeding to Phase 2

---

**Testing Guide Version:** 1.0  
**Last Updated:** February 11, 2026  
**For Questions:** Create GitHub issue or contact maintainer
