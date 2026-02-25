# te_api

**Version 8.0** - adds filename sanitisation when talking to the API; preserves original names on disk

**Version 7.0** - Cross-platform Python client for Check Point Threat Emulation API

A Python client side utility for using Threat Emulation API calls to an on-premises Check Point gateway (or Threat Emulation appliance). **Now with full Windows and Linux support, including SMB/UNC network paths.**

Starting in version 8.0 the scanner will accept files whose names contain arbitrary bytes; names are encoded to a UTF‑8‑safe, space‑free form when sent to the API and decoded back when results are handled.  This allows processing of files that the appliance itself would otherwise reject.

The utility will parse a directory tree, and use the Threat Emulation API to scan the files.
Files will be moved from the source or "input" directory to one of the following directories:
- Benign files will be moved to the "benign" directory.
- Malicious files will be moved to the "quarantine" directory.
- Files that can't be correctly processed will be moved to the "error" directory.
- Transcripts 

API transcripts for all files will be placed in the "reports" directory. Analysis reports will be downloaded for any malicious files and also placed in the "reports" directory.

Normal files, i.e. files that are not archives, will be processed in a parallel fashion. Change the "concurrency" value to suit the capacity of your environment to avoid overloading or slowing down the processing of files from other sources.

If processed in an on-premises Threat Emulation appliance, archives are expanded and all files within them are analysed. This can lead to very large numbers of files being processed at once, so archive files are processed one at a time after the normal files. If one or more files in the archive are found malicious, the parent archive file is marked as malicious.

Note that this utility will move files from the input directory to the output directories, leaving the input directory empty.
If your use case requires that benign files be left in the input directory and only malicious files be moved to the quarantine, a different approach is needed.

## Platform Support

**Supported Platforms:**
- ✅ Linux (tested on debian-based distro)
- ✅ Windows (tested on Windows 11)

**Network Path Support:**
- ✅ Windows UNC paths: `\\server\share\folder`
- ✅ Linux SMB mounts: `/mnt/smbshare/folder`
- ✅ Cross-filesystem moves (e.g., Windows D:\ to E:\)
- ✅ Automatic retry logic for network latency
- ✅ Checksum verification for network file transfers

### The flow
Going through the input directory and handling each file in order to get its Threat Emulation results.
Directory tree structure below the input directory will be reproduced in the bening directory.

For each file:

      1. Compute SHA1 hash and query the cache of recently analysed files for existing verdict.

           If results exist then goto #4, otherwise- continue to #2
    
      2. Upload the file to the appliance for te and te_eb features.
    
      3. If upload result is upload_success then wait and query until verdict is available.

           (Note, te_eb results of early malicious verdict might be received earlier during the queries in between)
    
      4. Write the log file and place it in the reports dir. Move the file to the benign or quarantine dir.
    
      5. If verdict is malicious then also download the TE report and place it in the reports dir.





## Installation

### Prerequisites
- Python 3.7 or higher
- Network access to Check Point Threat Emulation appliance

### Install Dependencies

**Linux:**
```bash
pip3 install -r requirements.txt
```

**Windows:**
```powershell
pip install -r requirements.txt

# Or if 'pip' is not recognized, use:
python -m pip install -r requirements.txt
```

The `requirements.txt` includes platform-specific dependencies (e.g., `pywin32` on Windows).

## Configuration

### Method 1: Configuration File (Recommended)

1. Copy `config.ini.default` to `config.ini`
2. Edit `config.ini` with your settings:

**Linux Example:**
```ini
[DEFAULT]
input_directory = /data/incoming
reports_directory = /data/reports
appliance_ip = 192.168.1.100
benign_directory = /data/benign
quarantine_directory = /data/quarantine
error_directory = /data/errors
concurrency = 4
```

**Windows Example:**
```ini
[DEFAULT]
input_directory = C:\Scans\Input
reports_directory = C:\Scans\Reports
appliance_ip = 192.168.1.100
benign_directory = \\fileserver\scanned\benign
quarantine_directory = C:\Quarantine
error_directory = C:\Scans\Errors
concurrency = 2
```

**Note for Windows:** Use either backslashes `C:\path` or forward slashes `C:/path`. UNC paths are fully supported: `\\server\share\folder`

### Method 2: Environment Variables

Set environment variables with `TE_` prefix:

**Linux:**
```bash
export TE_INPUT_DIRECTORY=/data/incoming
export TE_APPLIANCE_IP=192.168.1.100
export TE_CONCURRENCY=4
```

**Windows:**
```powershell
$env:TE_INPUT_DIRECTORY="C:\Scans\Input"
$env:TE_APPLIANCE_IP="192.168.1.100"
$env:TE_CONCURRENCY=2
```

### Method 3: Command-Line Arguments

Command-line arguments override both config file and environment variables:

```bash
python te_api.py --help
```

**Usage:**
```
usage: te_api.py [-h] [-in INPUT_DIRECTORY] [-rep REPORTS_DIRECTORY] 
                 [-ip APPLIANCE_IP] [-n CONCURRENCY] [-out BENIGN_DIRECTORY]
                 [-jail QUARANTINE_DIRECTORY] [-error ERROR_DIRECTORY]

optional arguments:
  -h, --help            show this help message and exit
  -in, --input_directory
                        the input files folder to be scanned by TE
  -rep, --reports_directory
                        the output folder with TE results
  -ip, --appliance_ip   the appliance ip address
  -n, --concurrency     Number of concurrent file processes
  -out, --benign_directory
                        the directory to move Benign files after scanning
  -jail, --quarantine_directory
                        the directory to move Malicious files after scanning
  -error, --error_directory
                        the directory to move files which cause a scanning error
```

**Configuration Priority** (highest to lowest):
1. Command-line arguments
2. Environment variables
3. Configuration file (`config.ini`)
4. Built-in defaults

## Usage

### Basic Usage

**Linux:**
```bash
python3 te_api.py
```

**Windows:**
```powershell
python te_api.py
```

The scanner will:
1. Load configuration
2. Scan the input directory recursively
3. Process files in parallel (respecting concurrency setting)
4. Move files based on verdict (Benign/Malicious/Error)
5. Clean up empty directories

### With Command-Line Arguments

```bash
python3 te_api.py -in /path/to/files -ip 192.168.1.100 -n 8
```

### Network Path Examples

**Windows UNC Paths:**
```powershell
python te_api.py -in "\\server\incoming" -out "\\server\safe" -jail "C:\Quarantine"
```

**Linux SMB Mounts:**
```bash
python3 te_api.py -in /mnt/incoming -out /mnt/safe -jail /local/quarantine
```

## Platform-Specific Notes

### Windows

**File Locking:** Windows may lock files being accessed by antivirus or search indexer. The scanner includes automatic retry logic with exponential backoff.

**Long Paths:** Windows paths are limited to 260 characters by default. To enable long path support:
1. Open Registry Editor (`regedit`)
2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`
3. Set `LongPathsEnabled` to `1`
4. Restart

Or use this PowerShell command (admin required):
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

**Cross-Drive Moves:** Moving files from C:\ to D:\ is fully supported (uses copy+delete automatically).

**UNC Paths:** Fully supported with automatic retry logic for network latency.

### Linux

**SMB Mounts:** Ensure SMB shares are properly mounted before running:
```bash
sudo mount -t cifs //server/share /mnt/smbshare -o username=user,password=pass
```

**Permissions:** Ensure the user running the scanner has read/write permissions on all directories.

## Troubleshooting

### Common Issues

**1. "Permission denied" errors on Windows**
- File may be locked by antivirus or another process
- Scanner will automatically retry (up to 3 attempts)
- Check Windows Defender exclusions if persistent

**2. Slow performance on network paths**
- SMB/UNC paths are slower than local paths
- Reduce concurrency for network paths
- Consider using local temp storage for processing

**3. "Path does not exist" on Windows UNC**
- Ensure network share is accessible: `dir \\server\share`
- Check firewall settings
- Verify credentials have access to the share

**4. Configuration validation failed**
- Check all required fields are set (especially `appliance_ip`)
- Verify paths exist and are accessible
- Review error messages for specific issues


### References
* Additional Threat Emulation API info: [sk167161](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk167161)
* te_eb feature: [sk117168 chapter 4](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk117168#New%20Public%20API%20Interface)
