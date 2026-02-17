# te_api

**Version 7.0** - Cross-platform Python client for Check Point Threat Emulation API

A Python client side utility for using Threat Emulation API calls to an on-premises Check Point gateway (or Threat Emulation appliance). **Now with full Windows and Linux support, including SMB/UNC network paths.**

The utility will parse a directory tree, and use the Threat Emulation API to scan the files.
Files will be moved from the source or "input" directory to one of the following directories:
- Benign files will be moved to the "benign" directory.
- Malicious files will be moved to the "quarantine" directory.
- Files that can't be correctly processed will be moved to the "error" directory.
- Transcripts of the API session for each file are saved in the "reports" directory.
- For any file found to be malicious, the Threat Emulation report is also downloaded and saved in the "reports" directory.
- UNC paths are supported, so this application may be used as part of a secure transfer methodology, e.g. set the "benign" directory to be \\192.168.1.2\share to ensure that only safe files are transferred to the destination.
- All files are processed using the Check Point recommended OS versions for maximum detection rate. At the moment, no custom choice of OS versions is possible in the application.


Normal files, i.e. files that are not archives, will be processed in a parallel fashion. Change the "concurrency" value to suit the capacity of your environment to avoid overloading or slowing down the processing of files from other sources.

Archive files are expanded the Threat Emulation and all files within them are analysed. This can lead to very large numbers of files being processed at once, so this application sends archive files one at a time after the normal files. If one or more files in the archive are found malicious, the whole parent archive file is marked as malicious, and moved to the quarantine directory.

Note that this utility will move (not copy) all files from the input directory to the output directories, leaving the input directory empty.


## Platform Support

**Supported Platforms:**
- ✅ Linux (tested on Ubuntu)
- ✅ Windows (Windows 10/11)


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
- Network access to Check Point API-enabled appliance

### Install Dependencies

**Linux:**
```bash
pip3 install -r requirements.txt
```

**Windows:**
```powershell
pip install -r requirements.txt
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

Command-line arguments override both config file and environment variables. This is useful if you want to use the application to process a few files in a different way on an occasional basis. To see the command structure and arguments, run:

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
