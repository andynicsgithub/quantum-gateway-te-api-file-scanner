# te_api

**Version 10.0** - Cross-platform Python client for Check Point Threat Emulation API

A Python client side utility for using Threat Emulation API calls to an on-premises Check Point gateway (or Threat Emulation appliance). **Now with full Windows and Linux support, including SMB/UNC network paths and continuous directory monitoring.**

## Two Modes of Operation

### 1. One-Shot Mode (Default)
Processes all files in the input directory once, then exits. Ideal for manual or scheduled scans.

### 2. Watch Mode (Continuous)
Monitors the input directory continuously, automatically processing files as they arrive. Ideal for unattended operation. Files are processed when copying is complete, with configurable batch collection delays.

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

## Watch Mode (Continuous Monitoring)

Watch mode enables automatic, unattended file scanning. The scanner monitors the input directory 24/7, processing files as they are dropped in.

### How It Works

1. **File Created** → Scanner detects new file (copy started)
2. **File Modified** → File growing (copy ongoing) - resets delay timer
3. **File Stable** → No changes for `batch_delay` seconds (copy complete)
4. **Batch Processed** → Files sent to TE appliance for scanning

When the scanner starts, it immediately processes any files already in the input directory, then enters the watch loop.

### Watch Mode Configuration

Add the `[WATCHER]` section to your `config.ini`:

```ini
[WATCHER]
# Seconds to wait after last file activity before processing batch
batch_delay = 5

# Minimum files to trigger batch (0 = process immediately after delay)
min_batch_size = 0

# Maximum batch size (0 = unlimited)
max_batch_size = 0
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--watch` | Enable continuous watch mode | Disabled |
| `--watch-delay SECS` | Seconds to wait after last file activity | 5 |
| `--watch-min NUM` | Minimum files to trigger batch | 0 (immediate) |
| `--watch-max NUM` | Maximum batch size | 0 (unlimited) |

### Watch Mode Examples

**Basic usage:**
```bash
python te_api.py --watch --ip 192.168.1.100
```

**Custom batch delay and minimum files:**
```bash
python te_api.py --watch --watch-delay 10 --watch-min 5 --ip 192.168.1.100
```

**Process files immediately (no delay):**
```bash
python te_api.py --watch --watch-delay 1 --ip 192.168.1.100
```

### Running as a Service

For production use, run the scanner as a service so it starts automatically and restarts on failure.

#### Windows Service

```powershell
# Install the service (run as Administrator)
python service_wrapper.py install

# Configure with auto-start and auto-restart
sc config TEWatcher start=auto
sc config TEWatcher failure=restart/restart/restart

# Start the service
sc start TEWatcher

# Check status
sc query TEWatcher

# View logs in Event Viewer
eventvwr.msc → Windows Logs → Application → Source: TEWatcher
```

#### Linux systemd Service

```bash
# Install service file
sudo cp te-watcher.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable te-watcher
sudo systemctl start te-watcher

# Check status
sudo systemctl status te-watcher

# View logs
sudo journalctl -u te-watcher -f
```

**Service Account:** By default, services run with limited privileges (Network Service on Windows, `network` user on Linux). If you need access to network shares or restricted folders, configure a specific user account.

### Email Notifications

The scanner can send batch completion email notifications via SMTP. Notifications are sent after each batch finishes processing in watch mode, and after all files are processed in one-shot mode.

**Configuration in config.ini:**

```ini
[EMAIL]
email_enabled = true
email_smtp_server = smtp.example.com
email_smtp_port = 587
email_use_tls = true
email_username = user@example.com
email_password = your_password
email_from = scanner@example.com
email_to = admin@example.com
email_verbose = false
```

**Configuration Options:**

| Setting | Description | Default |
|---------|-------------|---------|
| `email_enabled` | Enable email notifications | false |
| `email_smtp_server` | SMTP server hostname or IP | - |
| `email_smtp_port` | SMTP server port | 587 |
| `email_use_tls` | Use TLS for SMTP connection | true |
| `email_username` | SMTP authentication username | - |
| `email_password` | SMTP authentication password | - |
| `email_from` | Sender email address | - |
| `email_to` | Recipient email address | - |
| `email_verbose` | Include detailed file list with verdicts | false |

**Verbose Mode:** When `email_verbose = true`, the email includes a flat list of all processed files with their relative paths and verdicts:

```
File Details:
  malware.exe - Malicious
  docs/report.pdf - Benign
  subdir/archive.zip - Malicious
  subdir/data.csv - Benign
```

**Command-Line Options:**

| Option | Description |
|--------|-------------|
| `--email-enabled` | Enable email notifications |
| `--email-smtp-server HOST` | SMTP server hostname or IP |
| `--email-smtp-port PORT` | SMTP server port |
| `--email-use-tls` | Use TLS for SMTP connection |
| `--email-username USER` | SMTP authentication username |
| `--email-password PASS` | SMTP authentication password |
| `--email-from ADDR` | Sender email address |
| `--email-to ADDR` | Recipient email address |
| `--email-verbose` | Include detailed file list with verdicts |

**Example:**

```bash
python te_api.py --watch --email-enabled --email-smtp-server 10.1.48.103 --email-to admin@example.com --email-from scanner@example.com --email-verbose
```

**Note:** Email notifications require the `[EMAIL]` section to be properly configured in `config.ini` with the correct key names (`email_enabled`, `email_smtp_server`, etc.). Keys without the `email_` prefix will not be recognized.

### TEX (Threat Extraction / Scrub)

TEX is an additional processing path that runs alongside the standard TE Cloud API. Files are uploaded to a separate TPAPI endpoint where they are "scrubbed" of potentially malicious content, and a cleaned version is returned. TEX is fully independent of TE — errors do not stop the TE flow.

**Configuration in config.ini:**

```ini
[TEX]
tex_enabled = true
tex_url = https://10.1.46.85/UserCheck/TPAPI
tex_api_key = hkPBkzSnx94mU1ASD4yPF936PW6TqQ45
tex_response_info_directory = tex_response_info
tex_clean_files_directory = tex_clean_files

[TEX_SUPPORTED_FILE_TYPES]
; Extensions to send to TEX API (enable/disable individually)
; Empty section or missing entry = skip all file types
bmp = true
doc = true
docm = true
docx = true
pdf = true
...

[TEX_SCRUBBED_PARTS]
; Which content parts to scrub (enable/disable individually)
; Disabled entries (false) are excluded from the scrub request
1017 = true   ; Custom Properties
1018 = true   ; Database Queries
1019 = true   ; Embedded Objects
...
```

**Configuration Options:**

| Setting | Description | Default |
|---------|-------------|---------|
| `tex_enabled` | Enable TEX processing | false |
| `tex_url` | TPAPI endpoint URL | - |
| `tex_api_key` | API key for TPAPI | - |
| `tex_response_info_directory` | Directory for TEX response info files | tex_response_info |
| `tex_clean_files_directory` | Directory for cleaned/scrubbed files | tex_clean_files |

**TEX Supported File Types:** The `[TEX_SUPPORTED_FILE_TYPES]` section defines which file extensions are sent to TEX. Files with extensions not listed (or set to `false`) are skipped from TEX processing but still go through the standard TE flow. If the section is empty or missing, no files are sent to TEX.

**TEX Scrubbed Parts Codes:** The `[TEX_SCRUBBED_PARTS]` section defines which content parts are scrubbed. Each code corresponds to a content type (e.g., `1026` = Macros and Code, `1141` = PDF URI Actions). Disabled parts are excluded from the scrub request. If the section is empty or missing, all parts are scrubbed.

**TEX Output:**
- Cleaned files are written to `tex_clean_files_directory/` with the name returned by the API (e.g., `document.cleaned.docx`)
- Response info is written to `tex_response_info/` with the filename `filename.response.txt`
- TEX errors are non-blocking — TE processing continues on TEX failure

**Command-Line Options:**

| Option | Description |
|--------|-------------|
| `--tex-enabled` | Enable TEX processing |
| `--tex-url URL` | TPAPI endpoint URL |
| `--tex-api-key KEY` | API key for TPAPI |
| `--tex-response-info-dir DIR` | Directory for TEX response info files |
| `--tex-clean-files-dir DIR` | Directory for cleaned/scrubbed files |

**Example:**

```bash
python te_api.py --tex-enabled --tex-url https://10.1.46.85/UserCheck/TPAPI --tex-api-key hkPBkzSnx94mU1ASD4yPF936PW6TqQ45
```

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

### Watch Mode Configuration

For continuous monitoring, add the `[WATCHER]` section to your `config.ini`:

```ini
[WATCHER]
# Seconds to wait after last file activity before processing batch
batch_delay = 5

# Minimum files to trigger batch (0 = process immediately after delay)
min_batch_size = 0

# Maximum batch size (0 = unlimited)
max_batch_size = 0
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
    --watch                Enable continuous watch mode
    --watch-delay SECS     Seconds to wait after last file activity (default: 5)
    --watch-min NUM        Minimum files to trigger batch (default: 0)
    --watch-max NUM        Maximum batch size (default: 0, unlimited)
    --email-enabled        Enable email notifications
    --email-smtp-server    SMTP server hostname or IP
    --email-smtp-port      SMTP server port (default: 587)
    --email-use-tls        Use TLS for SMTP connection
    --email-username       SMTP authentication username
   --email-password       SMTP authentication password
    --email-from           Sender email address
    --email-to             Recipient email address
    --email-verbose        Include detailed file list with verdicts
    --tex-enabled           Enable TEX processing
    --tex-url URL          TPAPI endpoint URL
    --tex-api-key KEY      API key for TPAPI
    --tex-response-info-dir DIR  Directory for TEX response info files
    --tex-clean-files-dir DIR      Directory for cleaned/scrubbed files
    ```

**Configuration Priority** (highest to lowest):
1. Command-line arguments
2. Environment variables
3. Configuration file (`config.ini`)
4. Built-in defaults

### Logging Configuration

The scanner includes comprehensive logging with automatic rotation to prevent log files from growing too large.

**Log Settings in config.ini:**
```ini
[LOGGING]
log_level = INFO
log_dir = ./logs
max_log_size_mb = 10
backup_count = 5
```

**Configuration Options:**

| Setting | Description | Default |
|---------|-------------|---------|
| `log_level` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) | INFO |
| `log_dir` | Directory where log files are stored | ./logs |
| `max_log_size_mb` | Maximum size of log file before rotation (MB) | 10 |
| `backup_count` | Number of backup log files to keep | 5 |

**Log Rotation Behavior:**
- When `te_scanner.log` reaches `max_log_size_mb`, it rotates automatically
- Previous logs become `te_scanner.log.1`, `te_scanner.log.2`, etc.
- Oldest logs are deleted when exceeding `backup_count`
- Each application run is separated by a visual marker (`++++++++++`) for easy reading

**Example Log Output:**
```
2026-03-06T19:17:57 - te_scanner - INFO - Processing complete!

++++++++++

2026-03-06T19:18:15 - te_scanner - INFO - TE API Scanner v7.01 - Loading configuration...
```

**Log Retention Example:**
With `max_log_size_mb = 10` and `backup_count = 5`:
- Maximum disk usage: ~60 MB (current + 5 backups × 10 MB each)
- Adjust these values based on your scan volume and retention requirements

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

### Watch Mode Examples

**Basic watch mode (uses config.ini settings):**
```bash
python te_api.py --watch
```

**Override config settings from command line:**
```bash
python te_api.py --watch --ip 192.168.1.100 --watch-delay 10
```

**Continuous monitoring with minimum batch size:**
```bash
python te_api.py --watch --watch-min 5 --watch-delay 15 --ip 192.168.1.100
```

Press `Ctrl+C` to stop the watcher in development mode.

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
