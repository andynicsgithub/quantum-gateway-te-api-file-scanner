# TE API Scanner Watch Mode (v8.00)

## Overview

Watch mode enables continuous monitoring of the input directory for new files. When files are detected and copying is complete, they are automatically processed via the Threat Emulation API.

## Features

- **Automatic copy detection**: Waits for file handles to close (copy complete) before processing
- **Batch processing**: Collects multiple files dropped at once, waits 5 seconds for more, then processes as batch
- **Recursive monitoring**: Watches all subdirectories
- **Cross-platform**: Works on Windows (as Service) and Linux (as systemd service)
- **Flexible configuration**: Configurable batch delay, min/max batch size

## Installation

### Windows

#### Option A: Windows Service (Recommended)

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure config.ini (must be in script directory)
# Edit config.ini with your settings

# 3. Install service (run as Administrator)
python service_wrapper.py install

# 4. Configure service arguments (optional - overrides config.ini)
sc config TEWatcher binPath= "C:\Python\python.exe C:\te_api\service_wrapper.py --watch --ip 10.2.46.85"

# 5. Configure auto-start (optional)
sc config TEWatcher start=auto

# 6. Configure auto-restart on failure (recommended)
sc config TEWatcher failure=restart/restart/restart

# 7. Start service
sc start TEWatcher

# 8. Check status
sc query TEWatcher

# 9. View logs in Event Viewer
eventvwr.msc
```

**Service Account**: By default, the service runs as **Network Service** (limited privileges). If you need access to network shares or restricted folders, configure a specific user:

```powershell
sc config TEWatcher obj= "DOMAIN\\svc-te-scanner" password= "Password123"
```

#### Option B: PowerShell (Development/Testing)

```powershell
python te_api.py --watch --ip 10.2.46.85
```

Press `Ctrl+C` to stop.

### Linux

#### Option A: systemd Service (Recommended)

```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Configure config.ini (must be in script directory)

# 3. Edit service file paths
# Update WorkingDirectory and ExecStart in te-watcher.service:
# WorkingDirectory=/opt/te_api
# ExecStart=/usr/bin/python3 /opt/te_api/te_api.py --watch --ip 192.168.1.1

# 4. Install service
sudo cp te-watcher.service /etc/systemd/system/

# 5. Configure ReadWritePaths in te-watcher.service to match your directories
sudo systemctl daemon-reload

# 6. Enable and start
sudo systemctl enable te-watcher
sudo systemctl start te-watcher

# 7. Check status
sudo systemctl status te-watcher

# 8. View logs
sudo journalctl -u te-watcher -f
```

#### Option B: Direct Execution (Development/Testing)

```bash
python3 te_api.py --watch --ip 192.168.1.1
```

Press `Ctrl+C` to stop.

## Configuration

### Command-Line Arguments

```bash
python te_api.py --watch [options]

Watch Mode Options:
  --watch              Enable watch mode (continuous monitoring)
  --watch-delay SECS   Seconds to wait after last file activity (default: 5)
  --watch-min NUM      Minimum files to trigger batch (default: 0, immediate)
  --watch-max NUM      Maximum batch size (default: 0, unlimited)

Standard Options:
  --ip ADDRESS         Appliance IP address
  --input_directory    Input folder path
  --concurrency N      Parallel processing threads
```

### config.ini Sections

```ini
[DEFAULT]
# ... standard settings ...

[WATCHER]
# Wait time in seconds after last file activity before processing batch
batch_delay = 5

# Minimum files to trigger batch (0 = process immediately after delay)
min_batch_size = 0

# Maximum batch size (0 = unlimited)
max_batch_size = 0
```

## How It Works

### Copy Detection

1. **File Created**: File appears in input directory (copy started)
2. **File Modified**: File growing (copy ongoing) - resets 5-second timer
3. **File Closed**: File handle closed (copy complete) - marks file as ready
4. **Batch Check**: If all files closed + 5 seconds of silence → process batch

### Processing Flow

```
[Start] → Process existing files → Enter watch loop
                                    ↓
                    [New files arrive] → [Wait for copy complete]
                                    ↓
                    [Wait 5 seconds for more] → [Process batch]
                                    ↓
                              [Back to watch loop]
```

### Error Handling

- **Upload errors**: File moved to `error_directory`
- **Processing errors**: File moved to `error_directory`, batch continues with remaining files
- **Service crashes**: Auto-restart configured via `sc config` (Windows) or `Restart=always` (Linux)

## Examples

### Example 1: Default Configuration
```bash
# Process batches of any size after 5 seconds of silence
python te_api.py --watch --ip 10.2.46.85
```

### Example 2: Large Batch Collection
```bash
# Wait for up to 30 seconds to collect files, minimum 10 files per batch
python te_api.py --watch --watch-delay 30 --watch-min 10 --ip 10.2.46.85
```

### Example 3: Immediate Processing
```bash
# Process immediately when copy complete (no delay)
python te_api.py --watch --watch-delay 1 --ip 10.2.46.85
```

### Example 4: Limited Batch Size
```bash
# Process max 100 files per batch, then wait for next batch
python te_api.py --watch --watch-max 100 --ip 10.2.46.85
```

## Troubleshooting

### Files not being detected
- Check that input directory path is correct in config.ini
- Verify service is running: `sc query TEWatcher` (Windows) or `sudo systemctl status te-watcher` (Linux)
- Check logs: Event Viewer (Windows) or `sudo journalctl -u te-watcher` (Linux)

### Service won't start
- Check that config.ini exists in script directory
- Verify Python and dependencies are installed
- Check that input directory exists and is accessible

### Files stuck in "copying" state
- This may indicate antivirus scanning the file
- Increase `--watch-delay` if files are large and take time to settle
- Check disk space and permissions

### Permission errors on network shares
- Configure service to run as specific user with access rights
- Ensure user account has "Log on as a service" right (Windows)

## Service Management

### Windows

```powershell
# Start
sc start TEWatcher

# Stop (immediate - current batch not completed)
sc stop TEWatcher

# Pause (not supported)

# View logs
eventvwr.msc → Windows Logs → Application → Source: TEWatcher
```

### Linux

```bash
# Start
sudo systemctl start te-watcher

# Stop
sudo systemctl stop te-watcher

# Restart
sudo systemctl restart te-watcher

# View logs
sudo journalctl -u te-watcher -f
```

## Security Considerations

- **Network Service Account**: Uses limited privileges by default
- **No interactive access**: Service cannot access user desktop or interactive sessions
- **Network shares**: May require specific user account if computer account lacks permissions
- **Immediate stop**: Service does not complete current batch on stop (configurable in future versions)

## Version History

- **v8.00**: Initial release of watch mode
  - Copy completion detection via file handles
  - Batch processing with configurable delay
  - Windows Service and Linux systemd support
  - Recursive subdirectory monitoring
