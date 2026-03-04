# TE API Scanner - Code Analysis

## Overview
This is a Threat Emulation (TE) API file scanner that scans files for malware using Check Point's Threat Emulation technology. The scanner processes files through TE and TE_EB (Threat Emulation with Extraction) features.

## Architecture
The system consists of 4 main Python modules:

---

## 1. te_api.py (Main Entry Point)
**Version:** 7.0  
**Purpose:** Main entry point and orchestrator

### Key Functions:
- **Argument parsing** - CLI args for directories, appliance IP, concurrency
- **Configuration loading** - Integrates config.ini, env vars, and CLI args
- **File discovery** - Recursively scans input directory, separates archives from regular files
- **Parallel processing** - Processes non-archive files with multiprocessing pool
- **Sequential processing** - Handles archive files one at a time
- **Cleanup** - Removes empty subdirectories after processing

### Flow:
1. Parse CLI arguments
2. Load and validate configuration (ScannerConfig)
3. Discover files in input directory
4. Process files (parallel for non-archives, sequential for archives)
5. Clean up empty directories

### Key Variables:
- `SECONDS_TO_WAIT = 15` - Polling interval for TE queries
- `MAX_RETRIES = 120` - Maximum query attempts

---

## 2. te_file_handler.py (Core File Processing)
**Version:** 6.3  
**Purpose:** Handles individual file processing via TE API

### Class: `TE`

### Key Methods:

#### `handle_file()`
Main orchestrator method:
1. Check TE cache by SHA1
2. If not cached, upload file
3. Poll for results until verdict received
4. Write response info
5. Move file based on verdict (benign/quarantine/error)

#### `check_te_cache()`
- Calculates file SHA1 hash
- Queries TE cache to check for existing results
- Returns query response

#### `upload_file()`
- Uploads file to TE appliance
- Returns upload response
- On failure, moves file to error directory

#### `query_file()`
- Polls TE and TE_EB for results every 15 seconds
- Handles PENDING and PARTIALLY_FOUND states
- Detects early malicious verdicts from TE_EB
- Retries up to 120 times (30 minutes max)

#### `download_report()`
- Downloads detailed TE report for malicious files
- Saves as .tar.gz in reports directory
- Base64 decodes the response

#### `move_file(destination)`
- Moves processed files to appropriate directory
- Uses PathHandler for cross-platform support
- Handles network paths with retry logic

### File Movement Logic:
- **Benign verdict** → benign_directory
- **Malicious verdict** → quarantine_directory + download report
- **Error/Other verdicts** → error_directory

### Constants:
- `SECONDS_TO_WAIT = 15` - Query polling interval
- `MAX_RETRIES = 120` - Maximum query attempts

---

## 3. path_handler.py (Cross-Platform Path Utilities)
**Purpose:** Cross-platform path handling with network path support

### Class: `PathHandler`

### Key Methods:

#### `normalize_path(path_str)`
- Normalizes paths for current platform
- Expands user home (~) and environment variables
- Returns pathlib.Path object

#### `is_windows()` / `is_unc_path(path)`
- Platform detection
- UNC path detection (Windows network paths)

#### `is_smb_path(path)`
- Detects SMB/network paths:
  - Windows: UNC paths (\\server\share)
  - Linux: Common mount points (/mnt, /media, /net, /smb, /cifs)

#### `validate_path(path, create=False, retry_count=3)`
- Validates path accessibility
- Creates directories if requested
- Retry logic for network paths with exponential backoff
- Returns (success, message) tuple

#### `safe_move(src, dst, verify_checksum=None, retry_count=3)`
- Cross-filesystem file moves
- Handles Windows file locking
- Auto-enables checksum verification for network paths
- Verifies SHA1 hash after move to detect corruption
- Exponential backoff retry logic

#### `_calculate_sha1(file_path)`
- Calculates SHA1 hash in 1KB blocks
- Used for integrity verification

#### `supports_long_paths()`
- Checks Windows registry for long path support (>260 chars)

---

## 4. config_manager.py (Configuration Management)
**Purpose:** Type-safe configuration management

### Class: `ScannerConfig` (dataclass)

### Configuration Sources (Priority Order):
1. Hardcoded defaults (lowest)
2. Environment variables (TE_ prefix)
3. Config file (config.ini)
4. Command-line arguments (highest)

### Configuration Options:
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| input_directory | Path | input_files | Source files to scan |
| reports_directory | Path | te_response_data | TE API responses |
| benign_directory | Path | benign_files | Benign files destination |
| quarantine_directory | Path | quarantine_files | Malicious files destination |
| error_directory | Path | error_files | Error files destination |
| appliance_ip | str | '' | TE appliance IP address |
| concurrency | int | 4 | Parallel workers |
| seconds_to_wait | int | 15 | Query polling interval |
| max_retries | int | 120 | Max query attempts |
| watch_mode | bool | False | Watch directory for new files |

### Key Methods:

#### `from_sources(config_file, cli_args, env_prefix)`
- Loads configuration from multiple sources
- Applies precedence rules
- Normalizes all paths

#### `validate()`
- Validates all settings
- Checks directory accessibility
- Creates output directories if needed
- Returns (is_valid, errors) tuple

#### `print_summary()`
- Displays configuration for user verification
- Warns about network paths

---

## File Flow

```
1. te_api.py discovers files in input_directory
   ↓
2. For each file, creates TE instance
   ↓
3. TE.handle_file():
   a. Check cache by SHA1
   b. If not cached → upload file
   c. Poll for results
   d. Write response to reports_directory
   e. Move file to appropriate directory based on verdict
   ↓
4. te_api.py cleans up empty directories
```

## Archive Handling
- Archive files (.zip, .rar, .7z, etc.) are processed **sequentially**
- Non-archive files are processed in **parallel** (configurable concurrency)

## Supported Archive Extensions
`.7z`, `.arj`, `.bz2`, `.CAB`, `.dmg`, `.gz`, `.img`, `.iso`, `.msi`, `.pkg`, `.rar`, `.tar`, `.tbz2`, `.tbz`, `.tb2`, `.tgz`, `.xz`, `.zip`, `.udf`, `.qcow2`

## Error Handling
- **Upload failures** → Move to error_directory
- **Query timeouts** → Log and continue
- **Permission errors** → Retry with backoff
- **Checksum mismatches** → Delete corrupted file, report failure

## Dependencies
```
requests        # HTTP API calls
urllib3         # SSL warnings disable
pathlib         # Path manipulation
shutil          # File operations
hashlib         # SHA1 calculation
configparser    # Config file parsing
dataclasses     # Type-safe config (Python 3.7+)
```

## API Endpoints Used
- `POST /tecloud/api/v1/file/query` - Query cache/results
- `POST /tecloud/api/v1/file/upload` - Upload file
- `GET /tecloud/api/v1/file/download?id={report_id}` - Download report

## Platform Support
- **Linux** - Full support with SMB mount detection
- **Windows** - Full support with UNC path support, long path warnings
- **Cross-filesystem** - Handles moves between different filesystems
