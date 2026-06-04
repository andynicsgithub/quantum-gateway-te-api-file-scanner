# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`te_api` is a Python CLI tool that scans files through the Check Point Threat Emulation (TE) API. Files are submitted to an on-premises TE appliance, and moved to benign/quarantine/error directories based on the verdict. Supports two modes: one-shot (process and exit) and watch mode (continuous directory monitoring).

Current version: **11.1 (alpha)**. Cross-platform (Linux and Windows).

## Running the Scanner

```bash
# Install dependencies
pip3 install -r requirements.txt

# One-shot mode (process all files in input dir, then exit)
python3 te_api.py

# Watch mode (continuous monitoring)
python3 te_api.py --watch

# Override appliance IP from CLI
python3 te_api.py --ip 192.168.1.100

# Full help
python3 te_api.py --help
```

## Configuration

Copy `config.ini.default` to `config.ini` and edit. The minimum required setting is `appliance_ip`.

**Configuration priority (highest → lowest):** CLI args → environment variables (`TE_` prefix) → `config.ini` → built-in defaults.

Config sections:
- `[DEFAULT]` — core settings: directory paths, `appliance_ip`, `concurrency`
- `[WATCHER]` — `watch_batch_delay`, `watch_min_batch`, `watch_max_batch`
- `[LOGGING]` — `log_level`, `log_dir`, `max_log_size_mb`, `backup_count`
- `[EMAIL]` — SMTP and IMAP settings for batch notifications
- `[TEX]` — Threat Extraction/Scrub settings (`tex_enabled`, `tex_url`, `tex_api_key`)
- `[TEX_SUPPORTED_FILE_TYPES]` — per-extension enable/disable for TEX
- `[TEX_SCRUBBED_PARTS]` — numeric content-part codes to scrub

There are no automated tests in this repo.

## Architecture

### Module Overview

| Module | Purpose |
|--------|---------|
| `te_api.py` | Main entry point — CLI parsing, config loading, file discovery, parallel dispatch |
| `te_file_handler.py` | `TE` class — handles a single file end-to-end (cache query → upload → poll → verdict → move) |
| `config_manager.py` | `ScannerConfig` dataclass — type-safe config loaded from all sources |
| `path_handler.py` | `PathHandler` — static helpers for cross-platform paths, SMB/UNC, retries, checksum verification |
| `file_watcher.py` | `CopyCompletionWatcher` — watchdog-based watcher; detects file-copy completion via three-tier events |
| `notification.py` | `send_batch_notification()` — SMTP email with `string.Template`-based subject/body |
| `zip_archive.py` | `ZipArchiveManager` — password-protected zip archive for processed files |
| `safe_filename.py` | `sanitize_filename()` — converts filenames to ASCII-only for the TE API |
| `tex_results.py` | `TEX` class — handles the TEX (Threat Extraction/Scrub) API flow |
| `service_wrapper.py` | Windows Service wrapper (requires `pywin32`); Linux uses `te-watcher.service` (systemd) |
| `logger_config.py` | `setup_logging()` — rotating file handler + console, called per-process |

### Key Data Flow

1. `discover_files()` walks `input_directory` recursively, producing 4-tuples: `(real_name, safe_name, sub_dir, full_path)`. `sanitize_filename()` generates an ASCII pseudonym for any non-ASCII filenames (the TE API requires ASCII).

2. Non-archive files are processed in parallel via `multiprocessing.Pool` (concurrency set by config). Archive files are always processed **sequentially** after non-archives to avoid overwhelming the appliance.

3. Each worker calls `process_files()`, which instantiates `TE` and calls `te.handle_file()`. The `TE` class: checks SHA1 cache → uploads → polls until verdict → moves file → downloads report if malicious.

4. TEX processing runs inside `TE` alongside the standard TE flow. TEX errors are non-blocking.

5. When zip archiving is enabled, multiprocessing workers copy files to a shared temp directory; the main process consolidates them into a single zip via `ZipArchiveManager.consolidate()`. In watch/single-process mode, files are added directly.

6. After all files are processed, `send_batch_notification()` sends an email summary if `email_enabled = true`.

### Watch Mode

`file_watcher.py` uses `watchdog` to monitor `input_directory`. The `CopyCompletionWatcher` tracks files through three lifecycle events — `on_created`, `on_modified`, `on_closed` — and triggers a batch after `watch_batch_delay` seconds of inactivity once all open handles are closed.

### Logging

`setup_logging()` must be called in each subprocess (Windows `spawn` start method requires it). Log entries include the `sub_dir/file_name` path so files with the same name in different subdirectories are distinguishable. Run separators (`++++++++++`) are written directly to handler streams to avoid timestamps.
