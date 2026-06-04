# Release Notes

## v11.2
1. Fixed NameError in TEX processing (config → self.config)
2. Fixed NameError in TEX error handler (E → e)
3. Removed hardcoded SECONDS_TO_WAIT/MAX_RETRIES — now read from config with 15/120 fallback
4. Fixed seconds_to_wait default to match config.ini.default (10)
5. Renamed --zip_password CLI flag to --zip-password
6. Added zip_password to CLI config mappings

## v11.1
1. Added log_path to all log messages to distinguish files with same name in different subdirectories

## v11.0
1. Added configurable email subject and body templates via string.Template
2. Added IMAP "Sent" folder saving for sent emails
3. Removed email_verbose config option (use ${file_list} placeholder in template instead)
4. Template file defaults to data/email_template.txt with sensible defaults

## v10.0
1. Added TEX (Threat Extraction / Scrub) processing alongside TE
2. TEX uses /UserCheck/TPAPI endpoint with separate URL and API key
3. TEX results written to tex_response_info/ and cleaned files to tex_clean_files/
4. TEX config: tex_enabled, tex_url, tex_api_key (config file, CLI, env vars)
5. TEX processing is non-blocking — errors do not stop TE flow
6. Watch mode and multiprocessing support TEX

## v9.2
1. Added password-protected zip archive creation for processed files
2. Zip created concurrently with file moves to verdict directories
3. Configurable via config.ini, environment variables, and CLI args

## v9.1
1. Email notifications now also sent in one-shot mode
2. process_files() returns verdict info for aggregation

## v9.0
1. Added SMTP email notifications on batch completion in watch mode
2. Configurable mail server, credentials, and recipient addresses
3. Email reports include batch summary with malicious file details

## v8.00
1. Added --watch mode for continuous file monitoring
2. Added CopyCompletionWatcher for robust copy detection (waits for file handles to close)
3. Added Windows Service and Linux systemd support
4. Batch processing with configurable delay and size limits
5. Recursive subdirectory monitoring

## v7.01
1. Added logging functionality with multiple logging levels
2. Improved error handling
3. Fixes to Windows multiprocessing issues

## v7.0
1. Complete refactoring for cross-platform support (Windows and Linux)
2. Added PathHandler for robust file operations across filesystems and network paths
3. Replaced os.rename() with shutil.move() + retry logic for Windows and SMB compatibility
4. Added ConfigManager for type-safe configuration with validation
5. Support for Windows UNC paths (\\server\share) and Linux SMB mounts
6. Added checksum verification for files moved over network paths
7. Improved error handling with platform-specific guidance
8. Foundation for watch mode (Phase 2)

## v6.3
1. TE class handles a single file at a time:
   - Queries TE cache by SHA1 before uploading
   - Uploads file if not found
   - Polls TE and TE_EB results until final verdict
2. Moves files based on verdict into benign_directory, quarantine_directory, or error_directory
3. Downloads TE reports for malicious files and saves them under reports_directory, preserving subdirectory structure from input_directory
4. SHA1 is calculated in 1KB blocks for memory efficiency
5. Uses deep copy of request template to safely modify per file
6. Implements retries for query with MAX_RETRIES and SECONDS_TO_WAIT interval
7. Exception handling: upload errors → move to error_directory; other errors logged but do not stop processing of other files
8. Supports nested subdirectories via sub_dir argument to preserve folder structure
9. All printed messages include file path for easier debugging
