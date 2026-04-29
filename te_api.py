#!/usr/bin/env python3

"""
te_api v9.2 (alpha)
A Python client-side utility for interacting with the Threat Emulation API.
Features:
  - Scan input files in a specified directory
  - Handle TE and TE_EB processing via the appliance
  - Store results in an output directory
  - Support concurrent processing of multiple files (via command line argument or config.ini)
  - Move files from source directory to benign_directory, quarantine_directory, or error_directory based on TE verdict
  - Create password-protected zip archives of processed files (configurable)
  - Cross-platform support (Linux and Windows)
  - SMB/UNC network path support with retry logic
  - Watch mode: continuous monitoring of input directory with batch processing

Changes in v9.2 over v9.1:
  1. Added password-protected zip archive creation for processed files
  2. Zip created concurrently with file moves to verdict directories
  3. Configurable via config.ini, environment variables, and CLI args

Changes in v9.1 over v9.0:
  1. Added email_verbose option for detailed file listing with verdicts in email
  2. Email notifications now also sent in one-shot mode
  3. process_files() returns verdict info for aggregation

Changes in v9.0 over v8.00:
  1. Added SMTP email notifications on batch completion in watch mode
  2. Configurable mail server, credentials, and recipient addresses
  3. Email reports include batch summary with malicious file details

Changes in v8.00 over v7.01:
  1. Added --watch mode for continuous file monitoring
  2. Added CopyCompletionWatcher for robust copy detection (waits for file handles to close)
  3. Added Windows Service and Linux systemd support
  4. Batch processing with configurable delay and size limits
  5. Recursive subdirectory monitoring

Changes in v7.01 over v7.0:
  1. Added logging functionality with multiple logging levels
  2. Improved error handling
  3. Fixes to Windows multiprocessing issues

Changes in v7.0 over v6.3:
  1. Complete refactoring for cross-platform support (Windows and Linux)
  2. Added PathHandler for robust file operations across filesystems and network paths
  3. Replaced os.rename() with shutil.move() + retry logic for Windows and SMB compatibility
  4. Added ConfigManager for type-safe configuration with validation
  5. Support for Windows UNC paths (\\\\server\\share) and Linux SMB mounts
  6. Added checksum verification for files moved over network paths
  7. Improved error handling with platform-specific guidance
  8. Foundation for watch mode (Phase 2)
"""

from te_file_handler import TE
from config_manager import ScannerConfig
from path_handler import PathHandler
from logger_config import setup_logging
from zip_archive import ZipArchiveManager
import os
import shutil
import argparse
import multiprocessing
import logging
from pathlib import Path
from functools import partial
from datetime import datetime

# =======================
# Main entry point
# =======================

def main():
    """
    MAIN ENTRY POINT
    1. Parse command-line arguments
    2. Load configuration from file/env/cli with proper precedence
    3. Validate configuration and create directories
    4. Set API URL and discover files
    5. Process files (archives sequentially, others in parallel)
    6. Clean up empty directories
    """
    # =======================
    # Parse CLI Arguments
    # =======================
    
    parser = argparse.ArgumentParser(
        description='TE API Scanner - Cross-platform threat emulation file scanner'
    )
    parser.add_argument("-in", "--input_directory", help="the input files folder to be scanned by TE")
    parser.add_argument("-rep", "--reports_directory", help="the output folder with TE results")
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address")
    parser.add_argument('-n', '--concurrency', type=int, help='Number of concurrent file processes')
    parser.add_argument('-out', '--benign_directory', help='the directory to move Benign files after scanning')
    parser.add_argument('-jail', '--quarantine_directory', help='the directory to move Malicious files after scanning')
    parser.add_argument('-error', '--error_directory', help='the directory to move files which cause a scanning error')
    parser.add_argument('--watch', action='store_true', help='Watch mode: monitor directory for new files continuously')
    parser.add_argument('--watch-delay', type=int, default=5, help='Seconds to wait after last file activity before processing batch (default: 5)')
    parser.add_argument('--watch-min', type=int, default=0, help='Minimum files to trigger batch (0 = process immediately after delay)')
    parser.add_argument('--watch-max', type=int, default=0, help='Maximum batch size (0 = unlimited)')
    
    # Email notification CLI args
    parser.add_argument('--email-enabled', action='store_true', help='Enable email notifications on batch completion')
    parser.add_argument('--email-smtp-server', help='SMTP server hostname or IP')
    parser.add_argument('--email-smtp-port', type=int, help='SMTP server port (default: 587)')
    parser.add_argument('--email-use-tls', action='store_true', help='Use TLS for SMTP connection')
    parser.add_argument('--email-username', help='SMTP authentication username')
    parser.add_argument('--email-password', help='SMTP authentication password')
    parser.add_argument('--email-from', help='Sender email address')
    parser.add_argument('--email-to', help='Recipient email address')
    parser.add_argument('--email-verbose', action='store_true', help='Include detailed file list with verdicts in email notifications')
    
    # Zip archive CLI args
    parser.add_argument('-za', '--zip_archive_directory', help='Directory to store password-protected zip archives of processed files')
    parser.add_argument('--zip_password', help='Password for zip archives (empty or not provided = no zip archive)')
    args = parser.parse_args()
    
    # =======================
    # Load and Validate Config
    # =======================
    
    # Initialize logging first so we can log configuration loading
    # We'll get basic config without logging first to know where to put logs
    config = ScannerConfig.from_sources(config_file='config.ini', cli_args=args)
    
    # Now setup logging with loaded configuration
    logger = setup_logging(
        log_dir=config.log_dir,
        log_level=getattr(logging, config.log_level.upper()),
        max_bytes=config.max_log_size_mb * 1024 * 1024,
        backup_count=config.backup_count
    )
    
    logger.info("TE API Scanner v9.2 - Loading configuration...")
    
    # Display configuration summary
    config.print_summary()
    
    # Validate configuration
    is_valid, errors = config.validate()
    if not is_valid:
        logger.error("Configuration validation failed:")
        for error in errors:
            logger.error(f"  ERROR: {error}")
        parser.print_help()
        return 1
    
    logger.info("Configuration validated successfully")
    
    # Build API URL
    url = f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/"
    
    # Warn about Windows long path support if applicable
    if PathHandler.is_windows() and not PathHandler.supports_long_paths():
        logger.warning("Windows long path support is not enabled.")
        logger.warning("         Paths over 260 characters may fail.")
        logger.warning("         See: https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation")
    
    # =======================
    # Watch Mode vs One-Shot Mode
    # =======================
    
    if config.watch_mode:
        # Check for required dependencies
        if PathHandler.is_windows():
            try:
                import win32serviceutil
            except ImportError:
                logger.error("ERROR: pywin32 is not installed.")
                logger.error("Run: pip install pywin32")
                logger.error("Or: pip install -r requirements.txt")
                return 1
        
        try:
            import watchdog.observers
        except ImportError:
            logger.error("ERROR: watchdog is not installed.")
            logger.error("Run: pip install watchdog")
            logger.error("Or: pip install -r requirements.txt")
            return 1
        
        # Watch mode: process existing files, then monitor
        logger.info("Starting in WATCH mode")
        logger.info("Dependencies check passed.")
        
        # Prepare zip archive if password is configured
        zip_mgr = None
        zip_timestamp = None
        if config.zip_password:
            zip_timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            zip_mgr = ZipArchiveManager.create_archive(config.zip_archive_directory, config.zip_password, zip_timestamp)
            if zip_mgr:
                logger.info(f"Zip archive enabled: {zip_mgr.zip_path}")
            else:
                logger.warning("Failed to initialize zip archive, proceeding without it")
        
        # Process any existing files immediately
        archive_files, other_files = discover_files(config.input_directory)
        if archive_files or other_files:
            logger.info(f"Processing {len(archive_files) + len(other_files)} existing files...")
            process_discovered_files(archive_files, other_files, config, url, zip_mgr)
            find_and_delete_empty_subdirectories(config.input_directory)
            if zip_mgr:
                zip_mgr.close()
        else:
            logger.info("No existing files to process.")
            if zip_mgr:
                zip_mgr.abort()
        
        # Start watching (blocking call)
        from file_watcher import start_watching
        try:
            start_watching(config, url, zip_mgr)
        except Exception as e:
            logger.error(f"ERROR starting watcher: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 1
        
    else:
        # One-shot mode: process and exit
        logger.info("Starting in ONE-SHOT mode")
        logger.info(f"Parallel processing of {config.concurrency} files at once")
        
        # Prepare zip archive if password is configured
        zip_mgr = None
        if config.zip_password:
            zip_timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            zip_mgr = ZipArchiveManager.create_archive(config.zip_archive_directory, config.zip_password, zip_timestamp)
            if zip_mgr:
                logger.info(f"Zip archive enabled: {zip_mgr.zip_path}")
            else:
                logger.warning("Failed to initialize zip archive, proceeding without it")
        
        # Discover files
        archive_files, other_files = discover_files(config.input_directory)
        
        logger.info(f"Begin handling input files by TE")
        logger.info(f"Found {len(archive_files)} archive files and {len(other_files)} non-archive files")
        
        if len(other_files) == 0 and len(archive_files) == 0:
            logger.info("No files to process. Exiting.")
            if zip_mgr:
                zip_mgr.abort()
            return 0
        
        # Process files
        process_discovered_files(archive_files, other_files, config, url, zip_mgr)
        find_and_delete_empty_subdirectories(config.input_directory)
        
        if zip_mgr:
            zip_mgr.close()
        
        logger.info("Processing complete!")
        # Write separator directly to handlers (without timestamps)
        for handler in logger.handlers:
            if hasattr(handler, 'stream') and handler.stream:
                stream = handler.stream
                stream.write("\n")
                stream.write("++++++++++\n")
                stream.write("\n")
                stream.flush()
    
    return 0


# =======================
# Utility Functions
# =======================

def discover_files(input_directory):
    """
    Discover files in input directory and categorize them as archives or other.
    
    Args:
        input_directory: Path to input directory
        
    Returns:
        Tuple of (archive_files, other_files) as sets of (file_name, sub_dir, full_path) tuples
    """
    logger = logging.getLogger('te_scanner.main')
    
    # Identify archive vs other files
    archive_extensions = [".7z", ".arj", ".bz2", ".CAB", ".dmg", ".gz", ".img", ".iso", ".msi", ".pkg", ".rar", ".tar", ".tbz2", ".tbz", ".tb2", ".tgz", ".xz", ".zip", ".udf", ".qcow2"]

    archive_files = set()
    other_files = set()

    # Recursively walk through input_directory
    logger.info(f"Scanning input directory: {input_directory}")
    for root, dirs, files in os.walk(str(input_directory)):
        # Extract the subdirectory relative to the input_directory
        sub_dir = os.path.relpath(root, input_directory)
        for file in files:
            full_path = os.path.join(root, file)
            file_nameonly, file_extension = os.path.splitext(file)

            # Create a tuple with the file name, subdirectory, root, and full path
            file_info = (file, sub_dir, full_path)

            if file_extension.lower() in archive_extensions:
                archive_files.add(file_info)
            else:
                other_files.add(file_info)
    
    return archive_files, other_files

def process_discovered_files(archive_files, other_files, config, url, zip_mgr=None):
    """
    Process discovered files using the existing processing logic.
    
    In multiprocessing mode, non-archive files are copied to a temp directory by
    workers, then consolidated into the zip by the main process.
    Archive files are processed sequentially in the main process and added directly
    to the zip.
    
    Args:
        archive_files: Set of (file_name, sub_dir, full_path) tuples
        other_files: Set of (file_name, sub_dir, full_path) tuples
        config: ScannerConfig object
        url: TE API URL
        zip_mgr: ZipArchiveManager instance (None if disabled)
    """
    from notification import send_batch_notification
    
    logger = logging.getLogger('te_scanner.main')
    
    # Collect results for email notification
    all_files = []
    
    # Build temp directory and zip config for multiprocessing workers
    zip_config = None
    temp_dir = None
    verdict_basenames = [
        os.path.basename(str(config.benign_directory)),
        os.path.basename(str(config.quarantine_directory)),
        os.path.basename(str(config.error_directory))
    ]
    if zip_mgr:
        temp_dir = str(Path(config.zip_archive_directory) / f"te_zip_{datetime.now().strftime('%Y%m%d%H%M%S_%f')}")
        os.makedirs(temp_dir, exist_ok=True)
        logger.info(f"Zip temp directory: {temp_dir}")
        logger.info(f"Zip config tuple: {zip_config is not None}, len={len(zip_config) if zip_config else 0}")
        zip_config = (
            str(zip_mgr.zip_path),
            config.zip_password,
            verdict_basenames[0],
            verdict_basenames[1],
            verdict_basenames[2],
            temp_dir
        )
    
    # Non-archive files: parallel processing (workers copy to temp dir)
    if len(other_files) > 0:
        logger.info(f"Processing {len(other_files)} non-archive files with concurrency={config.concurrency}")
        process_func = partial(process_files, config=config, url=url, zip_config=zip_config)
        
        with multiprocessing.Pool(config.concurrency) as pool:
            results = pool.starmap(process_func, other_files)
            all_files.extend(results)

    # Archive files: sequential processing in main process (add directly to zip)
    if len(archive_files) > 0:
        logger.info(f"Processing {len(archive_files)} archive files sequentially")
        for file_info in archive_files:
            file_name, sub_dir, full_path = file_info
            result = process_files(file_name, sub_dir, full_path, config, url, zip_config=zip_mgr)
            all_files.append(result)
    
    # Consolidate temp directory files into the zip (multiprocessing mode)
    if zip_mgr and temp_dir:
        try:
            zip_mgr.consolidate(temp_dir, verdict_basenames, config.zip_password)
        except Exception as e:
            logger.error(f"Failed to consolidate temp files into zip: {e}")
    
    # Cleanup temp directory
    if temp_dir and os.path.exists(temp_dir):
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            logger.warning(f"Failed to clean up temp directory {temp_dir}: {e}")
    
    # Send email notification if enabled
    if config.email_enabled:
        batch_summary = {
            'processed': len(all_files),
            'benign': sum(1 for f in all_files if f.get('verdict') == 'Benign'),
            'malicious': sum(1 for f in all_files if f.get('verdict') == 'Malicious'),
            'error': sum(1 for f in all_files if f.get('status') == 'error' or f.get('verdict') == 'Error'),
            'malicious_files': [
                {'name': f['name'], 'verdict': f['verdict']}
                for f in all_files if f.get('verdict') == 'Malicious'
            ],
            'all_files': all_files,
        }
        try:
            send_batch_notification(config, batch_summary)
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")

def find_and_delete_empty_subdirectories(input_directory):
    """
    Finds and deletes all empty subdirectories under the specified input_directory.
    
    Args:
        input_directory (str): The root directory to start the search.
    """
    logger = logging.getLogger('te_scanner.main')
    for root, dirs, files in os.walk(input_directory, topdown=False):
        # Iterate in reverse order to avoid issues with modifying the list while iterating
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            if not os.listdir(dir_path):  # Check if the directory is empty
                try:
                    os.rmdir(dir_path)  # Remove the empty directory
                    logger.debug(f"Deleted empty directory: {dir_path}")
                except Exception as e:
                    logger.warning(f"Error deleting directory {dir_path}: {str(e)}")

def process_files(file_name, sub_dir, full_path, config, url, zip_config=None):
    """
    Process a single file through the TE API.
    
    Args:
        file_name: Name of the file
        sub_dir: Subdirectory relative to input_directory
        full_path: Full path to the file
        config: ScannerConfig object
        url: TE API URL
        zip_config: Tuple of (zip_path, zip_password, benign_basename, quarantine_basename, error_basename)
        
    Returns:
        dict with keys: 'name', 'path', 'verdict', 'status'
    """
    # Initialize logging for this worker process (needed for Windows spawn)
    setup_logging(
        log_dir=config.log_dir,
        log_level=getattr(logging, config.log_level.upper()),
        max_bytes=config.max_log_size_mb * 1024 * 1024,
        backup_count=config.backup_count
    )
    
    logger = logging.getLogger('te_scanner.main')
    result = {'name': file_name, 'path': sub_dir if sub_dir else '', 'verdict': 'Unknown', 'status': 'error'}
    try:
        logger.info(f"Handling file: {file_name} (zip_config type={type(zip_config).__name__})")
        te = TE(
            url, 
            file_name, 
            sub_dir, 
            full_path, 
            config.input_directory,
            config.reports_directory, 
            config.benign_directory, 
            config.quarantine_directory, 
            config.error_directory,
            zip_config=zip_config
        )
        te.handle_file()
        
        if te.final_status_label == "FOUND":
            verdict = te.parse_verdict(te.final_response, "te")
            result['verdict'] = verdict
            result['status'] = 'success'
        else:
            result['verdict'] = te.final_status_label if te.final_status_label else 'Not_Found'
            result['status'] = 'success'
    except Exception as E:
        logger.error(f"Could not handle file: {file_name} because: {E}. Continue to handle the next file.")
        result['status'] = 'error'
    
    return result

if __name__ == '__main__':
    exit(main())
