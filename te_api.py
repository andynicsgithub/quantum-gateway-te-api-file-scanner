#!/usr/bin/env python3

"""
te_api v8.00 (alpha)
A Python client-side utility for interacting with the Threat Emulation API.
Features:
  - Scan input files in a specified directory
  - Handle TE and TE_EB processing via the appliance
  - Store results in an output directory
  - Support concurrent processing of multiple files (via command line argument or config.ini)
  - Move files from source directory to benign_directory, quarantine_directory, or error_directory based on TE verdict
  - Cross-platform support (Linux and Windows)
  - SMB/UNC network path support with retry logic
  - Watch mode: continuous monitoring of input directory with batch processing

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
import os
import argparse
import multiprocessing
import logging
from pathlib import Path
from functools import partial

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
    
    logger.info("TE API Scanner v8.00 - Loading configuration...")
    
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
        
        # Process any existing files immediately
        existing_files = discover_files(config.input_directory)
        if existing_files:
            archive_files, other_files = existing_files
            logger.info(f"Processing {len(archive_files) + len(other_files)} existing files...")
            process_discovered_files(archive_files, other_files, config, url)
            find_and_delete_empty_subdirectories(config.input_directory)
        else:
            logger.info("No existing files to process.")
        
        # Start watching (blocking call)
        from file_watcher import start_watching
        try:
            start_watching(config, url)
        except Exception as e:
            logger.error(f"ERROR starting watcher: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 1
        
    else:
        # One-shot mode: process and exit
        logger.info("Starting in ONE-SHOT mode")
        logger.info(f"Parallel processing of {config.concurrency} files at once")
        
        # Discover files
        archive_files, other_files = discover_files(config.input_directory)
        
        logger.info(f"Begin handling input files by TE")
        logger.info(f"Found {len(archive_files)} archive files and {len(other_files)} non-archive files")
        
        if len(other_files) == 0 and len(archive_files) == 0:
            logger.info("No files to process. Exiting.")
            return 0
        
        # Process files
        process_discovered_files(archive_files, other_files, config, url)
        find_and_delete_empty_subdirectories(config.input_directory)
        
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

def process_discovered_files(archive_files, other_files, config, url):
    """
    Process discovered files using the existing processing logic.
    
    Args:
        archive_files: Set of (file_name, sub_dir, full_path) tuples
        other_files: Set of (file_name, sub_dir, full_path) tuples
        config: ScannerConfig object
        url: TE API URL
    """
    logger = logging.getLogger('te_scanner.main')
    
    # Non-archive files: parallel processing
    if len(other_files) > 0:
        logger.info(f"Processing {len(other_files)} non-archive files with concurrency={config.concurrency}")
        # Use partial to bind config and url parameters (works with multiprocessing pickle)
        process_func = partial(process_files, config=config, url=url)
        
        with multiprocessing.Pool(config.concurrency) as pool:
            pool.starmap(process_func, other_files)

    # Archive files: sequential processing
    if len(archive_files) > 0:
        logger.info(f"Processing {len(archive_files)} archive files sequentially")
        for file_info in archive_files:
            file_name, sub_dir, full_path = file_info
            process_files(file_name, sub_dir, full_path, config, url)

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

def process_files(file_name, sub_dir, full_path, config, url):
    """
    Process a single file through the TE API.
    
    Args:
        file_name: Name of the file
        sub_dir: Subdirectory relative to input_directory
        full_path: Full path to the file
        config: ScannerConfig object
        url: TE API URL
    """
    # Initialize logging for this worker process (needed for Windows spawn)
    setup_logging(
        log_dir=config.log_dir,
        log_level=getattr(logging, config.log_level.upper()),
        max_bytes=config.max_log_size_mb * 1024 * 1024,
        backup_count=config.backup_count
    )
    
    logger = logging.getLogger('te_scanner.main')
    try:
        logger.info(f"Handling file: {file_name}")
        te = TE(
            url, 
            file_name, 
            sub_dir, 
            full_path, 
            config.input_directory,
            config.reports_directory, 
            config.benign_directory, 
            config.quarantine_directory, 
            config.error_directory
        )
        te.handle_file()
    except Exception as E:
        logger.error(f"Could not handle file: {file_name} because: {E}. Continue to handle the next file.")

if __name__ == '__main__':
    exit(main())
