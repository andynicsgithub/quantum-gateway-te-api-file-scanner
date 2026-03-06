#!/usr/bin/env python3

"""
te_api v7.0
A Python client-side utility for interacting with the Threat Emulation API.
Features:
  - Scan input files in a specified directory
  - Handle TE and TE_EB processing via the appliance
  - Store results in an output directory
  - Support concurrent processing of multiple files (via command line argument or config.ini)
  - Move files from source directory to benign_directory, quarantine_directory, or error_directory based on TE verdict
  - Cross-platform support (Linux and Windows)
  - SMB/UNC network path support with retry logic

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
    parser.add_argument('--watch', action='store_true', help='Watch mode: monitor directory for new files (Phase 2)')
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
    
    logger.info("TE API Scanner v7.01 - Loading configuration...")
    
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
    
    logger.info(f"Parallel processing of {config.concurrency} files at once")
    
    # =======================
    # File Discovery
    # =======================
    
    # Identify archive vs other files
    archive_extensions = [".7z", ".arj", ".bz2", ".CAB", ".dmg", ".gz", ".img", ".iso", ".msi", ".pkg", ".rar", ".tar", ".tbz2", ".tbz", ".tb2", ".tgz", ".xz", ".zip", ".udf", ".qcow2"]

    archive_files = set()
    other_files = set()

    # Recursively walk through input_directory
    logger.info(f"Scanning input directory: {config.input_directory}")
    for root, dirs, files in os.walk(str(config.input_directory)):
        # Extract the subdirectory relative to the input_directory
        sub_dir = os.path.relpath(root, config.input_directory)
        for file in files:
            full_path = os.path.join(root, file)
            file_nameonly, file_extension = os.path.splitext(file)

            # Create a tuple with the file name, subdirectory, root, and full path
            file_info = (file, sub_dir, full_path)

            if file_extension.lower() in archive_extensions:
                archive_files.add(file_info)
            else:
                other_files.add(file_info)
            
    logger.info(f"Begin handling input files by TE")
    logger.info(f"Found {len(archive_files)} archive files and {len(other_files)} non-archive files")
    
    if len(other_files) == 0 and len(archive_files) == 0:
        logger.info("No files to process. Exiting.")
        return 0
    
    # =======================
    # Process files
    # =======================

    # Non-archive files: parallel processing
    if len(other_files) > 0:
        logger.info(f"Processing {len(other_files)} non-archive files with concurrency={config.concurrency}")
        # Use partial to bind config and url parameters (works with multiprocessing pickle)
        process_func = partial(process_files, config=config, url=url)
        
        # Initialize logging in each worker process
        with multiprocessing.Pool(
            config.concurrency,
            initializer=init_worker,
            initargs=(config.log_dir, getattr(logging, config.log_level.upper()), 
                     config.max_log_size_mb * 1024 * 1024, config.backup_count)
        ) as pool:
            pool.starmap(process_func, other_files)

    # Archive files: sequential processing
    if len(archive_files) > 0:
        logger.info(f"Processing {len(archive_files)} archive files sequentially")
        for file_info in archive_files:
            file_name, sub_dir, full_path = file_info
            process_files(file_name, sub_dir, full_path, config, url)

    # Delete empty sub-directories
    logger.info(f"Cleaning up empty subdirectories in {config.input_directory}")
    find_and_delete_empty_subdirectories(config.input_directory)
    
    logger.info("Processing complete!")
    return 0


# =======================
# Utility Functions
# =======================

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

def init_worker(log_dir, log_level, max_bytes, backup_count):
    """
    Initialize logging in each multiprocessing worker process.
    This function is called when each worker process starts.
    """
    setup_logging(
        log_dir=log_dir,
        log_level=log_level,
        max_bytes=max_bytes,
        backup_count=backup_count
    )

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
