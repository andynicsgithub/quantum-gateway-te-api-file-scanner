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
import os
import argparse
import multiprocessing
import datetime
from pathlib import Path

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
    
    print("TE API Scanner v7.0 - Loading configuration...")
    config = ScannerConfig.from_sources(config_file='config.ini', cli_args=args)
    
    # Display configuration summary
    config.print_summary()
    print()
    
    # Validate configuration
    is_valid, errors = config.validate()
    if not is_valid:
        print("\n==> Configuration validation failed:")
        for error in errors:
            print(f"  ERROR: {error}")
        print()
        parser.print_help()
        return 1
    
    print("Configuration validated successfully.\n")
    
    # Build API URL
    url = f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/"
    
    # Warn about Windows long path support if applicable
    if PathHandler.is_windows() and not PathHandler.supports_long_paths():
        print("WARNING: Windows long path support is not enabled.")
        print("         Paths over 260 characters may fail.")
        print("         See: https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation\n")
    
    print(f"Parallel processing of {config.concurrency} files at once")
    
    # =======================
    # File Discovery
    # =======================
    
    # Identify archive vs other files
    archive_extensions = [".7z", ".arj", ".bz2", ".CAB", ".dmg", ".gz", ".img", ".iso", ".msi", ".pkg", ".rar", ".tar", ".tbz2", ".tbz", ".tb2", ".tgz", ".xz", ".zip", ".udf", ".qcow2"]

    archive_files = set()
    other_files = set()

    # Recursively walk through input_directory
    print(f"Scanning input directory: {config.input_directory}")
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
            
    print("\nBegin handling input files by TE")
    print(f"Found {len(archive_files)} archive files and {len(other_files)} non-archive files")
    
    if len(other_files) == 0 and len(archive_files) == 0:
        print("No files to process. Exiting.")
        return 0
    
    # =======================
    # Process files
    # =======================

    # Non-archive files: parallel processing
    if len(other_files) > 0:
        print(f"\nProcessing {len(other_files)} non-archive files with concurrency={config.concurrency}")
        # Create partial function with config baked in
        def process_with_config(file_name, sub_dir, full_path):
            return process_files(file_name, sub_dir, full_path, config, url)
        
        with multiprocessing.Pool(config.concurrency) as pool:
            pool.starmap(process_with_config, other_files)

    # Archive files: sequential processing
    if len(archive_files) > 0:
        print(f"\nProcessing {len(archive_files)} archive files sequentially")
        for file_info in archive_files:
            process_files(*file_info, config, url)

    # Delete empty sub-directories
    print(f"\nCleaning up empty subdirectories in {config.input_directory}")
    find_and_delete_empty_subdirectories(config.input_directory)
    
    print("\n==> Processing complete!")
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
    for root, dirs, files in os.walk(input_directory, topdown=False):
        # Iterate in reverse order to avoid issues with modifying the list while iterating
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            if not os.listdir(dir_path):  # Check if the directory is empty
                try:
                    os.rmdir(dir_path)  # Remove the empty directory
                    print(f"Deleted empty directory: {dir_path}")
                except Exception as e:
                    print(f"Error deleting directory {dir_path}: {str(e)}")

def print_with_timestamp(message, variable):
    """Print message with timestamp."""
    now = datetime.datetime.now()
    timestamp = now.strftime("%H:%M:%S.%f")
    print("{} - {}".format(timestamp, message.format(variable)))

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
    try:
        print_with_timestamp("Handling file: {} by TE", file_name)
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
        print("Could not handle file: {} because: {}. Continue to handle the next file.".format(file_name, E))

if __name__ == '__main__':
    exit(main())
