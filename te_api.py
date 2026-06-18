#!/usr/bin/env python3

"""
te_api v12.0 (alpha)
"""

from te_file_handler import TE
from config_manager import ScannerConfig
from path_handler import PathHandler
import sys
from logger_config import setup_logging, rotate_today_log, cleanup_old_logs
from zip_archive import ZipArchiveManager
from safe_filename import sanitize_filename
import os
import shutil
import argparse
import multiprocessing
import logging
from pathlib import Path
from functools import partial
from datetime import datetime
import urllib3

 # Silence the urllib3 InsecureRequestWarning globally.
# This is the standard way to suppress the "Unverified HTTPS request"
# warning when verify=False is intentionally used with self-signed certs.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =======================
# Size Limits
# =======================
TE_FILE_SIZE_LIMIT = 104857600  # 100 MB — files >= this skip TE, go to AV
AV_FILE_SIZE_LIMIT = 2097152000  # ~2 GB — files >= this are skipped entirely

# =======================
# Utility Functions
# =======================


def _create_zip_manager(config):
    """
    Create a ZipArchiveManager if zip_password is configured.

    Args:
        config: ScannerConfig object

    Returns:
        ZipArchiveManager instance or None
    """
    if not config.zip_password:
        return None

    zip_timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    zip_mgr = ZipArchiveManager.create_archive(
        config.zip_archive_directory, config.zip_password, zip_timestamp
    )
    if zip_mgr:
        logging.getLogger("te_scanner.main").info(f"Zip archive enabled: {zip_mgr.zip_path}")
    else:
        logging.getLogger("te_scanner.main").warning(
            "Failed to initialize zip archive, proceeding without it"
        )
    return zip_mgr


# =======================
# Main entry point
# =======================


def main(stop_event=None, cli_args=None):
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
        description="TE API Scanner - Cross-platform threat emulation file scanner"
    )
    parser.add_argument(
        "-in", "--input_directory", help="the input files folder to be scanned by TE"
    )
    parser.add_argument(
        "-rep", "--reports_directory", help="the output folder with TE results"
    )
    parser.add_argument("-ip", "--appliance_ip", help="the appliance ip address")
    parser.add_argument(
        "--appliance-skip-tls-verify",
        action="store_true",
        default=None,
        help="Skip TLS certificate verification for TE appliance (default: false, enable for self-signed certs)",
    )
    parser.add_argument(
        "--no-appliance-skip-tls-verify",
        action="store_false",
        default=None,
        dest="appliance_skip_tls_verify",
        help="Explicitly disable TLS skip verification (overrides config.ini)",
    )
    parser.add_argument(
        "--no-save-response-info",
        action="store_false",
        default=None,
        dest="save_response_info",
        help="Disable saving API response transcripts (TE and TEX) to reports_directory",
    )
    parser.add_argument(
        "-n", "--concurrency", type=int, help="Number of concurrent file processes"
    )
    parser.add_argument(
        "--seconds-to-wait",
        type=int,
        help="Seconds to wait between TE query retries (default: from config)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        help="Maximum number of TE query retries (default: from config)",
    )
    parser.add_argument(
        "-out",
        "--benign_directory",
        help="the directory to move Benign files after scanning",
    )
    parser.add_argument(
        "-jail",
        "--quarantine_directory",
        help="the directory to move Malicious files after scanning",
    )
    parser.add_argument(
        "-error",
        "--error_directory",
        help="the directory to move files which cause a scanning error",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch mode: monitor directory for new files continuously",
    )
    parser.add_argument(
        "--watch-delay",
        type=int,
        help="Seconds to wait after last file activity before processing batch (default: from config)",
    )
    parser.add_argument(
        "--watch-max", type=int, help="Maximum batch size (0 = unlimited, from config)"
    )

    # Email notification CLI args
    parser.add_argument(
        "--email-enabled",
        action="store_true",
        help="Enable email notifications on batch completion",
    )
    parser.add_argument("--email-smtp-server", help="SMTP server hostname or IP")
    parser.add_argument(
        "--email-smtp-port", type=int, help="SMTP server port (default: 587)"
    )
    parser.add_argument(
        "--email-tls-method",
        choices=["none", "starttls", "smtp_ssl"],
        default=None,
        help="SMTP TLS method: none (no encryption), starttls (port 587), or smtp_ssl (port 465)",
    )
    parser.add_argument(
        "--email-skip-tls-verify",
        action="store_true",
        help="Skip TLS certificate verification for SMTP server (use with self-signed certs)",
    )
    parser.add_argument("--email-username", help="SMTP authentication username")
    parser.add_argument("--email-from", help="Sender email address")
    parser.add_argument("--email-to", help="Recipient email address")
    parser.add_argument(
        "--email-subject-template",
        help="Email subject template (supports ${timestamp}, ${appliance_ip}, ${processed}, ${malicious})",
    )
    parser.add_argument(
        "--email-template-file", help="Path to email body template file"
    )
    parser.add_argument(
        "--email-malicious-only",
        action="store_true",
        help="Only send email if at least one malicious file is found",
    )
    # IMAP "Sent" folder CLI args
    parser.add_argument(
        "--email-imap-enabled",
        action="store_true",
        help='Enable saving sent emails to IMAP "Sent" folder',
    )
    parser.add_argument("--email-imap-server", help="IMAP server hostname or IP")
    parser.add_argument(
        "--email-imap-port", type=int, help="IMAP server port (default: 993)"
    )
    parser.add_argument(
        "--email-imap-use-ssl", action="store_true", help="Use SSL for IMAP connection"
    )
    parser.add_argument(
        "--email-imap-skip-tls-verify",
        action="store_true",
        help="Skip TLS certificate verification for IMAP connection (use with self-signed certs)",
    )
    parser.add_argument("--email-imap-username", help="IMAP authentication username")
    parser.add_argument(
        "--email-imap-folder", help="IMAP folder to save sent emails (default: Sent)"
    )

    # Zip archive CLI args
    parser.add_argument(
        "-za",
        "--zip_archive_directory",
        help="Directory to store password-protected zip archives of processed files",
    )
    parser.add_argument(
        "--zip-password",
        help="Password for zip archives (empty or not provided = no zip archive)",
    )

    # TEX (Scrub) CLI args
    parser.add_argument(
        "--tex-enabled",
        action="store_true",
        help="Enable TEX (Threat Extraction/Scrub) processing",
    )
    parser.add_argument(
        "--tex-url", help="TEX API URL (e.g., https://appliance-ip/UserCheck/TPAPI)"
    )
    parser.add_argument("--tex-response-info-dir", help="TEX response info directory")
    parser.add_argument("--tex-clean-files-dir", help="TEX clean files directory")

    # AV (Antivirus) Fallback CLI args
    parser.add_argument(
        "--av-enabled",
        action="store_true",
        help="Enable AV fallback for files too large for TE or unsupported by TE",
    )
    parser.add_argument(
        "--av-username",
        help="SSH username for AV fallback (default: from config)",
    )
    parser.add_argument(
        "--av-password",
        help="SSH password for AV fallback (default: from config)",
    )
    parser.add_argument(
        "--av-remote-dir",
        help="Remote directory for AV files on appliance (default: /var/log/apiclient)",
    )
    parser.add_argument(
        "--av-rule-id",
        type=int,
        help="AV rule ID for policy selection (default: from config, fallback: 1)",
    )
    args = parser.parse_args(cli_args)

    # =======================
    # Load and Validate Config
    # =======================

    # Initialize logging first so we can log configuration loading
    # We'll get basic config without logging first to know where to put logs
    config = ScannerConfig.from_sources(config_file="config.ini", cli_args=args)

    # Now setup logging with loaded configuration
    logger = setup_logging(
        log_dir=config.log_dir,
        log_level=getattr(logging, config.log_level.upper()),
        max_bytes=config.max_log_size_mb * 1024 * 1024,
        log_retention_days=config.log_retention_days,
    )

    logger.info("TE API Scanner v12.0 - Loading configuration...")

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

    # Build API URLs
    # Port 18194 is the only port the TE API server listens on
    url = f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/"

    url_tex = config.tex_url

    # Warn about Windows long path support if applicable
    if PathHandler.is_windows() and not PathHandler.supports_long_paths():
        logger.warning("Windows long path support is not enabled.")
        logger.warning("         Paths over 260 characters may fail.")
        logger.warning(
            "         See: https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation"
        )

    # =======================
    # Watch Mode vs One-Shot Mode
    # =======================

    if config.watch_mode:
        # Check for required dependencies
        if PathHandler.is_windows():
            try:
                import win32serviceutil  # noqa: F401  # availability check
            except ImportError:
                logger.error("ERROR: pywin32 is not installed.")
                logger.error("Run: pip install pywin32")
                logger.error("Or: pip install -r requirements.txt")
                return 1

        try:
            import watchdog.observers  # noqa: F401  # availability check
        except ImportError:
            logger.error("ERROR: watchdog is not installed.")
            logger.error("Run: pip install watchdog")
            logger.error("Or: pip install -r requirements.txt")
            return 1

        # Watch mode: process existing files, then monitor
        logger.info("Starting in WATCH mode")
        logger.info("Dependencies check passed.")

        # Prepare zip archive if password is configured
        zip_mgr = _create_zip_manager(config)

        # Process any existing files immediately
        archive_files, other_files, av_files = discover_files(
            config.input_directory, config
        )
        has_files = archive_files or other_files or av_files
        if has_files:
            file_count = len(archive_files) + len(other_files) + len(av_files)
            logger.info(f"Processing {file_count} existing files...")
            process_discovered_files(
                archive_files, other_files, av_files, config, url, url_tex, zip_mgr
            )
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
            start_watching(config, url, url_tex, stop_event=stop_event)
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
        zip_mgr = _create_zip_manager(config)

        # Discover files
        archive_files, other_files, av_files = discover_files(
            config.input_directory, config
        )

        logger.info("Begin handling input files by TE")
        file_count = len(archive_files) + len(other_files) + len(av_files)
        logger.info(
            f"Found {len(archive_files)} archive files, "
            f"{len(other_files)} non-archive files, and "
            f"{len(av_files)} files for AV fallback"
        )

        if len(other_files) == 0 and len(archive_files) == 0 and len(av_files) == 0:
            logger.info("No files to process. Exiting.")
            if zip_mgr:
                zip_mgr.abort()
            return 0

        # Process files
        process_discovered_files(
            archive_files, other_files, av_files, config, url, url_tex, zip_mgr
        )
        find_and_delete_empty_subdirectories(config.input_directory)

        if zip_mgr:
            zip_mgr.close()

        logger.info("Processing complete!")
        logger.info("++++++++++")

        # End-of-run: rotate if over size limit, cleanup old files
        # Close existing file handlers so rename succeeds on Windows (WinError 32)
        root_logger = logging.getLogger("te_scanner")
        for h in root_logger.handlers:
            if isinstance(h, logging.FileHandler):
                h.close()
                root_logger.removeHandler(h)
        rotate_today_log(config.log_dir)
        # Re-add file handler for any remaining log output
        from logger_config import _swap_file_handler
        _swap_file_handler(config.log_dir)
        cleanup_old_logs(config.log_dir, config.log_retention_days)

    return 0


def discover_files(input_directory, config):
    """
    Discover files in input directory and categorize them as archives,
    other, or AV fallback files.

    Files >= 100 MB are routed to AV fallback. Archives are processed
    sequentially. All other files are processed in parallel via TE API.

    Args:
        input_directory: Path to input directory
        config: ScannerConfig object with archive_extensions set

    Returns:
        Tuple of (archive_files, other_files, av_files) as sets of
        (file_name, safe_file_name, sub_dir, full_path) tuples
    """
    logger = logging.getLogger("te_scanner.main")

    # Identify archive vs other files from config
    archive_extensions = [f".{ext}" for ext in config.archive_extensions]

    archive_files = set()
    other_files = set()
    av_files = set()

    # Shared collision-tracking dict across all discovered files
    seen = {}

    # Recursively walk through input_directory
    logger.info(f"Scanning input directory: {input_directory}")
    for root, dirs, files in os.walk(str(input_directory)):
        # Extract the subdirectory relative to the input_directory
        sub_dir = os.path.relpath(root, input_directory)
        # Normalize "." (root level) to empty string to avoid path issues
        if sub_dir == ".":
            sub_dir = ""
        for file in files:
            full_path = os.path.join(root, file)
            _, file_extension = os.path.splitext(file)

            # Sanitize filename for API compatibility (UTF-8 only)
            safe_file_name = sanitize_filename(file, seen)

            # Create a 4-tuple: (real_name, safe_name, sub_dir, full_path)
            file_info = (file, safe_file_name, sub_dir, full_path)

            # Check file size for AV fallback routing
            try:
                file_size = os.path.getsize(full_path)
                if file_size >= TE_FILE_SIZE_LIMIT:
                    av_files.add(file_info)
                    continue
            except OSError:
                pass

            if file_extension.lower() in archive_extensions:
                archive_files.add(file_info)
            else:
                other_files.add(file_info)

    return archive_files, other_files, av_files


def process_discovered_files(
    archive_files, other_files, av_files, config, url, url_tex="", zip_mgr=None
):
    """
    Process discovered files using the existing processing logic.

    In multiprocessing mode, non-archive files are copied to a temp directory by
    workers, then consolidated into the zip by the main process.
    Archive files are processed sequentially in the main process and added directly
    to the zip.
    AV fallback files are processed sequentially after TE processing.

    Args:
        archive_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
        other_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
        av_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
        config: ScannerConfig object
        url: TE API URL
        url_tex: TEX API URL (may be empty if TEX disabled)
        zip_mgr: ZipArchiveManager instance (None if disabled)
    """
    from notification import send_batch_notification

    logger = logging.getLogger("te_scanner.main")

    # Collect results for email notification
    all_files = []

    # Build temp directory and zip config for multiprocessing workers
    zip_config = None
    temp_dir = None
    verdict_basenames = [
        config.benign_directory.name,
        config.quarantine_directory.name,
        config.error_directory.name,
    ]
    if zip_mgr:
        temp_dir = str(
            Path(config.zip_archive_directory)
            / f"te_zip_{datetime.now().strftime('%Y%m%d%H%M%S_%f')}"
        )
        os.makedirs(temp_dir, exist_ok=True)
        logger.info(f"Zip temp directory: {temp_dir}")
        zip_config = (
            str(zip_mgr.zip_path),
            config.zip_password,
            verdict_basenames[0],
            verdict_basenames[1],
            verdict_basenames[2],
            temp_dir,
        )

    # Non-archive files: parallel processing (workers copy to temp dir)
    if len(other_files) > 0:
        logger.info(
            f"Processing {len(other_files)} non-archive files with concurrency={config.concurrency}"
        )
        # The config object is pickled to worker processes. pathlib.Path pickling
        # is supported in Python 3.9+, which is the minimum required version.
        process_func = partial(
            process_files,
            config=config,
            url=url,
            url_tex=url_tex,
            zip_config=zip_config,
        )

        with multiprocessing.Pool(config.concurrency) as pool:
            results = pool.starmap(process_func, other_files)
            all_files.extend(results)

    # Archive files: sequential processing in main process (add directly to zip)
    if len(archive_files) > 0:
        logger.info(f"Processing {len(archive_files)} archive files sequentially")
        for file_info in archive_files:
            file_name, safe_file_name, sub_dir, full_path = file_info
            result = process_files(
                file_name,
                safe_file_name,
                sub_dir,
                full_path,
                config,
                url,
                url_tex,
                zip_config=zip_mgr,
            )
            all_files.append(result)

    # AV fallback files: sequential processing (SSH/SCP based)
    if len(av_files) > 0 and config.av_fallback_enabled:
        logger.info(f"Processing {len(av_files)} files via AV fallback")
        try:
            from av_handler import AVHandler
        except ImportError as e:
            logger.error(
                f"AV fallback is enabled but paramiko is not installed: {e}"
            )
            logger.error(
                "Install it with: pip install paramiko"
            )
        else:
            with AVHandler(config) as av:
                av_results = av.process_batch(av_files)
                av_malicious = sum(1 for r in av_results if r.get("verdict") == "Malicious")
                av_benign = sum(1 for r in av_results if r.get("verdict") == "Benign")
                av_error = sum(1 for r in av_results if r.get("verdict") == "Error")
                logger.info(
                    f"AV fallback complete: {len(av_results)} files processed "
                    f"({av_benign} benign, {av_malicious} malicious, {av_error} errors)"
                )
                all_files.extend(av_results)
    elif len(av_files) > 0 and not config.av_fallback_enabled:
        logger.warning(
            f"{len(av_files)} files exceed TE size limit but AV fallback "
            "is not configured. Moving to error directory."
        )
        for file_info in av_files:
            file_name, safe_file_name, sub_dir, full_path = file_info
            try:
                if zip_mgr:
                    if isinstance(zip_mgr, tuple):
                        zip_path, zip_pwd, benign_dir, quarantine_dir, error_dir, temp_dir = zip_mgr
                        _add_file_to_temp(safe_name=file_name, local_path=full_path,
                                          sub_dir=sub_dir, verdict_dir=error_dir,
                                          zip_path=zip_path, zip_pwd=zip_pwd,
                                          temp_dir=temp_dir)
                    else:
                        zip_mgr.add_file(full_path, file_name, config.benign_directory.name)
                # Move file to error directory
                _move_file_to_error(file_name, sub_dir, full_path, config)
                all_files.append({
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "AV_Not_Configured",
                })
            except Exception as e:
                logger.error(f"Failed to handle large file {file_name}: {e}")
                all_files.append({
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "AV_Not_Configured",
                })

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
            "processed": len(all_files),
            "benign": sum(1 for f in all_files if f.get("verdict") == "Benign"),
            "malicious": sum(1 for f in all_files if f.get("verdict") == "Malicious"),
            "error": sum(
                1
                for f in all_files
                if f.get("status") == "error" or f.get("verdict") == "Error"
            ),
            "malicious_files": [
                {"name": f["name"], "verdict": f["verdict"]}
                for f in all_files
                if f.get("verdict") == "Malicious"
            ],
            "all_files": all_files,
        }
        try:
            send_batch_notification(config, batch_summary)
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")


def _add_file_to_temp(safe_name, local_path, sub_dir, verdict_dir, zip_path, zip_pwd, temp_dir):
    """Add a file to the temp directory for zip consolidation.

    Args:
        safe_name: Safe filename
        local_path: Original file path
        sub_dir: Subdirectory relative to input
        verdict_dir: Verdict directory basename
        zip_path: Path to the zip file
        zip_pwd: Password for the zip
        temp_dir: Temporary directory for consolidation
    """
    from path_handler import PathHandler
    verdict_path = Path(temp_dir) / verdict_dir / sub_dir if sub_dir else Path(temp_dir) / verdict_dir
    verdict_path.mkdir(parents=True, exist_ok=True)
    dest = verdict_path / safe_name
    try:
        shutil.copy2(local_path, str(dest))
    except Exception as e:
        logger.warning(f"Failed to copy {safe_name} to temp zip: {e}")


def _move_file_to_error(file_name, sub_dir, full_path, config):
    """Move a file to the error directory.

    Args:
        file_name: Original filename
        sub_dir: Subdirectory relative to input
        full_path: Full local path to the file
        config: ScannerConfig object
    """
    from path_handler import PathHandler
    display_name = PathHandler.display_path(file_name, sub_dir)
    error_dir = config.error_directory
    if sub_dir:
        error_dest = error_dir / sub_dir / file_name
    else:
        error_dest = error_dir / file_name

    error_dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        PathHandler.safe_move(full_path, str(error_dest))
        logger.info(f"Moved to error: {display_name}")
    except Exception as e:
        logger.error(f"Failed to move {display_name} to error directory: {e}")


def find_and_delete_empty_subdirectories(input_directory):
    """
    Finds and deletes all empty subdirectories under the specified input_directory.

    Args:
        input_directory (str): The root directory to start the search.
    """
    logger = logging.getLogger("te_scanner.main")
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


def process_single_file(file_name, safe_file_name, sub_dir, full_path, config, url, url_tex, zip_config):
    """
    Process a single file through the TE API and return result dict.

    Shared core logic used by both one-shot mode (via process_files)
    and watch mode (via process_batch_callback).

    Args:
        zip_config: ZipArchiveManager instance (single-process mode) or tuple
            (multiprocessing mode).

    Returns:
        dict with keys: name, path, verdict, status, tex_status
    """
    te = TE(
        url,
        url_tex,
        file_name,
        safe_file_name,
        sub_dir,
        full_path,
        config.input_directory,
        config.reports_directory,
        config.benign_directory,
        config.quarantine_directory,
        config.error_directory,
        tex_api_key=config.tex_api_key,
        zip_config=zip_config,
        config=config,
    )
    te.handle_file()

    result = {
        "name": file_name,
        "path": sub_dir if sub_dir else "",
        "verdict": "Unknown",
        "status": "success",
        "tex_status": te._tex_status,
    }

    if te.final_status_label == "FOUND":
        result["verdict"] = te.parse_verdict(te.final_response, "te")
    else:
        result["verdict"] = te.final_status_label if te.final_status_label else "Not_Found"

    return result


def process_files(
    file_name,
    safe_file_name,
    sub_dir,
    full_path,
    config,
    url,
    url_tex="",
    zip_config=None,
):
    """
    Process a single file through the TE API (multiprocessing worker entry point).

    Initializes logging for worker processes, then delegates to process_single_file().
    """
    setup_logging(
        log_dir=config.log_dir,
        log_level=getattr(logging, config.log_level.upper()),
        max_bytes=config.max_log_size_mb * 1024 * 1024,
        log_retention_days=config.log_retention_days,
    )

    logger = logging.getLogger("te_scanner.main")
    try:
        result = process_single_file(
            file_name, safe_file_name, sub_dir, full_path,
            config, url, url_tex, zip_config,
        )
    except Exception as e:
        logger.error(
            f"Could not handle file: {PathHandler.display_path(file_name, sub_dir)} because: {e}. Continue to handle the next file."
        )
        result = {
            "name": file_name,
            "path": sub_dir if sub_dir else "",
            "verdict": "Unknown",
            "status": "error",
            "tex_status": None,
        }

    return result


if __name__ == "__main__":
    sys.exit(main())
