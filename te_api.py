#!/usr/bin/env python3

"""
te_api v13.2 (alpha)
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
import te_healthcheck
import requests
import hashlib
import json

 # Silence the urllib3 InsecureRequestWarning globally.
# This is the standard way to suppress the "Unverified HTTPS request"
# warning when verify=False is intentionally used with self-signed certs.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Module-level logger for use by helper functions that can't access
# the local 'logger' variable inside process_discovered_files()
logger = logging.getLogger("te_scanner.main")

# =======================
# Size Limits
# =======================
TE_FILE_SIZE_LIMIT = 104857600  # 100 MB — default, overridden by config.te_to_av_fallback_at_mb
# AV_FILE_SIZE_LIMIT removed — now uses config.av_to_signature_fallback_at_mb (default 2048 MB)


def get_te_threshold_bytes(config):
    """Convert the config MB threshold to bytes."""
    return config.te_to_av_fallback_at_mb * 1024 * 1024


def get_av_signature_threshold_bytes(config):
    """Convert the AV-to-signature config MB threshold to bytes."""
    return config.av_to_signature_fallback_at_mb * 1024 * 1024


def query_av_signature(config, md5_hash):
    """Query Check Point API with MD5 hash and 'av' feature.

    Args:
        config: ScannerConfig object with appliance_ip and appliance_skip_tls_verify
        md5_hash: MD5 hex digest string of the file

    Returns:
        Verdict string: "Benign", "Malicious", or "Error"
    """
    logger = logging.getLogger("te_scanner.main")
    base_url = f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/query"

    request_data = {
        "request": [
            {
                "features": ["av"],
                "md5": md5_hash
            }
        ]
    }

    try:
        response = requests.post(
            url=base_url,
            json=request_data,
            verify=not config.appliance_skip_tls_verify,
            timeout=30
        )
        response.raise_for_status()
        response_json = response.json()

        # Check response structure
        if "response" in response_json and len(response_json["response"]) > 0:
            response_entry = response_json["response"][0]
            if "av" in response_entry:
                av_result = response_entry["av"]
                # Malicious: has malware_info object
                if "malware_info" in av_result:
                    logger.info(f"AV signature check: MALICIOUS (hash={md5_hash})")
                    return "Malicious"
                # Benign: has status but no malware_info
                elif "status" in av_result:
                    logger.info(f"AV signature check: BENIGN (hash={md5_hash})")
                    return "Benign"

        logger.warning(f"AV signature check: unexpected response format (hash={md5_hash})")
        return "Error"

    except requests.exceptions.RequestException as e:
        logger.error(f"AV signature API request failed for hash {md5_hash}: {e}")
        return "Error"
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.error(f"AV signature response parse error for hash {md5_hash}: {e}")
        return "Error"

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
        "--email-include-log",
        action="store_true",
        help="Attach today's log file to email notification",
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
    parser.add_argument(
        "--av-te-threshold-mb",
        type=int,
        help="Deprecated: use --av-to-signature-threshold-mb instead",
    )
    parser.add_argument(
        "--av-to-signature-threshold-mb",
        type=int,
        help="Files >= this (MB) skip AV path and use MD5 signature check only (default: from config, 2048)",
    )
    parser.add_argument(
        "--tex-max-file-size-mb",
        type=int,
        help="Skip TEX processing for files >= this (MB) (default: from config, 15)",
    )
    parser.add_argument(
        "--healthcheck-dir",
        help="Health check test files directory (default: from config, healthcheck/)",
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

    logger.info("TE API Scanner v13.2 - Loading configuration...")

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

    # Email notification startup validation
    if config.email_enabled:
        if config.email_smtp_server and config.email_from and config.email_to:
            logger.info(
                f"Email notifications enabled: sending to {config.email_to}"
            )
        else:
            logger.warning(
                "Email notifications enabled but SMTP fields are incomplete "
                "(smtp_server, from, and to are required). "
                "Emails will not be sent until configuration is corrected."
            )

    # Build API URLs
    # Port 18194 is the only port the TE API server listens on
    url = f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/"

    url_tex = config.tex_url

   # Warn about Windows long path support if applicable
    if PathHandler.is_windows() and not PathHandler.supports_long_paths():
        logger.warning("Windows long path support is not enabled.")
        logger.warning("         Paths over 260 characters may fail.")
        logger.warning(
            "         See: https://learn.microsoft.com/en-us/windows/32/fileio/maximum-file-path-limitation"
        )

    # =======================
    # Health Check
    # =======================

    healthcheck_dir = Path(config.healthcheck_directory)
    te_health_result = None
    av_health_result = None
    api_healthy = True

    if healthcheck_dir and healthcheck_dir.exists():
        logger.info("Running health check...")
        try:
            te_health_result = te_healthcheck.check_te_health(config, healthcheck_dir)
            if not te_health_result["healthy"]:
                logger.error(f"Health check failed: {te_health_result.get('message', 'TE API')}")
                api_healthy = False

            if config.av_fallback_enabled:
                av_health_result = te_healthcheck.check_av_health(config, healthcheck_dir)
                if not av_health_result["healthy"]:
                    logger.error(f"AV health check failed: {av_health_result.get('message', '')}")
                    api_healthy = False

            if api_healthy:
                logger.info("Health check passed")
            else:
                logger.warning("Health check failed — will send notification and proceed based on mode")

        except Exception as e:
            logger.error(f"Health check error: {e}")
            api_healthy = False
            te_health_result = {
                "te": f"FAIL: {e}",
                "healthy": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": str(e),
            }
    else:
        logger.info("Health check skipped — healthcheck directory not found: %s", healthcheck_dir)

    # Send failure notification if health check failed
    if not api_healthy and te_health_result:
        try:
            te_healthcheck.send_healthcheck_notification(config, te_health_result)
        except Exception as e:
            logger.warning(f"Failed to send health check notification: {e}")

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

        if not api_healthy:
            logger.warning("Health check failed — entering polling mode (files will not be processed)")
            logger.warning("Waiting for API to recover...")

        # Prepare zip archive if password is configured
        zip_mgr = _create_zip_manager(config)

        # Process any existing files immediately (only if API is healthy)
        if api_healthy:
            archive_files, other_files, av_files, signature_files = discover_files(
                config.input_directory, config
            )
            has_files = archive_files or other_files or av_files or signature_files
            if has_files:
                file_count = len(archive_files) + len(other_files) + len(av_files) + len(signature_files)
                logger.info(f"Processing {file_count} existing files...")
                process_discovered_files(
                    archive_files, other_files, av_files, signature_files, config, url, url_tex, zip_mgr
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
            start_watching(config, url, url_tex, api_healthy=api_healthy, stop_event=stop_event)
        except Exception as e:
            logger.error(f"ERROR starting watcher: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return 1

    else:
        # One-shot mode: process and exit
        if not api_healthy:
            logger.error("ERROR: Health check failed. API is not responding correctly.")
            print("\n" + "=" * 60)
            print("  ERROR: Health check failed")
            print("=" * 60)
            if te_health_result:
                print(f"  TE: {te_health_result.get('te', 'UNKNOWN')}")
            if av_health_result:
                print(f"  AV: {av_health_result.get('av', 'N/A')}")
            if te_health_result:
                print(f"  Details: {te_health_result.get('message', 'N/A')}")
            print("=" * 60)
            return 1

        logger.info("Starting in ONE-SHOT mode")
        logger.info(f"Parallel processing of {config.concurrency} files at once")

        # Prepare zip archive if password is configured
        zip_mgr = _create_zip_manager(config)

        # Discover files
        archive_files, other_files, av_files, signature_files = discover_files(
            config.input_directory, config
        )

        logger.info("Begin handling input files by TE")
        file_count = len(archive_files) + len(other_files) + len(av_files) + len(signature_files)
        logger.info(
            f"Found {len(archive_files)} archive files, "
            f"{len(other_files)} non-archive files, "
            f"{len(av_files)} files for AV fallback, and "
            f"{len(signature_files)} files for MD5 signature check"
        )

        if len(other_files) == 0 and len(archive_files) == 0 and len(av_files) == 0 and len(signature_files) == 0:
            logger.info("No files to process. Exiting.")
            if zip_mgr:
                zip_mgr.abort()
            return 0

        # Process files
        process_discovered_files(
            archive_files, other_files, av_files, signature_files, config, url, url_tex, zip_mgr
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
    other, AV fallback, or signature check files.

    Files are routed based on size thresholds:
    - Files < te_to_av_fallback_at_mb: go to TE path (archives or other)
    - Files >= te_to_av_fallback_at_mb and < av_to_signature_fallback_at_mb: go to AV fallback (SFTP+SSH)
    - Files >= av_to_signature_fallback_at_mb: go to signature check (MD5 API query)

    Args:
        input_directory: Path to input directory
        config: ScannerConfig object with archive_extensions set

    Returns:
        Tuple of (archive_files, other_files, av_files, signature_files) as sets of
        (file_name, safe_file_name, sub_dir, full_path) tuples
    """
    logger = logging.getLogger("te_scanner.main")

    # Identify archive vs other files from config
    archive_extensions = [f".{ext}" for ext in config.archive_extensions]

    archive_files = set()
    other_files = set()
    av_files = set()
    signature_files = set()

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

            # Check file size for AV fallback / signature routing
            try:
                file_size = os.path.getsize(full_path)
                if file_size >= get_av_signature_threshold_bytes(config):
                    signature_files.add(file_info)
                    continue
                elif file_size >= get_te_threshold_bytes(config):
                    av_files.add(file_info)
                    continue
            except OSError:
                pass

            if file_extension.lower() in archive_extensions:
                archive_files.add(file_info)
            else:
                other_files.add(file_info)

    return archive_files, other_files, av_files, signature_files


def _get_verdict_basename(directory):
    """
    Get a safe name for a directory to use as a ZIP internal path prefix.

    On Windows, pathlib.Path.name can return an empty string for UNC paths
    (e.g. \\\\server\\share) when the path has no subdirectory components.
    This helper detects UNC paths and uses PureWindowsPath.parts to extract
    the last meaningful component, skipping the UNC root part (\\\\server\\).
    """
    try:
        import platform

        if platform.system() != "Windows":
            return directory.name

        path_str = str(directory)
        if path_str.startswith("\\\\"):
            # Windows UNC path detected
            from pathlib import PureWindowsPath

            win_path = PureWindowsPath(path_str)
            parts = win_path.parts
            # UNC parts: ('\\\\server\\', 'share', 'dir', ...) -> skip first
            meaningful = parts[1:] if len(parts) > 1 else parts
            if meaningful:
                return meaningful[-1]
            # UNC root with no subdirs (e.g. \\\\server\\share) -> extract share name
            remainder = path_str[2:]  # strip leading \\
            parts = remainder.split("\\")
            if len(parts) >= 2:
                return parts[1]  # index 0 = server, index 1 = share
            return path_str
    except Exception:
        pass
    return directory.name


def process_discovered_files(
    archive_files, other_files, av_files, signature_files, config, url, url_tex="", zip_mgr=None
):
    """
    Process discovered files using the existing processing logic.

    In multiprocessing mode, non-archive files are copied to a temp directory by
    workers, then consolidated into the zip by the main process.
    Archive files are processed sequentially in the main process and added directly
    to the zip.
    AV fallback files are processed sequentially after TE processing.
    Signature check files are processed after AV files (MD5-based API query).

    Args:
        archive_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
        other_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
        av_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
        signature_files: Set of (file_name, safe_file_name, sub_dir, full_path) tuples
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
        _get_verdict_basename(config.benign_directory),
        _get_verdict_basename(config.quarantine_directory),
        _get_verdict_basename(config.error_directory),
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

                # Move local AV files to verdict directories
                for result in av_results:
                    file_name = result.get("name", "unknown")
                    sub_dir = result.get("path", "")
                    verdict = result.get("verdict", "Error")
                    full_path = None
                    # Find the full path from av_files
                    for file_info in av_files:
                        if file_info[0] == file_name:
                            full_path = file_info[3]
                            break

                    if not full_path:
                        logger.error(f"AV: could not find file path for {file_name}")
                        continue

                    # Determine destination based on verdict
                    if verdict == "Malicious":
                        dest = config.quarantine_directory / sub_dir / file_name
                        action = "quarantine"
                    elif verdict == "Benign":
                        dest = config.benign_directory / sub_dir / file_name
                        action = "benign"
                    else:
                        dest = config.error_directory / sub_dir / file_name
                        action = "error"

                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        PathHandler.safe_move(Path(full_path), dest)
                        logger.info(f"AV {action}: moved {file_name} to {action} directory")
                    except Exception as e:
                        logger.error(f"AV: failed to move {file_name} to {action}: {e}")

                all_files.extend(av_results)

    # Signature check files: MD5-based API query (sequential)
    if len(signature_files) > 0:
        logger.info(f"Processing {len(signature_files)} files via MD5 signature check")
        sig_benign = 0
        sig_malicious = 0
        sig_error = 0

        for file_info in signature_files:
            file_name, safe_file_name, sub_dir, full_path = file_info

            # Compute MD5 hash
            try:
                md5_hash = hashlib.md5()
                with open(str(full_path), "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        md5_hash.update(chunk)
                md5_hex = md5_hash.hexdigest()
            except OSError as e:
                logger.error(f"Cannot compute MD5 for {file_name}: {e}")
                _move_file_to_error(file_name, sub_dir, full_path, config)
                sig_error += 1
                all_files.append({
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "MD5_Compute_Failed",
                    "error_detail": str(e),
                })
                continue

            logger.info(
                f"MD5 signature check for {file_name} ({md5_hex}, "
                f"{full_path.stat().st_size:,} bytes)"
            )

            # Query AV signature API
            verdict = query_av_signature(config, md5_hex)

            if zip_mgr:
                if isinstance(zip_mgr, tuple):
                    zip_path, zip_pwd, benign_dir, quarantine_dir, error_dir, temp_dir = zip_mgr
                    _add_file_to_temp(
                        safe_name=file_name, local_path=full_path,
                        sub_dir=sub_dir, verdict_dir=verdict,
                        zip_path=zip_path, zip_pwd=zip_pwd,
                        temp_dir=temp_dir
                    )
                else:
                    zip_mgr.add_file(full_path, verdict, sub_dir, file_name)

            # Move file to verdict directory
            if verdict == "Malicious":
                _move_file_to_quarantine(file_name, sub_dir, full_path, config)
                sig_malicious += 1
            elif verdict == "Benign":
                _move_file_to_verdict(file_name, sub_dir, full_path, config, "benign")
                sig_benign += 1
            else:
                _move_file_to_error(file_name, sub_dir, full_path, config)
                sig_error += 1

            all_files.append({
                "name": file_name,
                "path": sub_dir if sub_dir else "",
                "verdict": verdict,
                "status": "success" if verdict in ("Benign", "Malicious") else "error",
                "tex_status": None,
                "av_verdict": f"MD5_{verdict}",
            })

        logger.info(
            f"MD5 signature check complete: {len(signature_files)} files processed "
            f"({sig_benign} benign, {sig_malicious} malicious, {sig_error} errors)"
        )
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
                        zip_mgr.add_file(full_path, 'error', sub_dir, file_name)
                # Move file to error directory
                _move_file_to_error(file_name, sub_dir, full_path, config)
                all_files.append({
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "AV_Not_Configured",
                    "error_detail": "File exceeds TE size limit, AV fallback not configured",
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
                    "error_detail": f"AV_Not_Configured: {e}",
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
        PathHandler.safe_move(Path(full_path), error_dest)
        logger.info(f"Moved to error: {display_name}")
    except Exception as e:
        logger.error(f"Failed to move {display_name} to error directory: {e}")


def _move_file_to_quarantine(file_name, sub_dir, full_path, config):
    """Move a file to the quarantine directory.

    Args:
        file_name: Original filename
        sub_dir: Subdirectory relative to input
        full_path: Full local path to the file
        config: ScannerConfig object
    """
    from path_handler import PathHandler
    display_name = PathHandler.display_path(file_name, sub_dir)
    quarantine_dir = config.quarantine_directory
    if sub_dir:
        quarantine_dest = quarantine_dir / sub_dir / file_name
    else:
        quarantine_dest = quarantine_dir / file_name

    quarantine_dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        PathHandler.safe_move(Path(full_path), quarantine_dest)
        logger.info(f"Moved to quarantine: {display_name}")
    except Exception as e:
        logger.error(f"Failed to move {display_name} to quarantine directory: {e}")


def _move_file_to_verdict(file_name, sub_dir, full_path, config, verdict_type):
    """Move a file to a verdict directory by type.

    Args:
        file_name: Original filename
        sub_dir: Subdirectory relative to input
        full_path: Full local path to the file
        config: ScannerConfig object
        verdict_type: One of 'benign', 'quarantine', 'error'
    """
    from path_handler import PathHandler
    display_name = PathHandler.display_path(file_name, sub_dir)
    verdict_dirs = {
        "benign": config.benign_directory,
        "quarantine": config.quarantine_directory,
        "error": config.error_directory,
    }
    target_dir = verdict_dirs.get(verdict_type, config.error_directory)
    if sub_dir:
        target_dest = target_dir / sub_dir / file_name
    else:
        target_dest = target_dir / file_name

    target_dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        PathHandler.safe_move(Path(full_path), target_dest)
        logger.info(f"Moved to {verdict_type}: {display_name}")
    except Exception as e:
        logger.error(f"Failed to move {display_name} to {verdict_type} directory: {e}")


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
        "error_detail": None,
    }

    if te.final_status_label == "FOUND":
        result["verdict"] = te.parse_verdict(te.final_response, "te")
    else:
        result["verdict"] = te.final_status_label if te.final_status_label else "Not_Found"
        # Capture error/detail context for non-FOUND statuses
        if te.final_status_label:
            result["error_detail"] = te.final_status_label

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
            "error_detail": str(e)[:500],
        }

    return result


if __name__ == "__main__":
    sys.exit(main())
