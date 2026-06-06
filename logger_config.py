#!/usr/bin/env python3

"""
logger_config.py v11.2 (alpha)
Centralized logging configuration for TE API Scanner.

Features:
  - Date-numbered log files: te_scanner_YYYY-MM-DD.N.log
  - Event-driven rotation on size limit (checked at startup, end of run, end of batch)
  - Automatic gzip compression of files older than 24 hours
  - Configurable retention period (default 90 days)
  - Console output for real-time monitoring

Rotation behavior:
  - On startup: cleanup old files, compress old files, open/create today's file
  - On end of run (one-shot): rotate if over size limit, cleanup old files
  - On end of batch (watch): check if date changed, rotate if needed
  - Files are named te_scanner_YYYY-MM-DD.N.log where N increments on rotation
  - Files older than 24 hours are automatically compressed to .gz
  - Size overflows between rotation checkpoints are tolerated (event-driven, not continuous)

Cross-platform: uses Python stdlib gzip (works on Linux and Windows).
"""

import gzip
import logging
import re
import time
from datetime import datetime, timedelta
from logging import FileHandler
from pathlib import Path
import sys
from typing import List, Optional, Tuple

LOG_PREFIX = "te_scanner_"
LOG_EXTENSIONS = (".log", ".log.gz")
DATE_PATTERN = re.compile(
    r"te_scanner_(\d{4}-\d{2}-\d{2})"
    r"(?:\.(\d+))?"
    r"(\.log)?(\.gz)?"
    r"$"
)
_SCAN_RESULT = Tuple[str, int, str, Path]
TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S"


def _scan_log_files(log_dir: Path) -> List[_SCAN_RESULT]:
    """
    Scan log directory for all matching log files.

    Returns:
        List of (date_str, number, extension) tuples.
        date_str: YYYY-MM-DD
        number: rotation number (0 for most recent or only file of that date)
        extension: ".log" or ".log.gz"
    """
    results = []
    if not log_dir.is_dir():
        return results

    for entry in log_dir.iterdir():
        if not entry.is_file():
            continue
        m = DATE_PATTERN.search(entry.name)
        if m:
            date_str = m.group(1)
            num = int(m.group(2)) if m.group(2) else 0
            ext = ".log.gz" if m.group(4) else ".log"
            results.append((date_str, num, ext, entry))

    return results


def cleanup_old_logs(log_dir: Path, retention_days: int) -> None:
    """
    Delete log files older than retention_days.
    """
    cutoff = datetime.now() - timedelta(days=retention_days)
    files = _scan_log_files(log_dir)
    deleted = 0

    for date_str, _num, _ext, path in files:
        try:
            file_date = datetime.strptime(date_str, "%Y-%m-%d")
            if file_date < cutoff:
                path.unlink()
                deleted += 1
        except (ValueError, OSError):
            continue

    if deleted:
        print(
            f"  [LOGGING] Deleted {deleted} log files older than {retention_days} days"
        )


def _compress_old_files(log_dir: Path) -> None:
    """
    Gzip uncompressed .log files older than 24 hours.
    Uses Python stdlib gzip. Cross-platform (Linux and Windows).
    """
    cutoff = time.time() - (24 * 3600)

    for entry in log_dir.iterdir():
        if not entry.is_file():
            continue
        if not entry.name.startswith(LOG_PREFIX):
            continue
        if not entry.name.endswith(".log"):
            continue
        if entry.stat().st_mtime > cutoff:
            continue

        gz_path = Path(str(entry) + ".gz")
        try:
            with open(entry, "rb") as f_in:
                with gzip.open(gz_path, "wb") as f_out:
                    f_out.write(f_in.read())
            entry.unlink()
        except OSError:
            if gz_path.exists():
                gz_path.unlink()
            continue


def rotate_today_log(log_dir: Path) -> str:
    """
    Rotate today's current log file to a numbered backup.

    Logic:
      1. Find today's latest log file by mtime
      2. Determine next rotation number
      3. Rename current file → te_scanner_YYYY-MM-DD.{N}.log
      4. Create te_scanner_YYYY-MM-DD.0.log (empty, new)

    Returns:
        Path of the new current log file (te_scanner_YYYY-MM-DD.0.log).
    """
    today = datetime.now().strftime("%Y-%m-%d")
    files = _scan_log_files(log_dir)
    today_files = [(d, n, e, p) for d, n, e, p in files if d == today]

    if today_files:
        today_files.sort(key=lambda x: (x[1], -x[3].stat().st_mtime), reverse=True)
        _date, max_num, _ext, _max_num_path = today_files[0]
        next_num = max_num + 1
    else:
        next_num = 0

    if next_num > 0:
        for i in range(next_num - 1, -1, -1):
            old_name = f"{LOG_PREFIX}{today}.{i}.log"
            new_name = f"{LOG_PREFIX}{today}.{i + 1}.log"
            old_path = log_dir / old_name
            new_path = log_dir / new_name
            if old_path.exists():
                old_path.rename(new_path)

    new_file = f"{LOG_PREFIX}{today}.0.log"
    new_path = log_dir / new_file
    try:
        with open(new_path, "w"):
            pass
    except OSError:
        pass

    return new_file


def _get_today_log_name(log_dir: Path) -> str:
    """
    Get today's current log file name (the .0 file).

    Always returns a string; the caller should check if the file exists.
    """
    today = datetime.now().strftime("%Y-%m-%d")
    return f"{LOG_PREFIX}{today}.0.log"


def _swap_file_handler(log_dir: Path) -> None:
    """
    Replace the te_scanner logger's file handler to point to today's current log file.
    This is needed after rotation because on Linux, the old FileHandler's file descriptor
    persists after the file is renamed, causing writes to go to the old file.

    Removes all existing te_scanner file handlers and adds a fresh one.
    """
    root_logger = logging.getLogger("te_scanner")
    today = datetime.now().strftime("%Y-%m-%d")
    today_file = f"{LOG_PREFIX}{today}.0.log"
    log_path = log_dir / today_file

    # Remove old file handlers
    old_handlers = [h for h in root_logger.handlers if isinstance(h, FileHandler)]
    for h in old_handlers:
        h.close()
        root_logger.removeHandler(h)

    # Add fresh handler
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt=TIMESTAMP_FMT,
    )
    new_handler = FileHandler(log_path, mode="a", encoding="utf-8")
    new_handler.setFormatter(formatter)
    root_logger.addHandler(new_handler)


def setup_logging(
    log_dir: Optional[Path] = None,
    log_level=logging.INFO,
    max_bytes=10 * 1024 * 1024,
    log_retention_days=90,
) -> logging.Logger:
    """
    Configure application-wide logging with date-numbered file rotation.

    Rotation is event-driven, not continuous:
      - Size is checked at startup, end of run, and end of batch.
      - Date change is checked at end of each batch (watch mode).
      - Files older than 24 hours are auto-compressed on startup.
      - Files older than log_retention_days are deleted on startup.

    Args:
        log_dir: Directory for log files (default: ./logs)
        log_level: Logging level (default: INFO)
        max_bytes: Maximum size per log file before rotation (default: 10MB)
        log_retention_days: Number of days to keep log files (default: 90)

    Returns:
        logging.Logger: Configured root logger
    """
    try:
        if log_dir is None:
            log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Phase 1: Cleanup old files
        cleanup_old_logs(log_dir, log_retention_days)

        # Phase 2: Compress old files (older than 24 hours)
        _compress_old_files(log_dir)

        # Phase 3: Determine which file to use today
        today = datetime.now().strftime("%Y-%m-%d")

        # Find today's current file
        current_log_name = _get_today_log_name(log_dir)

        # Check size of current file
        current_log_path = log_dir / current_log_name
        if current_log_path.exists():
            current_size = current_log_path.stat().st_size
            if current_size >= max_bytes:
                # Rotate and create new file
                rotate_today_log(log_dir)
                current_log_name = f"{LOG_PREFIX}{today}.0.log"

        log_file = log_dir / current_log_name

        # ISO 8601 timestamp format
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt=TIMESTAMP_FMT,
        )

        # File handler - no automatic rotation (we handle it manually)
        file_handler = FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)

        # Console handler for real-time output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

        # Configure root logger
        root_logger = logging.getLogger("te_scanner")
        root_logger.setLevel(log_level)

        # Avoid duplicate handlers if setup_logging is called multiple times
        if not root_logger.handlers:
            root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)

        return root_logger

    except Exception as e:
        # Fallback to console-only if file logging fails
        print(f"WARNING: Could not setup file logging: {e}", file=sys.stderr)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt=TIMESTAMP_FMT,
            )
        )
        root_logger = logging.getLogger("te_scanner")
        root_logger.setLevel(log_level)
        if not root_logger.handlers:
            root_logger.addHandler(console_handler)
        return root_logger
