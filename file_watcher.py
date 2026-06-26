#!/usr/bin/env python3

"""
file_watcher.py v13.2 (alpha)
Cross-platform file watcher for TE API Scanner using watchdog.
Features:
  - Detects file completion using three-tier monitoring (created, modified, closed)
  - Batch collection with configurable delay after all files closed
  - Recursive subdirectory monitoring
  - Cross-platform support (Windows/Linux)
"""

import os
import time
import threading
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from safe_filename import sanitize_filename
from te_api import (
    process_single_file,
    get_te_threshold_bytes,
    get_av_signature_threshold_bytes,
    query_av_signature,
)
from path_handler import PathHandler
import hashlib


class CopyCompletionWatcher(FileSystemEventHandler):
    """
    Monitors a directory for file copy completion using a quiet-period trigger.

    Logic:
    1. on_created / on_moved: File appears - add to pending set
    2. on_modified: File still being written - reset activity timer
    3. On_closed: Never fires on Windows (see note below)

    Batch trigger:
    - Track last_activity timestamp (updated on every file event)
    - When directory is quiet for batch_delay seconds, dispatch all pending files
    - max_batch caps per-dispatch size for large bursts
    """

    def __init__(self, config, batch_callback):
        """
        Initialize watcher with configuration and callback function.

        Args:
            config: ScannerConfig object with watch_* fields
            batch_callback: Function to call with list of file paths when batch ready
        """
        super().__init__()
        self.config = config
        self.batch_callback = batch_callback
        self.logger = logging.getLogger("te_scanner.watcher")

        # State tracking
        self.pending_files = {}  # path -> {created, last_modified, closed, size}
        self._lock = threading.Lock()
        self.last_activity = 0.0
        self._batch_dispatched = False  # Set before batch callback, cleared after
        self._batch_processing = False  # True while batch callback is running
        self.batch_delay = config.watch_batch_delay
        self.max_batch = config.watch_max_batch

        self.logger.info(
            f"CopyCompletionWatcher initialized: delay={self.batch_delay}s, max_batch={self.max_batch}"
        )

    def on_created(self, event, path_override=None):
        """
        Triggered when a file is created (copy started).

        Args:
            event: File system event
            path_override: Optional path to use instead of event.src_path
                          (used for move events where src_path is stale)
        """
        if event.is_directory:
            return

        try:
            file_path = str(Path(path_override or event.src_path).resolve())
            self.logger.info(f"[WATCHER] on_created: {file_path}")

            # Check if file still exists (might be deleted immediately)
            if not os.path.exists(file_path):
                self.logger.warning(f"[WATCHER] File deleted immediately: {file_path}")
                return

            with self._lock:
                self.pending_files[file_path] = {
                    "created": time.time(),
                    "last_modified": time.time(),
                    "closed": False,
                    "size": os.path.getsize(file_path),
                }
                self.last_activity = time.time()
            self.logger.info(
                f"[WATCHER] Added to pending: {file_path} (size: {self.pending_files.get(file_path, {}).get('size', 'unknown')} bytes)"
            )

            self._check_batch_ready()

        except Exception as e:
            self.logger.error(
                f"[WATCHER] Error handling created event for {event.src_path}: {e}"
            )
            import traceback

            self.logger.error(traceback.format_exc())

    def on_modified(self, event):
        """
        Triggered when file is modified (copy in progress).
        Updates last activity timestamp to reset batch timer.
        """
        if event.is_directory:
            return

        try:
            file_path = str(Path(event.src_path).resolve())
            self.logger.info(f"[WATCHER] on_modified: {file_path}")

            with self._lock:
                if file_path not in self.pending_files:
                    return
                old_size = self.pending_files[file_path]["size"]
                self.pending_files[file_path]["last_modified"] = time.time()
                self.last_activity = time.time()
                new_size = os.path.getsize(file_path)
                self.pending_files[file_path]["size"] = new_size
            self.logger.info(
                f"[WATCHER] File growing: {file_path} ({old_size} → {new_size} bytes)"
            )

            self._check_batch_ready()

        except Exception as e:
            self.logger.error(
                f"[WATCHER] Error handling modified event for {event.src_path}: {e}"
            )
            import traceback

            self.logger.error(traceback.format_exc())

    def on_closed(self, event):
        """
        NOTE: This handler is currently unused. The watchdog library does not
        emit 'close' events on any platform, so this method will never be called.
        File copy completion is detected via stale-file detection in
        _check_batch_ready() (checks last_modified timestamp) instead.
        This handler may be removed in a future refactoring.
        """
        if event.is_directory:
            return

        try:
            file_path = str(Path(event.src_path).resolve())
            self.logger.info(f"[WATCHER] on_closed: {file_path}")

            with self._lock:
                if file_path not in self.pending_files:
                    return
                self.pending_files[file_path]["closed"] = True
                self.pending_files[file_path]["last_modified"] = time.time()
                self.last_activity = time.time()
            self.logger.info(f"[WATCHER] File closed (copy complete): {file_path}")

            self._check_batch_ready()

        except Exception as e:
            self.logger.error(
                f"[WATCHER] Error handling closed event for {event.src_path}: {e}"
            )
            import traceback

            self.logger.error(traceback.format_exc())

    def on_moved(self, event):
        """
        Handle file moved into watched directory.
        """
        if event.is_directory:
            return

        # Treat as created event, using dest_path (src_path is the old location)
        self.on_created(event, path_override=event.dest_path)

    def _check_batch_ready(self):
        """
        Check if batch should be processed based on directory quiet period.

        Uses a single last_activity timestamp: if the directory has been
        quiet (no on_created/on_modified/on_moved events) for batch_delay
        seconds and there are pending files, dispatch them.

        All operations (snapshot, pop, callback) are performed under a
        single lock acquisition to prevent the event thread and polling
        loop from both triggering the same batch.
        """
        now = time.time()

        with self._lock:
            if not self.pending_files:
                return

            # If directory is still active (files arriving or being written),
            # do not dispatch yet — wait for quiet period
            if now - self.last_activity < self.batch_delay:
                return

            # All pending files are ready for dispatch (directory is quiet)
            dispatchable = dict(self.pending_files)

            if self.max_batch > 0:
                file_paths = list(dispatchable.keys())[:self.max_batch]
            else:
                file_paths = list(dispatchable.keys())

            if not file_paths:
                return

            for path in file_paths:
                self.pending_files.pop(path, None)

        # Process stale files outside the lock (callback may be slow)
        self.logger.info(f"[WATCHER] {len(file_paths)} files ready for processing")
        self.logger.info(
            f"[WATCHER] Triggering batch processing: {len(file_paths)} files"
        )

        self._batch_dispatched = True
        self._batch_processing = True
        try:
            self.batch_callback(file_paths)
        except Exception as e:
            self.logger.error(f"[WATCHER] Error in batch callback: {e}")
            with self._lock:
                for path in file_paths:
                    if os.path.exists(path):
                        self.pending_files[path] = {
                            "created": time.time(),
                            "last_modified": time.time(),
                            "closed": True,
                            "size": os.path.getsize(path),
                        }
        finally:
            self._batch_processing = False

    def get_pending_count(self):
        """Return number of files currently pending."""
        return len(self.pending_files)


def _move_to_error_in_watch(file_name, sub_dir, full_path, config, batch_logger):
    """Move a file to the error directory during watch mode.

    Args:
        file_name: Original filename
        sub_dir: Subdirectory relative to input
        full_path: Full local path to the file
        config: ScannerConfig object
        batch_logger: Logger instance
    """
    try:
        error_sub = str(Path(full_path).parent.relative_to(config.input_directory))
        if error_sub == ".":
            error_sub = ""
        error_path = config.error_directory / error_sub / file_name
        PathHandler.safe_move(full_path, str(error_path))
        display = f"{error_sub}/{file_name}" if error_sub else file_name
        batch_logger.info(f"Moved {display} to error directory")
    except Exception as move_error:
        batch_logger.error(
            f"Failed to move {file_name} to error directory: {move_error}"
        )


class WatcherThread:
    """
    Thread-safe wrapper for watchdog Observer with graceful shutdown.
    """

    def __init__(self, config, batch_callback):
        self.config = config
        self.batch_callback = batch_callback
        self.logger = logging.getLogger("te_scanner.watcher")

        self.watcher = CopyCompletionWatcher(config, batch_callback)
        self.observer = Observer()
        self._running = False

    def start(self):
        """
        Start watching directory.
        """
        watch_path = str(self.config.input_directory)

        self.observer.schedule(self.watcher, watch_path, recursive=True)
        self.observer.start()
        self._running = True

        self.logger.info(f"Started watching: {watch_path} (recursive)")
        self.logger.info("Using stale file detection (fallback for Windows)")

    def stop(self):
        """
        Stop watching directory.
        """
        if self._running:
            self.logger.info("Stopping watcher...")
            self.observer.stop()
            self.observer.join(timeout=10)
            self._running = False
            self.logger.info("Watcher stopped")

    def is_running(self):
        """Check if watcher is running."""
        return self._running and self.observer.is_alive()

    def get_pending_count(self):
        """Get count of files currently pending."""
        return self.watcher.get_pending_count()


def start_watching(config, url, url_tex="", api_healthy=True, stop_event=None):
    """
    Start file watching (blocking call).

    Args:
        config: ScannerConfig object
        url: TE API URL
        url_tex: TEX API URL (may be empty if TEX disabled)
        api_healthy: Initial API health status (from startup health check)
    """
    logger = logging.getLogger("te_scanner.watcher")

    # Health check state
    healthcheck_dir = Path(config.healthcheck_directory)

    # Run startup health check if needed
    if healthcheck_dir and healthcheck_dir.exists() and api_healthy:
        try:
            import te_healthcheck
            te_result = te_healthcheck.check_te_health(config, healthcheck_dir)
            if config.av_fallback_enabled:
                av_result = te_healthcheck.check_av_health(config, healthcheck_dir)
            else:
                av_result = {"av": "SKIPPED", "healthy": True}
            api_healthy = te_result["healthy"] and av_result["healthy"]
            if api_healthy:
                logger.info("Startup health check passed")
            else:
                logger.error(f"Startup health check failed: {te_result.get('message', 'TE API')}")
                if av_result["healthy"] is not True:
                    logger.error(f"AV health check failed: {av_result.get('message', '')}")
        except Exception as e:
            logger.error(f"Startup health check error: {e}")
            api_healthy = False

    # Define batch processing callback
    def process_batch_callback(file_paths):
        """Process a batch of files."""
        from notification import send_batch_notification
        from zip_archive import ZipArchiveManager

        batch_logger = logging.getLogger("te_scanner.batch_processor")

        # Create per-batch zip archive if configured
        batch_zip_mgr = None
        if config.zip_password:
            batch_timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            batch_zip_mgr = ZipArchiveManager.create_archive(
                config.zip_archive_directory, config.zip_password, batch_timestamp
            )
            if batch_zip_mgr:
                batch_logger.info(f"Zip archive: {batch_zip_mgr.zip_path}")
            else:
                batch_logger.warning("Failed to create zip archive for batch")

        # Track batch results for email notification
        batch_summary = {
            "processed": 0,
            "benign": 0,
            "malicious": 0,
            "error": 0,
            "malicious_files": [],
            "all_files": [],
        }

        # Shared collision-tracking dict for sanitize_filename
        seen = {}

        # Phase 1: Discover and categorize files (TE vs AV fallback vs signature)
        te_files = []
        av_files = []
        signature_files = []

        for file_path in file_paths:
            if not os.path.exists(file_path):
                batch_logger.warning(f"File no longer exists: {file_path}")
                continue

            try:
                file_obj = Path(file_path)
                file_name = file_obj.name
                safe_file_name = sanitize_filename(file_name, seen)
                sub_dir = str(file_obj.parent.relative_to(config.input_directory))
                full_path = str(file_obj)

                if sub_dir == ".":
                    sub_dir = ""

                try:
                    file_size = os.path.getsize(full_path)
                except OSError:
                    file_size = 0

                if file_size >= get_av_signature_threshold_bytes(config):
                    signature_files.append((file_path, file_name, safe_file_name, sub_dir, full_path, file_size))
                elif file_size >= get_te_threshold_bytes(config):
                    av_files.append((file_path, file_name, safe_file_name, sub_dir, full_path, file_size))
                else:
                    te_files.append((file_path, file_name, safe_file_name, sub_dir, full_path))
            except Exception as e:
                batch_logger.error(f"Error categorizing {file_path}: {e}")
                continue

        if signature_files:
            batch_logger.info(
                f"Found {len(signature_files)} files above AV-to-signature threshold ({config.av_to_signature_fallback_at_mb} MB) -> will use MD5 signature check"
            )

        # Phase 2: Process TE files concurrently via ThreadPoolExecutor
        if te_files:
            batch_logger.info(
                f"Processing {len(te_files)} files via TE (concurrency={config.concurrency})"
            )
            with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
                futures = {}
                for file_path, file_name, safe_file_name, sub_dir, full_path in te_files:
                    batch_logger.info(f"Processing: {PathHandler.display_path(file_name, sub_dir)}")
                    future = pool.submit(
                        process_single_file,
                        file_name, safe_file_name, sub_dir, full_path,
                        config, url, url_tex, batch_zip_mgr,
                    )
                    futures[future] = (file_path, file_name, sub_dir)

                for future in as_completed(futures):
                    file_path, file_name, sub_dir = futures[future]
                    try:
                        result = future.result()
                        batch_summary["all_files"].append(result)
                        batch_summary["processed"] += 1

                        verdict = result["verdict"]
                        if verdict == "Malicious":
                            batch_summary["malicious"] += 1
                            batch_summary["malicious_files"].append({"name": file_name, "verdict": verdict})
                        elif verdict == "Benign":
                            batch_summary["benign"] += 1
                        elif verdict == "Error":
                            batch_summary["error"] += 1
                    except Exception as e:
                        batch_logger.error(f"Error processing {file_path}: {e}")
                        batch_summary["error"] += 1
                        batch_summary["all_files"].append(
                            {
                                "name": file_path,
                                "path": "",
                                "verdict": "Error",
                                "tex_status": None,
                            }
                        )

        # Phase 3: Process AV fallback files sequentially (SSH-based, not safe for threads)
        for file_path, file_name, safe_file_name, sub_dir, full_path, file_size in av_files:
            display_path = PathHandler.display_path(file_name, sub_dir)
            batch_logger.info(
                f"Large file detected: {display_path} ({file_size / (1024*1024):.1f} MB)"
            )

            if config.av_fallback_enabled:
                try:
                    from av_handler import AVHandler
                    with AVHandler(config) as av:
                        result = av.process_file(
                            file_name, safe_file_name, sub_dir,
                            full_path, batch_zip_mgr,
                        )
                except ImportError:
                    batch_logger.error(
                        f"AV fallback enabled but paramiko not installed: {file_name}"
                    )
                    result = {
                        "name": file_name,
                        "path": sub_dir if sub_dir else "",
                        "verdict": "Error",
                        "status": "error",
                        "tex_status": None,
                        "av_verdict": "paramiko_not_installed",
                    }
                    _move_to_error_in_watch(
                        file_name, sub_dir, full_path, config, batch_logger
                    )

                verdict = result.get("verdict", "Unknown")
                av_verdict = result.get("av_verdict", "")
                if av_verdict == "Transfer_Failed":
                    batch_logger.error(
                        f"AV transfer failed for {display_path} — "
                        "file stays in input"
                    )
                elif av_verdict == "Above_AV_To_Signature_Threshold":
                    batch_logger.warning(
                        f"AV skipped for {display_path} "
                        f"({file_size / (1024*1024):.1f} MB > {config.av_to_signature_fallback_at_mb} MB threshold, use MD5 signature check)"
                    )
                elif verdict == "Malicious":
                    batch_logger.warning(
                        f"AV MALICIOUS: {display_path} — "
                        f"verdict: {verdict} (action: drop)"
                    )
                elif verdict == "Benign":
                    batch_logger.info(
                        f"AV benign: {display_path} (action: accept)"
                    )
                elif verdict == "Error":
                    batch_logger.warning(
                        f"AV error for {display_path} ({av_verdict})"
                    )
            else:
                batch_logger.warning(
                    f"AV fallback not configured for large file: {display_path}"
                )
                _move_to_error_in_watch(
                    file_name, sub_dir, full_path, config, batch_logger
                )
                result = {
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "AV_Not_Configured",
                }

            # Move file to verdict directory (mirrors te_api.py AV move logic)
            verdict = result.get("verdict", "Error")
            av_verdict = result.get("av_verdict", "")

            # Transfer_Failed: file never left local system, leave in input for retry
            if av_verdict == "Transfer_Failed":
                pass
            # AV not configured already handled by _move_to_error_in_watch above
            elif av_verdict == "AV_Not_Configured":
                pass
            else:
                if verdict == "Malicious":
                    dest = config.quarantine_directory / sub_dir / file_name
                    action = "quarantine"
                elif verdict == "Benign":
                    dest = config.benign_directory / sub_dir / file_name
                    action = "benign"
                else:
                    dest = config.error_directory / sub_dir / file_name
                    action = "error"

                # Add file to batch zip archive before moving
                if batch_zip_mgr:
                    try:
                        batch_zip_mgr.add_file(full_path, action, sub_dir, file_name)
                    except Exception as e:
                        batch_logger.warning(f"Failed to add {file_name} to zip: {e}")

                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    PathHandler.safe_move(Path(full_path), dest)
                    batch_logger.info(f"AV {action}: moved {file_name} to {action} directory")
                except Exception as e:
                    batch_logger.error(f"AV: failed to move {file_name} to {action}: {e}")
                    result["verdict"] = "Error"

            batch_summary["all_files"].append(result)
            batch_summary["processed"] += 1

            verdict = result["verdict"]
            if verdict == "Malicious":
                batch_summary["malicious"] += 1
                batch_summary["malicious_files"].append({"name": file_name, "verdict": verdict})
            elif verdict == "Benign":
                batch_summary["benign"] += 1
            elif verdict == "Error":
                batch_summary["error"] += 1

        # Phase 4: Process signature check files sequentially (MD5 API query)
        sig_benign = 0
        sig_malicious = 0
        sig_error = 0
        sig_files_processed = 0

        for file_path, file_name, safe_file_name, sub_dir, full_path, file_size in signature_files:
            display_path = PathHandler.display_path(file_name, sub_dir)
            batch_logger.info(
                f"Large file detected: {display_path} ({file_size / (1024*1024):.1f} MB) -> MD5 signature check"
            )

            try:
                # Compute MD5 hash
                md5_hash = hashlib.md5()
                with open(str(full_path), "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        md5_hash.update(chunk)
                md5_hex = md5_hash.hexdigest()
            except OSError as e:
                batch_logger.error(f"Cannot compute MD5 for {file_name}: {e}")
                result = {
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "MD5_Compute_Failed",
                    "error_detail": str(e),
                }
                _move_to_error_in_watch(file_name, sub_dir, full_path, config, batch_logger)
                sig_error += 1
                sig_files_processed += 1
                batch_summary["all_files"].append(result)
                batch_summary["processed"] += 1
                batch_summary["error"] += 1
                continue

            # Query AV signature API
            verdict = query_av_signature(config, md5_hex)

            if verdict == "Malicious":
                dest = config.quarantine_directory / sub_dir / file_name
                action = "quarantine"
            elif verdict == "Benign":
                dest = config.benign_directory / sub_dir / file_name
                action = "benign"
            else:
                dest = config.error_directory / sub_dir / file_name
                action = "error"

            # Add file to batch zip archive before moving
            if batch_zip_mgr:
                try:
                    batch_zip_mgr.add_file(full_path, action, sub_dir, file_name)
                except Exception as e:
                    batch_logger.warning(f"Failed to add {file_name} to zip: {e}")

            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                PathHandler.safe_move(Path(full_path), dest)
                batch_logger.info(f"Signature {action}: moved {file_name} to {action} directory")
            except Exception as e:
                batch_logger.error(f"Signature: failed to move {file_name} to {action}: {e}")

            result = {
                "name": file_name,
                "path": sub_dir if sub_dir else "",
                "verdict": verdict,
                "status": "success" if verdict in ("Benign", "Malicious") else "error",
                "tex_status": None,
                "av_verdict": f"MD5_{verdict}",
            }

            sig_files_processed += 1
            batch_summary["all_files"].append(result)
            batch_summary["processed"] += 1

            if verdict == "Malicious":
                sig_malicious += 1
                batch_summary["malicious"] += 1
                batch_summary["malicious_files"].append({"name": file_name, "verdict": verdict})
            elif verdict == "Benign":
                sig_benign += 1
                batch_summary["benign"] += 1
            else:
                sig_error += 1
                batch_summary["error"] += 1

        # Close zip archive for this batch
        if batch_zip_mgr:
            batch_zip_mgr.close()

  # Send email notification after batch completes
        try:
            if config.email_enabled and (
                not config.email_malicious_only or batch_summary["malicious"] > 0
            ):
                send_batch_notification(config, batch_summary)
        except Exception as e:
            batch_logger.warning(f"Email notification failed: {e}")

        batch_logger.info("Batch processing complete, waiting for new files...")

        # NOTE: Do NOT clean up empty subdirectories here. Deleting watched
        # subdirectories breaks the OS-level file event handles
        # (inotify on Linux, ReadDirectoryChangesW on Windows). The watchdog
        # Observer does not re-register deleted subdirectories, so any files
        # copied into a newly-created subdirectory after deletion would be
        # silently missed.  Empty subdirectories are harmless — they only
        # contain moved (already-processed) files.

    # Create and start watcher
    try:
        watcher_thread = WatcherThread(config, process_batch_callback)
        watcher_thread.start()
    except Exception as e:
        logger.error(f"Failed to start watchdog observer: {e}")
        raise

    logger.info("Watching directory for new files... (Ctrl+C to stop)")
    logger.info("This will run continuously. Press Ctrl+C to exit.")

    try:
        last_dispatch_time = 0.0
        check_interval = 2

        last_batch_time = time.time()
        idle_check_interval = 300  # 5 minutes in seconds
        last_fallback_scan_time = time.time()
        fallback_scan_interval = 30  # seconds between fallback scans

        while True:
            if stop_event:
                stop_event.wait(check_interval)
                if stop_event.is_set():
                    break
            else:
                time.sleep(check_interval)

            if api_healthy:
                # Normal operation — process batch and check idle timeout
                now = time.time()

                watcher_thread.watcher._check_batch_ready()

                # If a batch was dispatched and all pending files are gone,
                # processing has finished. Reset the idle timer so the
                # health check fires idle_check_interval seconds after the
                # batch completes.
                if watcher_thread.watcher._batch_dispatched:
                    watcher_thread.watcher._batch_dispatched = False
                    if watcher_thread.watcher.get_pending_count() == 0:
                        last_batch_time = time.time()

                # Periodically check if today's log file needs rotation
                if now - last_dispatch_time >= check_interval:
                    last_dispatch_time = now
                    from logger_config import (
                        _swap_file_handler,
                        rotate_today_log,
                        _get_today_log_name,
                    )

                    today_name = _get_today_log_name(config.log_dir)
                    if today_name:
                        today_path = config.log_dir / today_name
                        if (
                            today_path.exists()
                            and today_path.stat().st_size
                            >= config.max_log_size_mb * 1024 * 1024
                        ):
                            rotate_today_log(config.log_dir)
                            _swap_file_handler(config.log_dir)

                # Fallback scan: periodically check input dir for files the
                # watchdog observer may have missed (SMB mounts, race conditions,
                # directories recreated after deletion). Runs every ~30 seconds.
                if now - last_fallback_scan_time >= fallback_scan_interval:
                    last_fallback_scan_time = now
                    try:
                        input_dir = Path(config.input_directory)
                        for root, dirs, files in os.walk(input_dir):
                            for fname in files:
                                fpath = str(Path(root) / fname)
                                resolved = str(Path(fpath).resolve())
                                with watcher_thread.watcher._lock:
                                    if resolved not in watcher_thread.watcher.pending_files:
                                        watcher_thread.watcher.pending_files[resolved] = {
                                            "created": time.time(),
                                            "last_modified": time.time(),
                                            "closed": False,
                                            "size": os.path.getsize(fpath),
                                        }
                                        watcher_thread.watcher.last_activity = time.time()
                        if watcher_thread.watcher.pending_files:
                            logger.info(
                                f"[WATCHER] Fallback scan found {len(watcher_thread.watcher.pending_files)} file(s) — triggering batch"
                            )
                            watcher_thread.watcher._check_batch_ready()
                    except Exception as scan_err:
                        logger.debug(f"[WATCHER] Fallback scan error: {scan_err}")

                # Idle health check (every 5 min, only when pending queue is empty)
                pending = watcher_thread.get_pending_count()
                if pending > 0:
                    logger.info(
                        f"[WATCHER] {pending} files pending (waiting for copy completion)..."
                    )

                # Check idle timeout — skip if a batch is actively processing
                idle_time = time.time() - last_batch_time
                if idle_time >= idle_check_interval:
                    last_batch_time = time.time()
                    if pending == 0 and not watcher_thread.watcher._batch_processing:
                        try:
                            import te_healthcheck
                            te_result = te_healthcheck.check_te_health(
                                config, healthcheck_dir
                            )
                            if config.av_fallback_enabled:
                                av_result = te_healthcheck.check_av_health(
                                    config, healthcheck_dir
                                )
                            else:
                                av_result = {"av": "SKIPPED", "healthy": True}
                            if not te_result["healthy"] or not av_result["healthy"]:
                                logger.warning(
                                    f"Idle health check failed: "
                                    f"TE={te_result.get('te')}, "
                                    f"AV={av_result.get('av')}"
                                )
                                try:
                                    te_healthcheck.send_healthcheck_notification(
                                        config, te_result
                                    )
                                except Exception:
                                    pass
                                api_healthy = False
                                logger.warning(
                                    "Entering polling mode — waiting for API recovery"
                                )
                        except Exception as e:
                            logger.error(f"Idle health check error: {e}")

            else:
                # Polling mode — retry health check every 30 seconds
                time.sleep(check_interval)
                try:
                    import te_healthcheck
                    te_result = te_healthcheck.check_te_health(config, healthcheck_dir)
                    if config.av_fallback_enabled:
                        av_result = te_healthcheck.check_av_health(
                            config, healthcheck_dir
                        )
                    else:
                        av_result = {"av": "SKIPPED", "healthy": True}
                    if te_result["healthy"] and av_result["healthy"]:
                        api_healthy = True
                        logger.info("API recovered — resuming file processing")
                        try:
                            te_healthcheck.send_healthcheck_notification(
                                config, te_result, is_recovery=True
                            )
                        except Exception:
                            pass
                    else:
                        logger.debug(
                            f"Health check retry failed: "
                            f"TE={te_result.get('te')}, AV={av_result.get('av')}"
                        )
                except Exception as e:
                    logger.error(f"Health check retry failed: {e}")

    except KeyboardInterrupt:
        logger.info("Shutdown requested...")
    finally:
        watcher_thread.stop()
        logger.info("Watcher shutdown complete")
