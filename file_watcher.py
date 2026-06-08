#!/usr/bin/env python3

"""
file_watcher.py v11.2 (alpha)
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
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from safe_filename import sanitize_filename
from path_handler import PathHandler
from te_api import process_single_file


class CopyCompletionWatcher(FileSystemEventHandler):
    """
    Monitors a directory for file copy completion using file handle events.

    Logic:
    1. on_created: File appears (copy started) - add to pending set
    2. on_modified: File growing (copy ongoing) - update last activity timestamp
    3. on_closed: File handle closed (copy complete) - mark as ready

    Batch trigger:
    - All files must be closed (copy complete)
    - No new activity for batch_delay seconds
    - Then trigger process_batch()
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
        self.batch_delay = config.watch_batch_delay
        self.min_batch = config.watch_min_batch
        self.max_batch = config.watch_max_batch

        self.logger.info(
            f"CopyCompletionWatcher initialized: delay={self.batch_delay}s, "
            f"min_batch={self.min_batch}, max_batch={self.max_batch}"
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
            self.logger.info(
                f"[WATCHER] Added to pending: {file_path} (size: {self.pending_files.get(file_path, {}).get('size', 'unknown')} bytes)"
            )

            # Check if this single file should trigger immediately
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
                new_size = os.path.getsize(file_path)
                self.pending_files[file_path]["size"] = new_size
            self.logger.info(
                f"[WATCHER] File growing: {file_path} ({old_size} → {new_size} bytes)"
            )

            # Check if this file might be done copying
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
            self.logger.info(f"[WATCHER] File closed (copy complete): {file_path}")

            # Check if we should trigger batch immediately (single file, no delay)
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
        Check if batch should be processed.
        Uses "stale file" detection: a file is ready if it hasn't been modified
        for batch_delay seconds. This works on all platforms, even where
        on_closed events don't fire (Windows).

        All operations (snapshot, stale detection, pop, callback) are performed
        under a single lock acquisition to prevent the event thread and polling
        loop from both triggering the same batch.
        """
        now = time.time()

        with self._lock:
            if not self.pending_files:
                return

            # Check batch size constraints first
            if self.min_batch > 0 and len(self.pending_files) < self.min_batch:
                return

            # Collect files ready for dispatch.
            # Default path: only stale files (no modification for batch_delay).
            # max_batch path: files that are closed OR stale (avoids mid-copy dispatch
            # while preserving the staleness fallback for platforms where on_closed
            # doesn't fire, e.g. Windows).
            dispatchable = {}
            for file_path, info in self.pending_files.items():
                time_since_last_modified = now - info["last_modified"]
                is_closed = info.get("closed", False)
                is_stale = time_since_last_modified >= self.batch_delay
                if is_closed or is_stale:
                    dispatchable[file_path] = info

            if self.max_batch > 0:
                file_paths = list(dispatchable.keys())[:self.max_batch]
                stale_files = {p: dispatchable[p] for p in file_paths}
            else:
                stale_files = dispatchable

            if not stale_files:
                return

            file_paths = list(stale_files.keys())
            for path in file_paths:
                self.pending_files.pop(path, None)

        # Process stale files outside the lock (callback may be slow)
        self.logger.info(f"[WATCHER] {len(file_paths)} files ready for processing")
        self.logger.info(
            f"[WATCHER] Triggering batch processing: {len(file_paths)} files"
        )

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

    def get_pending_count(self):
        """Return number of files currently pending."""
        return len(self.pending_files)


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


def start_watching(config, url, url_tex=""):
    """
    Start file watching (blocking call).

    Args:
        config: ScannerConfig object
        url: TE API URL
        url_tex: TEX API URL (may be empty if TEX disabled)
    """
    logger = logging.getLogger("te_scanner.watcher")

    # Define batch processing callback
    def process_batch_callback(file_paths):
        """Process a batch of files."""
        from path_handler import PathHandler
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

        for file_path in file_paths:
            # Verify file still exists
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

                display_path = PathHandler.display_path(file_name, sub_dir)
                batch_logger.info(f"Processing: {display_path}")

                result = process_single_file(
                    file_name, safe_file_name, sub_dir, full_path,
                    config, url, url_tex,
                    batch_zip_mgr,
                )

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
                # Use file_path (the loop variable) for accurate error reporting
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
                # Try to move to error directory manually
                try:
                    if file_obj is not None:
                        error_sub = str(file_obj.parent.relative_to(config.input_directory))
                        if error_sub == ".":
                            error_sub = ""
                        error_path = config.error_directory / error_sub / file_obj.name
                        PathHandler.safe_move(file_path, error_path)
                        display = f"{error_sub}/{file_obj.name}" if error_sub else file_obj.name
                        batch_logger.info(f"Moved {display} to error directory")
                except Exception as move_error:
                    batch_logger.error(
                        f"Failed to move {file_path} to error directory: {move_error}"
                    )
                # Continue to next file
                continue

        # Close zip archive for this batch
        if batch_zip_mgr:
            batch_zip_mgr.close()

        # Send email notification after batch completes
        try:
            send_batch_notification(config, batch_summary)
        except Exception as e:
            batch_logger.warning(f"Email notification failed: {e}")

        batch_logger.info("Batch processing complete, waiting for new files...")

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
        last_check_time = time.time()
        check_interval = 2  # Check for stale files every 2 seconds

        while True:
            time.sleep(check_interval)

            # Periodically check for stale (completed) files
            now = time.time()
            if now - last_check_time >= check_interval:
                last_check_time = now
                watcher_thread.watcher._check_batch_ready()

                # End-of-batch: check if today's log file needs rotation
                from logger_config import (
                    _swap_file_handler,
                    rotate_today_log,
                    _get_today_log_name,
                )

                today_name = _get_today_log_name(config.log_dir)
                if today_name:
                    today_path = config.log_dir / today_name
                    if today_path.exists():
                        if (
                            today_path.stat().st_size
                            >= config.max_log_size_mb * 1024 * 1024
                        ):
                            rotate_today_log(config.log_dir)
                            _swap_file_handler(config.log_dir)

                pending = watcher_thread.get_pending_count()
                if pending > 0:
                    logger.info(
                        f"[WATCHER] {pending} files pending (waiting for copy completion)..."
                    )

    except KeyboardInterrupt:
        logger.info("Shutdown requested...")
    finally:
        watcher_thread.stop()
        logger.info("Watcher shutdown complete")
