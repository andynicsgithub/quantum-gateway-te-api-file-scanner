#!/usr/bin/env python3

"""
file_watcher.py v9.1 (alpha)
Cross-platform file watcher for TE API Scanner using watchdog.
Features:
  - Detects file completion using three-tier monitoring (created, modified, closed)
  - Batch collection with configurable delay after all files closed
  - Recursive subdirectory monitoring
  - Cross-platform support (Windows/Linux)
"""

import os
import time
import logging
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


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
        self.logger = logging.getLogger('te_scanner.watcher')
        
        # State tracking
        self.pending_files = {}  # path -> {created, last_modified, closed, size}
        self.batch_delay = config.watch_batch_delay
        self.min_batch = config.watch_min_batch
        self.max_batch = config.watch_max_batch
        
        self.logger.info(f"CopyCompletionWatcher initialized: delay={self.batch_delay}s, "
                        f"min_batch={self.min_batch}, max_batch={self.max_batch}")
    
    def on_created(self, event):
        """
        Triggered when a file is created (copy started).
        """
        if event.is_directory:
            return
        
        try:
            file_path = str(Path(event.src_path).resolve())
            self.logger.info(f"[WATCHER] on_created: {file_path}")
            
            # Check if file still exists (might be deleted immediately)
            if not os.path.exists(file_path):
                self.logger.warning(f"[WATCHER] File deleted immediately: {file_path}")
                return
            
            self.pending_files[file_path] = {
                'created': time.time(),
                'last_modified': time.time(),
                'closed': False,
                'size': os.path.getsize(file_path)
            }
            self.logger.info(f"[WATCHER] Added to pending: {file_path} (size: {self.pending_files[file_path]['size']} bytes)")
            
            # Check if this single file should trigger immediately
            self._check_batch_ready()
            
        except Exception as e:
            self.logger.error(f"[WATCHER] Error handling created event for {event.src_path}: {e}")
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
            
            if file_path in self.pending_files:
                # Update activity timestamp
                old_size = self.pending_files[file_path]['size']
                self.pending_files[file_path]['last_modified'] = time.time()
                new_size = os.path.getsize(file_path)
                self.pending_files[file_path]['size'] = new_size
                self.logger.info(f"[WATCHER] File growing: {file_path} ({old_size} → {new_size} bytes)")
                
                # Check if this file might be done copying
                self._check_batch_ready()
                
        except Exception as e:
            self.logger.error(f"[WATCHER] Error handling modified event for {event.src_path}: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def on_closed(self, event):
        """
        Triggered when file handle is closed (copy complete).
        Marks file as ready for processing.
        """
        if event.is_directory:
            return
        
        try:
            file_path = str(Path(event.src_path).resolve())
            self.logger.info(f"[WATCHER] on_closed: {file_path}")
            
            if file_path in self.pending_files:
                self.pending_files[file_path]['closed'] = True
                self.pending_files[file_path]['last_modified'] = time.time()
                self.logger.info(f"[WATCHER] File closed (copy complete): {file_path}")
                
                # Check if we should trigger batch immediately (single file, no delay)
                self._check_batch_ready()
                
        except Exception as e:
            self.logger.error(f"[WATCHER] Error handling closed event for {event.src_path}: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def on_moved(self, event):
        """
        Handle file moved into watched directory.
        """
        if event.is_directory:
            return
        
        # Treat as created event
        self.on_created(event)
    
    def _check_batch_ready(self):
        """
        Check if batch should be processed.
        Uses "stale file" detection: a file is ready if it hasn't been modified
        for batch_delay seconds. This works on all platforms, even where
        on_closed events don't fire (Windows).
        """
        if not self.pending_files:
            return
        
        now = time.time()
        
        # Find files that are "stale" (no modification for batch_delay seconds)
        stale_files = {}
        still_copying = False
        
        for file_path, info in self.pending_files.items():
            time_since_last_modified = now - info['last_modified']
            
            # Check batch size constraints first
            if self.min_batch > 0:
                file_count = len(self.pending_files)
                if file_count < self.min_batch:
                    still_copying = True
                    continue
            
            if self.max_batch > 0 and len(self.pending_files) >= self.max_batch:
                # Max batch reached, process all
                still_copying = True
                continue
            
            if time_since_last_modified >= self.batch_delay:
                stale_files[file_path] = info
                self.logger.info(f"[WATCHER] File marked as ready (stale for {time_since_last_modified:.1f}s): {file_path}")
            else:
                still_copying = True
        
        if still_copying or not stale_files:
            return
        
        # Process stale files
        self.logger.info(f"[WATCHER] {len(stale_files)} files ready for processing")
        self._trigger_stale_batch(stale_files)
    
    def _trigger_stale_batch(self, stale_files):
        """
        Trigger batch processing for stale (completed) files.
        """
        if not stale_files:
            return
        
        file_paths = list(stale_files.keys())
        for path in file_paths:
            del self.pending_files[path]
        
        self.logger.info(f"[WATCHER] Triggering batch processing: {len(file_paths)} files")
        
        try:
            self.batch_callback(file_paths)
        except Exception as e:
            self.logger.error(f"[WATCHER] Error in batch callback: {e}")
            for path in file_paths:
                if os.path.exists(path):
                    self.pending_files[path] = {
                        'created': time.time(),
                        'last_modified': time.time(),
                        'closed': True,
                        'size': os.path.getsize(path)
                    }
    
    def _trigger_batch(self):
        """
        Trigger batch processing.
        """
        if not self.pending_files:
            return
        
        file_paths = list(self.pending_files.keys())
        self.pending_files.clear()
        
        self.logger.info(f"Triggering batch processing: {len(file_paths)} files")
        
        # Call callback (process_batch function)
        try:
            self.batch_callback(file_paths)
        except Exception as e:
            self.logger.error(f"Error in batch callback: {e}")
            # Put files back in pending to retry
            for path in file_paths:
                if os.path.exists(path):
                    self.pending_files[path] = {
                        'created': time.time(),
                        'last_modified': time.time(),
                        'closed': True,
                        'size': os.path.getsize(path)
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
        self.logger = logging.getLogger('te_scanner.watcher')
        
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
        self.logger.info(f"Using stale file detection (fallback for Windows)")
    
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


def start_watching(config, url, initial_zip_mgr=None):
    """
    Start file watching (blocking call).
    
    Args:
        config: ScannerConfig object
        url: TE API URL
        initial_zip_mgr: ZipArchiveManager for pre-existing files (None = not applicable)
    """
    logger = logging.getLogger('te_scanner.watcher')
    
    # Build zip config tuple for TE instances (used in watch mode single-process)
    zip_config = None
    if config.zip_password and not initial_zip_mgr:
        # Per-batch zip - config passed as tuple for consistency with te_file_handler
        pass  # zip_config set per-batch inside process_batch_callback
    
    # Define batch processing callback
    def process_batch_callback(file_paths):
        """Process a batch of files."""
        from te_file_handler import TE
        from path_handler import PathHandler
        from notification import send_batch_notification
        from zip_archive import ZipArchiveManager
        
        batch_logger = logging.getLogger('te_scanner.batch_processor')
        
        # Create per-batch zip archive if configured
        batch_zip_mgr = None
        if config.zip_password:
            batch_timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            batch_zip_mgr = ZipArchiveManager.create_archive(
                config.zip_archive_directory, config.zip_password, batch_timestamp
            )
            if batch_zip_mgr:
                batch_logger.info(f"Zip archive: {batch_zip_mgr.zip_path}")
            else:
                batch_logger.warning("Failed to create zip archive for batch")
        
        # Track batch results for email notification
        batch_summary = {
            'processed': 0,
            'benign': 0,
            'malicious': 0,
            'error': 0,
            'malicious_files': [],
            'all_files': []
        }
        
        for file_path in file_paths:
            # Verify file still exists
            if not os.path.exists(file_path):
                batch_logger.warning(f"File no longer exists: {file_path}")
                continue
            
            try:
                # Extract file info
                file_obj = Path(file_path)
                file_name = file_obj.name
                sub_dir = str(file_obj.parent.relative_to(config.input_directory))
                full_path = str(file_obj)
                
                # Handle root directory case
                if sub_dir == '.':
                    sub_dir = ''
                
                batch_logger.info(f"Processing: {file_name}")
                
                # Create TE instance and process
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
                    zip_config=batch_zip_mgr if batch_zip_mgr else None
                )
                te.handle_file()
                
                # Track results
                batch_summary['processed'] += 1
                
                if te.final_status_label == "FOUND":
                    verdict = te.parse_verdict(te.final_response, "te")
                    batch_summary['all_files'].append({
                        'name': file_name,
                        'path': sub_dir if sub_dir else '',
                        'verdict': verdict
                    })
                    if verdict == "Malicious":
                        batch_summary['malicious'] += 1
                        batch_summary['malicious_files'].append({
                            'name': file_name,
                            'verdict': verdict
                        })
                    elif verdict == "Benign":
                        batch_summary['benign'] += 1
                    elif verdict == "Error":
                        batch_summary['error'] += 1
                else:
                    batch_summary['all_files'].append({
                        'name': file_name,
                        'path': sub_dir if sub_dir else '',
                        'verdict': te.final_status_label if te.final_status_label else 'Not_Found'
                    })
                    batch_summary['error'] += 1
                
            except Exception as e:
                batch_logger.error(f"Error processing {file_path}: {e}")
                batch_summary['error'] += 1
                batch_summary['all_files'].append({
                    'name': file_name,
                    'path': sub_dir if sub_dir else '',
                    'verdict': 'Error'
                })
                # Try to move to error directory manually
                try:
                    error_path = config.error_directory / file_obj.name
                    PathHandler.safe_move(file_path, error_path)
                    batch_logger.info(f"Moved {file_name} to error directory")
                except Exception as move_error:
                    batch_logger.error(f"Failed to move {file_name} to error directory: {move_error}")
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
                pending = watcher_thread.get_pending_count()
                if pending > 0:
                    logger.info(f"[WATCHER] {pending} files pending (waiting for copy completion)...")
                
    except KeyboardInterrupt:
        logger.info("Shutdown requested...")
    finally:
        watcher_thread.stop()
        logger.info("Watcher shutdown complete")
