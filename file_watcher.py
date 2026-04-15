#!/usr/bin/env python3

"""
file_watcher.py v8.00
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
            
            # Check if file still exists (might be deleted immediately)
            if not os.path.exists(file_path):
                return
            
            self.pending_files[file_path] = {
                'created': time.time(),
                'last_modified': time.time(),
                'closed': False,
                'size': os.path.getsize(file_path)
            }
            self.logger.debug(f"File created: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error handling created event for {event.src_path}: {e}")
    
    def on_modified(self, event):
        """
        Triggered when file is modified (copy in progress).
        Updates last activity timestamp to reset batch timer.
        """
        if event.is_directory:
            return
        
        try:
            file_path = str(Path(event.src_path).resolve())
            
            if file_path in self.pending_files:
                # Update activity timestamp
                self.pending_files[file_path]['last_modified'] = time.time()
                self.pending_files[file_path]['size'] = os.path.getsize(file_path)
                
        except Exception as e:
            self.logger.debug(f"Error handling modified event for {event.src_path}: {e}")
    
    def on_closed(self, event):
        """
        Triggered when file handle is closed (copy complete).
        Marks file as ready for processing.
        """
        if event.is_directory:
            return
        
        try:
            file_path = str(Path(event.src_path).resolve())
            
            if file_path in self.pending_files:
                self.pending_files[file_path]['closed'] = True
                self.pending_files[file_path]['last_modified'] = time.time()
                self.logger.debug(f"File closed (copy complete): {file_path}")
                
                # Check if we should trigger batch immediately (single file, no delay)
                self._check_batch_ready()
                
        except Exception as e:
            self.logger.error(f"Error handling closed event for {event.src_path}: {e}")
    
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
        Conditions:
        1. All files are closed
        2. No activity for batch_delay seconds
        3. Batch size constraints met
        """
        if not self.pending_files:
            return
        
        now = time.time()
        
        # Check if all files are closed
        all_closed = all(info['closed'] for info in self.pending_files.values())
        
        if not all_closed:
            # Still copying, don't process yet
            return
        
        # Check batch size constraints
        file_count = len(self.pending_files)
        
        if self.min_batch > 0 and file_count < self.min_batch:
            # Wait for minimum batch size
            return
        
        if self.max_batch > 0 and file_count >= self.max_batch:
            # Max batch reached, trigger immediately
            self._trigger_batch()
            return
        
        # Check if delay elapsed since last activity
        last_activity = max(info['last_modified'] for info in self.pending_files.values())
        elapsed = now - last_activity
        
        if elapsed >= self.batch_delay:
            self._trigger_batch()
    
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


def start_watching(config, url):
    """
    Start file watching (blocking call).
    
    Args:
        config: ScannerConfig object
        url: TE API URL
    """
    logger = logging.getLogger('te_scanner.watcher')
    
    # Define batch processing callback
    def process_batch_callback(file_paths):
        """Process a batch of files."""
        from te_file_handler import TE
        from path_handler import PathHandler
        
        batch_logger = logging.getLogger('te_scanner.batch_processor')
        
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
                    config.error_directory
                )
                te.handle_file()
                
            except Exception as e:
                batch_logger.error(f"Error processing {file_path}: {e}")
                # Try to move to error directory manually
                try:
                    error_path = config.error_directory / file_obj.name
                    PathHandler.safe_move(file_path, error_path)
                    batch_logger.info(f"Moved {file_name} to error directory")
                except Exception as move_error:
                    batch_logger.error(f"Failed to move {file_name} to error directory: {move_error}")
                # Continue to next file
                continue
    
    # Create and start watcher
    watcher_thread = WatcherThread(config, process_batch_callback)
    watcher_thread.start()
    
    logger.info("Entering watch loop (Ctrl+C to stop)")
    
    try:
        while True:
            time.sleep(1)
            # Optional: Log pending count every 60 seconds
            if watcher_thread.get_pending_count() > 0:
                logger.debug(f"Pending files: {watcher_thread.get_pending_count()}")
                
    except KeyboardInterrupt:
        logger.info("Shutdown requested...")
    finally:
        watcher_thread.stop()
        logger.info("Watcher shutdown complete")
