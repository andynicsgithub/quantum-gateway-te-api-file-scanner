# Plan: Reduce Watcher Log Noise for `on_modified` and `File growing` Notifications

## Goal

Reduce excessive logging from the file watcher when large files are copied into the watch directory. Currently, the `CopyCompletionWatcher.on_modified()` method logs two lines per `on_modified` event:

1. `[WATCHER] on_modified: {file_path}`
2. `[WATCHER] File growing: {file_path} ({old_size} → {new_size} bytes)`

For a several-GB file, this results in ~15,000+ log lines, creating excessive noise and making it difficult to monitor actual file processing activity.

**Solution:** Implement a **time-based throttling mechanism** that logs the `on_modified` and `File growing` notifications only once every **5 seconds** per file, rather than on every `on_modified` event.

---

## Background & Current State

### Issue: Excessive `on_modified` Logging

When copying large files into the watch directory, the `watchdog` library generates frequent `on_modified` events as the file is written in small chunks. The current implementation in `file_watcher.py` (lines 117-149) logs two lines for every `on_modified` event:

```python
def on_modified(self, event):
    if event.is_directory:
        return

    try:
        file_path = str(Path(event.src_path).resolve())
        self.logger.info(f"[WATCHER] on_modified: {file_path}")  # Line 127

        with self._lock:
            if file_path not in self.pending_files:
                return
            old_size = self.pending_files[file_path]["size"]
            self.pending_files[file_path]["last_modified"] = time.time()
            self.last_activity = time.time()
            new_size = os.path.getsize(file_path)
            self.pending_files[file_path]["size"] = new_size
        self.logger.info(
            f"[WATCHER] File growing: {file_path} ({old_size} → {new_size} bytes)"  # Lines 137-139
        )

        self._check_batch_ready()
```

For a several-GB file copied over the network, the `watchdog` library generates `on_modified` events for each write chunk (often 1MB or smaller increments). This results in ~15,000+ log lines, creating excessive noise.

**Impact:** 
- Log files become large and difficult to parse
- Actual file processing activity is obscured by growth notifications
- No functional benefit from logging every size change (batch processing still uses the quiet-period trigger)

---

## Changes in Detail

### Change 1: Add Logging State Tracking

**File:** `file_watcher.py`  
**Location:** `CopyCompletionWatcher.__init__()` (around line 62)

Add a new dictionary to track the last log time per file, and a constant for the log interval:

```python
# State tracking
self.pending_files = {}  # path -> {created, last_modified, closed, size}
self.last_log_time = {}  # path -> last log timestamp (for throttling)
self._lock = threading.Lock()
self.last_activity = 0.0
self._batch_dispatched = False  # Set before batch callback, cleared after
self._batch_processing = False  # True while batch callback is running
self.batch_delay = config.watch_batch_delay
self.max_batch = config.watch_max_batch
self.log_interval = 5.0  # 5 seconds between log notifications per file
```

### Change 2: Modify `on_modified()` Method with Throttled Logging

**File:** `file_watcher.py`  
**Location:** `CopyCompletionWatcher.on_modified()` (lines 117-149)

Replace the current logging logic with throttled logging:

```python
def on_modified(self, event):
    """
    Triggered when file is modified (copy in progress).
    Updates last activity timestamp to reset batch timer.
    Logs file growth events at most once every 5 seconds per file.
    """
    if event.is_directory:
        return

    try:
        file_path = str(Path(event.src_path).resolve())

        with self._lock:
            if file_path not in self.pending_files:
                return
            
            # Throttle logging: only log if 5 seconds have passed since last log for this file
            now = time.time()
            should_log = False
            if file_path not in self.last_log_time or (now - self.last_log_time[file_path]) >= self.log_interval:
                should_log = True
                self.last_log_time[file_path] = now
            
            old_size = self.pending_files[file_path]["size"]
            self.pending_files[file_path]["last_modified"] = time.time()
            self.last_activity = time.time()
            new_size = os.path.getsize(file_path)
            self.pending_files[file_path]["size"] = new_size
        
        # Log outside the lock to avoid blocking event processing
        if should_log:
            self.logger.info(f"[WATCHER] on_modified: {file_path}")
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
```

### Change 3: Cleanup Old Log Times

**File:** `file_watcher.py`  
**Location:** `CopyCompletionWatcher._check_batch_ready()` (around line 228)

When files are removed from `pending_files` (dispatched or processed), remove them from `last_log_time` to prevent memory leaks:

```python
for path in file_paths:
    self.pending_files.pop(path, None)
    self.last_log_time.pop(path, None)  # Clean up log time tracking
```

---

## Tradeoffs Considered

| Approach | Pros | Cons |
|----------|------|------|
| **Time-based throttling (5 sec)** | Predictable log frequency; easy to understand; reduces noise significantly | May miss rapid size changes if file grows quickly in <5 sec windows |
| **Size-based thresholds (e.g., 10MB)** | Tracks actual data transfer progress | Requires calculating delta; may still log frequently for very large files |
| **Remove logs entirely** | Maximum noise reduction | Loses all visibility into file copy progress |

**Selected Approach:** Time-based throttling (5 seconds) balances visibility with noise reduction. The file copy completion is still detected via the quiet-period trigger (`batch_delay`), so the detailed growth logs are not strictly necessary for functionality—only for user visibility.

---

## Files to Modify

1. **`file_watcher.py`**
   - `CopyCompletionWatcher.__init__()`: Add `last_log_time` dictionary and `log_interval` attribute
   - `CopyCompletionWatcher.on_modified()`: Implement throttled logging logic
   - `CopyCompletionWatcher._check_batch_ready()`: Clean up `last_log_time` when files are dispatched

---

## Verification Steps

1. Copy a large file (several GB) into the watch directory
2. Verify that the log shows `[WATCHER] on_modified: {file_path}` and `[WATCHER] File growing: ...` only once every 5 seconds
3. Verify that the batch processing still works correctly (files are processed after the quiet period)
4. Verify that no memory leak occurs from the `last_log_time` dictionary (files are removed when processed)

---

## Non-Goals

- No changes to the batch processing logic or quiet-period trigger
- No changes to `on_created`, `on_moved`, or `on_closed` logging
- No changes to the file watcher mode's core functionality or stability checks

</content>
<parameter=filePath>
/home/andyn/dev/TE_API_AndyN/plans/015-reduce-watcher-log-noise/plan.md