# Timeline: Reduce Watcher Log Noise for `on_modified` and `File growing` Notifications

Estimated effort: **1 hour**

## Phase 1: Add Logging State Tracking (15 min)

**Files:** `file_watcher.py`

- [x] Add `last_log_time = {}` dictionary to `CopyCompletionWatcher.__init__()` state tracking
- [x] Add `log_interval = 5.0` attribute to `CopyCompletionWatcher.__init__()`
- [x] Verify the state tracking variables are in the correct order and properly documented

## Phase 2: Modify `on_modified()` Method with Throttled Logging (30 min)

**Files:** `file_watcher.py`

- [x] Update `CopyCompletionWatcher.on_modified()` docstring to mention 5-second throttling
- [x] Add time-based throttling logic before logging:
  - Calculate `now = time.time()`
  - Check if `file_path not in self.last_log_time or (now - self.last_log_time[file_path]) >= self.log_interval`
  - Set `should_log = True` and update `self.last_log_time[file_path] = now` if condition met
- [x] Move logging statements outside the `with self._lock:` block
- [x] Wrap logging in `if should_log:` condition
- [x] Verify the `pending_files` state is still updated correctly inside the lock
- [x] Verify `_check_batch_ready()` is still called after logging

## Phase 3: Cleanup Old Log Times (15 min)

**Files:** `file_watcher.py`

- [x] Locate the file cleanup loop in `CopyCompletionWatcher._check_batch_ready()` (around line 228)
- [x] Add `self.last_log_time.pop(path, None)` to the cleanup loop
- [x] Verify no other places add files to `pending_files` without corresponding `last_log_time` initialization (e.g., fallback scan)

## Phase 4: Verification & Testing (30 min)

- [x] Run a test copy of a large file (several GB) into the watch directory
- [x] Verify that the log shows `[WATCHER] on_modified: {file_path}` and `[WATCHER] File growing: ...` only once every 5 seconds
- [x] Verify that the batch processing still works correctly (files are processed after the quiet period)
- [x] Verify that no memory leak occurs from the `last_log_time` dictionary (files are removed when processed)
- [x] Check log file size after the test to confirm significant reduction in log lines

## Total Estimated Time

| Phase | Time |
|---|---|
| 1: Add logging state tracking | 15 min |
| 2: Modify `on_modified()` with throttled logging | 30 min |
| 3: Cleanup old log times | 15 min |
| 4: Verification & testing | 30 min |
| **Total** | **1–1.5 hours** |

</content>
<parameter=filePath>
/home/andyn/dev/TE_API_AndyN/plans/015-reduce-watcher-log-noise/timeline.md