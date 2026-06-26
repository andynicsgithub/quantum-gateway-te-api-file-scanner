# Decisions: Reduce Watcher Log Noise for `on_modified` and `File growing` Notifications

## D1: Time-Based Throttling (5 seconds)

**Decision:** Use time-based throttling with a 5-second interval for logging `on_modified` and `File growing` notifications.

**Rationale:**
- Predictable log frequency that is easy to understand and configure
- Significantly reduces noise without losing all visibility into file copy progress
- The file copy completion is still detected via the quiet-period trigger (`batch_delay`), so the detailed growth logs are not strictly necessary for functionality—only for user visibility
- 5 seconds is a reasonable balance: frequent enough to show progress, infrequent enough to avoid log spam

Alternatives considered:
- **Size-based thresholds (e.g., 10MB)**: Requires calculating size delta; may still log frequently for very large files or rapidly growing files
- **Remove logs entirely**: Maximum noise reduction but loses all visibility into file copy progress
- **Longer time interval (e.g., 10 or 30 seconds)**: Reduces logs further but may make users think the file copy is stalled

## D2: Throttle Both `on_modified` and `File growing` Logs

**Decision:** Apply the 5-second throttling to both the `[WATCHER] on_modified: {file_path}` and `[WATCHER] File growing: {file_path} ({old_size} → {new_size} bytes)` log lines.

**Rationale:**
- Both logs are emitted together for every `on_modified` event
- Users want to reduce the overall noise, not just the size details
- Keeping only the `on_modified` log without the size details would still generate 1 log line per event, which is still too frequent for large files

## D3: Log Outside the Lock

**Decision:** Move the logging statements outside the `with self._lock:` block in `on_modified()`.

**Rationale:**
- Logging is an I/O operation that can be slow and should not block the event processing thread
- The `pending_files` state is already updated inside the lock, so the size data is safely captured before logging
- This maintains the performance characteristics of the watcher event handler

## D4: Clean Up `last_log_time` When Files Are Dispatched

**Decision:** Remove file paths from `last_log_time` when they are removed from `pending_files` in `_check_batch_ready()`.

**Rationale:**
- Prevents memory leaks from the `last_log_time` dictionary over long-running watch sessions
- Files that have been processed or dispatched no longer need log time tracking
- Uses `self.last_log_time.pop(path, None)` to safely remove without raising KeyError if the path is already gone

## D5: No Config Option for Log Interval

**Decision:** Hardcode the `log_interval` to 5.0 seconds as a class attribute, rather than adding a config option.

**Rationale:**
- The log interval is a visibility concern, not a functional configuration
- Users rarely need to adjust log throttling intervals
- Hardcoding simplifies the config layer and reduces complexity
- If users need a different interval in the future, it can be added as a config option later

## D6: No Changes to Other Watcher Events

**Decision:** Only modify `on_modified()` logging. Do not change `on_created`, `on_moved`, or `on_closed` logging.

**Rationale:**
- `on_created` and `on_moved` events are infrequent (only when a file first appears)
- `on_closed` events are not actually emitted by the watchdog library on Windows (as noted in the code comments), so they don't generate noise
- The `on_modified` event is the only one that generates frequent, repetitive logs during file copy

</content>
<parameter=filePath>
/home/andyn/dev/TE_API_AndyN/plans/015-reduce-watcher-log-noise/decisions.md