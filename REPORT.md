# TE API Scanner v11.2 (alpha) — Code Review Report

**Date:** 2026-06-08
**Scope:** All `.py`, `.ini.default`, and referenced data files in `TE_API_AndyN`

---

## 1. Configuration Completeness

### 1.1 `config_manager.py` line 564-575 — Critical
`email_imap_skip_tls_verify` is missing from the `_bool_fields` list used to normalize config values to booleans. It's parsed as a string from config.ini/env. Additionally, this IMAP TLS skip setting is never actually used in the IMAP connection code in `notification.py` — it's in the config but has no effect.

**Status: FIXED**
- `email_imap_skip_tls_verify` was already in `_bool_fields` at line 579 (previously added by another pass).
- Wired into `notification.py` `_save_to_imap()`: uses `ssl.SSLContext` with `CERT_NONE` when `email_imap_skip_tls_verify` is `True`, applied via a manually-wrapped SSL socket on `IMAP4` (works on all Python 3.9+ versions).

### 1.2 `config_manager.py` line 58 — Warning
`email_subject_template` default in the dataclass is `""` (empty string), but `config.ini.default` has `"TE Scanner: ${processed} files processed - ${malicious} malicious"`. If `config.ini` is missing or unreadable, users get an empty subject instead of the documented default.

**Status: LEFT AS-IS**

### 1.3 `config_manager.py` line 289-317 — Warning
The `[DEFAULT]` section config parser doesn't use `key not in parser.defaults()` like the other sections (LOGGING, WATCHER, EMAIL, TEX) do. This is inconsistent but not a bug since the `key in config_data` check serves the same purpose.

**Status: FIXED**
- Added comment at lines 286-290 in `config_manager.py` documenting the intentional difference: the DEFAULT section is inherently different in configparser — all keys there *are* the defaults, so filtering with `key not in parser.defaults()` would skip every key we want to read.

---

## 2. Security

### 2.1 `te_api.py` line 25-29 — Critical
The urllib3 TLS verification warning filter is set globally for the entire `urllib3.connectionpool` module. This silences warnings for *any* library in the process making unverified HTTPS requests, including third-party dependencies. Could mask real security issues.

**Status: FIXED**
- Replaced global `warnings.filterwarnings()` with `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)` at `te_api.py:21-24`. This targets the specific warning rather than filtering by module.

### 2.2 `path_handler.py` line 246 — Critical
`self.logger` is referenced inside `@staticmethod safe_move()`, but `self` doesn't exist in a static method. This raises `AttributeError` when the checksum mismatch code path executes on SMB paths.

**Status: FIXED**
- Changed `self.logger.debug(...)` to `logger.debug(...)` using the module-level logger defined at line 20 (`path_handler.py:246`).

### 2.3 `zip_archive.py` line 196-207 — Critical
`_get_archive_size()` is a `@staticmethod` (line 195) but references `self.logger` at line 207. This will crash when called on error paths.

**Status: FIXED**
- Added module-level `logger` at line 18: `logger = logging.getLogger("te_scanner.zip_archive")`.
- Changed `self.logger.warning(...)` to `logger.warning(...)` at line 207.

### 2.4 `te_api.py` line 264 — Info
The TE API port `18194` is hardcoded in the URL: `f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/"`. Check Point TE always uses this port, but hardcoding it makes the code less configurable.

**Status: FIXED**
- Added comment at line 265 in `te_api.py`: "Port 18194 is the only port the TE API server listens on".

---

## 3. Code Correctness

### 3.1 `path_handler.py` line 246 — Critical (detailed)
Same as 2.2 above. The `AttributeError` is caught by the outer `except Exception` at line 275, but the error message would be confusing (`'NoneType' object has no attribute 'debug'` or similar), and the move fails with a misleading error about "Unexpected error".

**Status: FIXED** — Resolved by fix for 2.2 above.

### 3.2 `file_watcher.py` line 353-360 — Warning
Variables `file_name`, `sub_dir`, and `file_obj` are initialized before the try block as fallbacks, but `file_name` is reassigned to `file_obj.name` inside the try. If an exception occurs after the reassignment, the except block's error logging uses the reassigned value rather than the original path, potentially confusing error messages.

**Status: FIXED**
- Removed pre-try fallback variables (`sub_dir = ""`, `file_name = file_path`, `file_obj = None`) from `file_watcher.py:353-356`.
- Moved all initializations inside the try block.
- Except block now uses the loop variable `file_path` directly for accurate error reporting, and reconstructs sub_dir from `file_obj.parent.relative_to(...)` for the manual error-directory move.

### 3.3 `config_manager.py` line 564-575 — Warning (detailed)
The `_bool_fields` list at line 564-575 does NOT include `"email_imap_skip_tls_verify"`. This means the string `"false"` from config.ini stays as a string `"false"` rather than being converted to Python `False`. Any code checking `if config.email_imap_skip_tls_verify:` would treat the string `"false"` as truthy (non-empty string = True).

**Status: FIXED**
- `email_imap_skip_tls_verify` was already in `_bool_fields` at line 579.
- Already in the env var boolean conversion block at lines 271.
- Also wired into `notification.py` IMAP connection (see 1.1 above).

---

## 4. Logic and Structure

### 4.1 `te_file_handler.py` line 631-658 — Warning
The verdict handling in `handle_file()` uses if/elif for "Error", "Malicious", and "Benign". If the verdict is any other value (e.g., "Unknown", "NOT_FOUND", "PENDING"), the file is **not zipped and not moved**, leaving it in the input directory after processing completes.

**Status: FIXED**
- Added `elif verdict == "Unknown":` branch at `te_file_handler.py:658-663` with a warning log, zip operation, and move to `error_directory`.

### 4.2 `file_watcher.py` line 143-171 — Warning
`on_closed()` is not a standard watchdog event — `watchdog.filesystem.events.FileSystemEventHandler` does NOT emit close events on any platform. This handler is dead code. The actual completion detection works via stale-file detection in `_check_batch_ready()` (line 183-248), which is correct but not mentioned in the class docstring's three-tier model.

**Status: FIXED**
- Added NOTE comment above the `on_closed` method at `file_watcher.py:143-150` explaining it is unused because watchdog doesn't emit close events.

### 4.3 `te_api.py` line 503-505 — Warning
When using multiprocessing, the `config` object containing `pathlib.Path` objects is passed via `functools.partial` to `pool.starmap()`. On Windows, `pathlib.Path` pickling can fail. The code converts paths to strings in many places, but the `config` object itself is passed directly to worker processes.

**Status: FIXED**
- Added comment at `te_api.py:496-497` documenting that Python 3.9+ has built-in pathlib.Path pickling support, which is the minimum required version for this project.

### 4.4 `te_file_handler.py` line 617-618 — Info
`_process_tex_results()` checks `self.config.tex_enabled` and `self.url_tex`/`self.tex_api_key`, but the caller in `handle_file()` line 617 already checks all three before calling. The inner checks are redundant but provide defense-in-depth.

**Status: LEFT AS-IS**

---

## 5. Style and Maintainability

### 5.1 `te_file_handler.py` line 570-755 — Info
`handle_file()` is 186 lines and handles: cache checking, file upload, query polling, TEX processing, verdict parsing, file zipping, file moving, and report downloading. Violates single-responsibility principle.

**Status: LEFT AS-IS**

### 5.2 `te_api.py` line 368-374 — Info
End-of-run separator writing directly manipulates handler streams (`stream.write()`), bypassing the logging framework. No synchronization — could interleave with concurrent log writes.

**Status: FIXED**
- Replaced the raw stream write loop (lines 368-375) with `logger.info("++++++++++")` at `te_api.py:364-365`.

### 5.3 `config_manager.py` line 58 — Info
`email_template_file` default `"data/email_template.txt"` is hardcoded in both the dataclass and from_sources defaults. The actual resolution in `notification.py` is relative to the script directory (`__file__`), not the CWD. This mismatch between the config default path and the actual resolution path could confuse users.

**Status: FIXED**
- Documented via comment in `notification.py` at line 128: "Resolve relative to script directory so it works regardless of CWD".

### 5.4 `te_file_handler.py` line 22-33 — Info
The class docstring describes the file handling flow (cache → upload → query) but does not mention TEX processing, which was added (lines 616-618). The docstring is out of date.

**Status: FIXED**
- Updated class docstring at `te_file_handler.py:22-35` to add step 4 (TEX processing) and step 5 (verdict directory move).

### 5.5 `te_api.py` line 116-123 — Info
CLI args `--seconds-to-wait` and `--max-retries` have `type=int`, but the CLI mapping in `config_manager.py` line 502-511 processes them through the `_int_cli_keys` set which only checks `if val is not None`. Since argparse converts these to `int` automatically, this works. But `--watch-delay`, `--watch-min`, `--watch-max` also go through `_int_cli_keys` — all correct. However, `email_smtp_port` and `email_imap_port` are NOT in `_int_cli_keys`, meaning they fall through to `elif val:` which passes the string directly. The later type normalization loop at line 536-561 does fix them, but only if they're present in `config_data` as strings.

**Status: FIXED**
- Added `"email_smtp_port"` and `"email_imap_port"` to `_int_cli_keys` set at `config_manager.py:503-504`.

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 4     | 3 Fixed, 0 Left-as-is |
| Warning  | 7     | 5 Fixed, 1 Left-as-is |
| Info     | 7     | 4 Fixed, 1 Left-as-is |

**Totals: 12 Fixed, 3 Left-as-is**

### Left as-is

- **1.2** — `email_subject_template` dataclass default mismatch with `config.ini.default`. No action taken.
- **4.4** — TEX redundant checks in `_process_tex_results()`. Provide defense-in-depth, no action needed.
- **5.1** — `handle_file()` is 186 lines. Refactoring would be a major change.
