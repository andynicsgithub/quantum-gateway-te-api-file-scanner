# Code Review Report — TE API Scanner v11.2 (alpha)

**Date:** 2026-06-06
**Scope:** All Python files, `config.ini.default`, `data/email_template.txt`

---

## Verification of Previous Report's New Findings

### Fixed ✅ (Previous Report)

| Finding | File / Lines | Evidence |
|---------|-------------|---------|
| `--max-retries` CLI arg missing | `te_api.py` | Added at lines 95–99; mapped in `_cli_mappings` at line 445 |
| Unguarded `query_file()` consumption in `handle_file` | `te_file_handler.py:584-590` | Wrapped in `try/except (KeyError, IndexError)` |
| Unguarded dict accesses inside `query_file()` | `te_file_handler.py:252-300` | All four accesses now guarded with `try/except` |
| IMAP connections have no timeout | `notification.py:343-347` | `timeout=30` added to all three `IMAP4`/`IMAP4_SSL` constructors |
| `file_obj` NameError in watcher except handler | `file_watcher.py:345` | `file_obj = None` pre-initialised before the `try` block |
| `--watch` not guaranteed in `SvcDoRun` | `service_wrapper.py:104-105` | Guard + `sys.argv.append("--watch")` now present |
| Comment misindentation at lines 91–92 | `te_file_handler.py` | Lines 92–95 now have correct 8-space indent |

### Fixed ✅ (This Review Round)

| Finding | File / Lines | Severity | Fix Applied |
|---------|-------------|----------|-------------|
| `typing.Set` NameError (Critical) | `config_manager.py` | **Critical** | Added `Set` to `from typing import`; replaced 3× `typing.Set` → `Set` |
| `if config else True` TLS fallback | `te_file_handler.py:90` | **Warning** | Changed `True` → `False` |
| Unguarded `image_j["status"]` | `te_file_handler.py:303` | **Warning** | Changed to `image_j.get("status", "")` |
| TOCTOU race in watcher handlers | `file_watcher.py:119-161` | **Warning** | Moved membership guards inside `with self._lock:` for both `on_modified` and `on_closed` |
| `--appliance-skip-tls-verify` no toggle | `te_api.py` + `config_manager.py` | **Warning** | Added `--no-appliance-skip-tls-verify` flag with `default=None`; added `_cli_override_keys` |
| `watch_batch_delay` comment | `config.ini.default:45` | **Info** | Updated comment to "Must be between 1 and 60." |
| 7-space indent in `te_api.py` | `te_api.py:352` | **Info** | Corrected to 8-space indent |
| Docstring lie in `cleanup_old_logs` | `logger_config.py:78` | **Info** | Removed "Keeps at least 1 file." claim |
| IMAP flags `""` | `notification.py:362` | **Info** | Changed to `"()"` per RFC 3501 |

### Not Fixed ❌

| Finding | File | Line | Severity | Status |
|---------|------|------|----------|--------|
| (None) | — | — | — | All findings from previous report have been addressed |

---

## Issues to Ignore

These issues were identified but intentionally left unfixed for the current release cycle.

| ID | File | Line | Severity | Issue |
|----|------|------|----------|-------|
| W10 | `file_watcher.py` | 205 | **Warning** | When `max_batch` is reached, `stale_files = dict(self.pending_files)` grabs all pending files without checking their `"closed"` status. Partially-copied files could slip into the batch. |
| S14 | `te_file_handler.py` | 613–630 | **Info** | The Malicious/Benign/Error branches are still separate (`if`/`elif`/`elif`), each logging and calling `_add_to_zip` / `move_file`. No duplication reduction was performed. |

---

## 1. Configuration Completeness

- Every key in `config.ini.default` is present in `config_data` defaults and read in `config_manager.py`. No orphan config keys found.
- Every key read in code exists in `config.ini.default`. `watch_mode` is the only key in `config_data` with no config-file counterpart; this is intentional (CLI-only via `--watch`).
- All integer fields are covered by the final catch-all int-conversion loop (lines 511–537), so strings from configparser are always converted before use.
- Boolean fields: all eight bool fields that can arrive as strings from configparser are in `_bool_fields` (lines 540–550). No omissions.

| File | Line | Severity | Finding | Fix |
|------|------|----------|---------|-----|
| `config.ini.default` | 46 | **Info** | Comment says `watch_batch_delay` "Must be 1 or greater" but the code also enforces a maximum of 60 seconds (`config_manager.py:134`). The upper limit is undocumented for users. | Add `# Must be between 1 and 60` to the comment. | **Fixed** ✅ — Comment updated to `# Must be between 1 and 60.` |

---

## 2. Security

| File | Line | Severity | Finding | Fix |
|------|------|----------|---------|-----|
| `te_file_handler.py` | 90 | **Warning** | `self.skip_tls_verify = config.appliance_skip_tls_verify if config else True` — the `config=None` fallback silently disables TLS verification. No public caller omits `config` today, but the insecure default is a latent trap. | Change to `... if config else False`. | **Fixed** ✅ — Changed `True` → `False` on line 90. |

No hardcoded credentials, API keys, or secrets found in any Python file. Config defaults for passwords are correctly empty strings. No `verify=False` literals — TLS bypass is driven through `not self.skip_tls_verify` which defaults to `False`.

---

## 3. Code Correctness

| File | Line | Severity | Finding | Fix |
|------|------|----------|---------|-----|
| `config_manager.py` | 44, 83, 84 | **Critical** | `typing.Set[str]` and `typing.Set[int]` are used as qualified module attribute accesses, but `typing` is never imported as a module. The import at line 15 is `from typing import List, Optional, Tuple`, which does not put `typing` in scope. Python evaluates dataclass field annotations eagerly at class-definition time, so loading `config_manager` raises `NameError: name 'typing' is not defined`. The scanner cannot start at all. | Add `import typing` at the top of the file, **or** add `Set` to the `from typing import` line and replace `typing.Set` with `Set` on all three lines. | **Fixed** ✅ — Added `Set` to the `from typing import` on line 15; replaced all three `typing.Set` → `Set`. |
| `te_file_handler.py` | 303 | **Warning** | `image_j["status"]` is an unguarded dict access inside the `for image_j in te_images_j_arr` loop. The list itself is now retrieved under `try/except (KeyError, IndexError)`, but individual image elements are not checked. A malformed image object with no `"status"` key raises `KeyError` here, crashing the worker. | Use `image_j.get("status", "")` in the condition, or wrap the loop body in `try/except` matching the pattern applied to the outer accesses above. | **Fixed** ✅ — Changed to `image_j.get("status", "")` on line 303. |
| `file_watcher.py` | 121–124, 154–157 | **Warning** | Both `on_modified` and `on_closed` check `if file_path in self.pending_files` **outside** the lock, then access `self.pending_files[file_path]` **inside** the lock. The poll loop (main thread) calls `_check_batch_ready()` which pops entries from `pending_files` under the same lock. Between the membership check and the lock acquisition, the entry can be removed, producing a `KeyError`. The outer `try/except Exception` in each handler catches it, but it generates a spurious error log on every batch. | Move the membership guard inside the lock: acquire `self._lock` first, then check `if file_path not in self.pending_files: return`. | **Fixed** ✅ — Both handlers now check membership inside `with self._lock:` and return early if missing. |
| `te_api.py` | 83–86 | **Warning** | `--appliance-skip-tls-verify` uses `action="store_true"`. Once `appliance_skip_tls_verify = true` is set in `config.ini`, there is no CLI flag to override it back to `false` for a specific run. | Use `argparse.BooleanOptionalAction` (Python 3.9+) or add a complementary `--no-appliance-skip-tls-verify` flag. | **Fixed** ✅ — Added `--no-appliance-skip-tls-verify` with `store_false`/`default=None`; added `_cli_override_keys` to `config_manager.py` to handle `is not None` for this flag. |

---

## 4. Logic and Structure

| File | Line | Severity | Finding | Fix |
|------|------|----------|---------|-----|
| `te_file_handler.py` | 90 | **Warning** | (Repeated from §2 / previous report.) The `if config else True` guard defaults TLS verification **off** when `config` is absent. All current callers pass `config`, but the default makes future misuse dangerous. | Change the fallback to `False`. | **Fixed** ✅ — Same fix as §2; see above. |

No other logic errors found. The TEX flow, verdict branching, zip consolidation, and watch-mode batch callback all behave as intended by the architecture.

---

## 5. Style and Maintainability

| File | Line | Severity | Finding | Fix |
|------|------|----------|---------|-----|
| `config_manager.py` | 44, 83, 84 | **Info** | (Overlaps with §3 Critical above.) `typing.Set[str]` / `typing.Set[int]` mixes the qualified-module form with the `from typing import` style used for `List`, `Optional`, `Tuple` on line 15. | Standardise: either replace with `Set[str]` / `Set[int]` (add `Set` to the `from typing import` line), or replace all `from typing import` references with qualified `typing.*` forms. Consider also adding `from __future__ import annotations` and migrating to bare `set[str]` / `set[int]` (Python 3.9+ built-in generics) to resolve the version inconsistency entirely. | **Fixed** ✅ — Same fix as §3; see above. |
| `te_api.py` | 352 | **Info** | `       # End-of-run: rotate if over size limit...` has 7 leading spaces; the surrounding `else` block uses 8-space indent throughout. | Change to 8 spaces. | **Fixed** ✅ — Corrected to 8-space indent on line 352. |
| `logger_config.py` | 78 | **Info** | Docstring for `cleanup_old_logs` states "Keeps at least 1 file" but the code unconditionally deletes every file whose date precedes the cutoff. No guard enforces the minimum-one constraint. | Either remove the claim from the docstring, or add a guard that exempts the newest file from deletion when the list would otherwise be fully cleared. | **Fixed** ✅ — Removed "Keeps at least 1 file." claim from docstring. |
| `notification.py` | 362 | **Info** | `imap_conn.append(imap_folder, "", None, raw_msg.encode("utf-8"))` passes an empty string `""` for the IMAP flags argument. RFC 3501 expects the flags field to be a parenthesised list (`"()"` for no flags) or `None`. Some IMAP servers silently accept `""`, but others reject it, causing the save to fail (already caught by the outer `try/except`, so non-fatal). | Change the flags argument to `"()"`. | **Fixed** ✅ — Changed flags from `""` to `"()"` on line 362. |

---

## Summary by Severity

| Severity | Count | Key items |
|----------|-------|-----------|
| **Critical** | 1 | `config_manager.py` — `typing` not imported; scanner cannot start |
| **Warning** | 4 | `te_file_handler.py:90` TLS fallback; `:303` unguarded image access; `file_watcher.py` TOCTOU race; `te_api.py:83` CLI toggle missing |
| **Info** | 5 | Docstring lie in logger; IMAP flags empty string; indent off by one; type-annotation style inconsistency; undocumented max config constraint |
| **Total** | **10** | |

## Resolution Status

**All 10 findings have been fixed and verified.** Every module imports successfully.

## Top Priority (Resolved)

1. ~~`config_manager.py:44,83,84`~~ — **Fixed** — `Set` added to `from typing import`, all `typing.Set` replaced.
2. ~~`file_watcher.py:121-124, 154-157`~~ — **Fixed** — Membership guards moved inside lock in both handlers.
3. ~~`te_file_handler.py:303`~~ — **Fixed** — Changed to `image_j.get("status", "")`.
