# AGENTS.md

## Project
`te_api` is a Python CLI tool that scans files through the Check Point Threat Emulation (TE)
API. Files are submitted to an on-premises TE appliance and moved to benign/quarantine/error
directories based on the verdict. Supports one-shot mode (process and exit) and watch mode
(continuous directory monitoring). Cross-platform: Linux and Windows.

Current version: **11.2 (alpha)**

Key modules: `te_api.py` (entry point), `te_file_handler.py` (per-file TE flow),
`config_manager.py` (typed config), `logger_config.py` (date-numbered log rotation),
`file_watcher.py` (watchdog-based watch mode),
`tex_results.py` (Threat Extraction/scrub flow), `notification.py` (SMTP batch email),
`zip_archive.py` (password-protected archive), `path_handler.py` (cross-platform paths).

Config is layered: CLI args → env vars (`TE_` prefix) → `config.ini` → built-in defaults.
There are no automated tests in this repo.

## Instructions for the Agent
- At session start: read RECAP and ROADMAP below before doing anything else.
- During the session: update ROADMAP in place — check off completed items, add newly planned
  items with unchecked boxes.
- At session end: append one concise block to RECAP summarising what was done. One line per
  action. If RECAP exceeds ~20 entries, consolidate older entries into a brief paragraph first.
- Keep this file human-readable. Prefer short lines over long prose.
- Update the ## Project section only when a structural change has been completed and verified
  (e.g. a new module added, a config section removed). Do not update it speculatively or
  mid-task. Flag proposed Project section changes to the user for confirmation before writing.

## RECAP
<!-- Session history — newest at the bottom -->
- Rewrote `logger_config.py`: date-numbered log rotation (`te_scanner_YYYY-MM-DD.N.log`), size-triggered rotation at startup/end-of-run/end-of-batch, auto gzip compression of files older than 24h, configurable retention (90 days default), handler swap after rotation
- Renamed `backup_count` → `log_retention_days` in `config_manager.py`, `config.ini`, `config.ini.default`
- Added rotation + cleanup calls to `te_api.py` (end-of-run) and `file_watcher.py` (outer loop, end-of-batch)
- Minor code fixes and added comments to config.ini.default for consistency
- Code review fixes (v11.2): F1.1 (email_skip_tls_verify bool in ini parsing), F1.2 (remove dead watch_* from LOGGING section), F1.3 (remove dead watch_mode from ini parsing), F1.4 (TEX validation), F1.5 (zip_archive_directory default=None), S2 (ssl public API), L6 (consistent empty file list in email), C1 (log rotation index bug), C2 (on_moved dest_path), C3 (threading lock for pending_files), C4 (dead else in _get_today_log_name), C5 (rename _calculate_md5), C6 (unused var), C7 (docstring), C8 (debug log), C9 (json.loads("{}")), L1 (swap handler conditional), L3 (delete dead functions), L4 (pre-loop guard), L5 (Path.name), M1 (shared display_path), M2 (zip manager helper), M3 (win32 import guard)
- Code review round 2 (report.md): Fixed 1 Critical (`config_manager.py` `typing.Set` NameError), 4 Warnings (TLS fallback, unguarded image access, TOCTOU race, CLI toggle missing), 5 Info (comment, indent, docstring, IMAP flags, type annotation style). Added `--no-appliance-skip-tls-verify` flag. W10 and S14 deferred.

## ROADMAP
<!-- Living task list — check off completed items, add new ones as they emerge -->
- [x] Date-numbered log rotation with auto-compression and retention cleanup
- [x] Code review fixes (v11.2): F1.1-F1.5, S2, L6, C1-C9, L1, L3-L6, M1-M3
- [x] claudereport.md fixes: C1 (tex_enabled env var), C2 (zip validation), CC1 (old_info), CC2 (docstring), CC3 (SMTP context), CC4 (dead param), L1 (race condition), L2 (dead sort)
- [x] report.md fixes: F1 (typing.Set NameError), F2 (TLS fallback), F3 (unguarded image_j access), F4 (TOCTOU race), F5 (--no-appliance-skip-tls-verify), F6 (watch_batch_delay comment), F7 (indent), F8 (docstring), F9 (IMAP flags)
- [ ] report.md issues to consider: W10 (`file_watcher.py:205` — `stale_files` grabs unclosed files at max_batch), S14 (`te_file_handler.py:613-630` — separate Malicious/Benign/Error branches)
