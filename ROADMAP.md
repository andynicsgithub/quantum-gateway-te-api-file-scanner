# ROADMAP

<!-- Living task list — check off completed items, add new ones as they emerge -->
- [x] Date-numbered log rotation with auto-compression and retention cleanup
- [x] Code review fixes (v11.2): F1.1-F1.5, S2, L6, C1-C9, L1, L3-L6, M1-M3
- [x] claudereport.md fixes: C1 (tex_enabled env var), C2 (zip validation), CC1 (old_info), CC2 (docstring), CC3 (SMTP context), CC4 (dead param), L1 (race condition), L2 (dead sort)
- [x] report.md fixes: F1 (typing.Set NameError), F2 (TLS fallback), F3 (unguarded image_j access), F4 (TOCTOU race), F5 (--no-appliance-skip-tls-verify), F6 (watch_batch_delay comment), F7 (indent), F8 (docstring), F9 (IMAP flags)
- [x] report.md W10 fixed (`file_watcher.py:205` — `stale_files` grabs unclosed files at max_batch)
- [x] S14 (`te_file_handler.py:610–630` — verdict branch duplication): documented as deliberate decision, left as-is
- [x] Review zip file logic — duplicate entries (`/jail/...` vs `jail/...`), `verdict_basename` empty warnings on benign files, consolidation path normalization (see `ziplogic.md` for full details)
- [x] v11.2 code review follow-up:
  - [x] 1.1 `config_manager.py`: `email_imap_skip_tls_verify` already in `_bool_fields`; wired into `notification.py` IMAP connection with Python 3.11+ ssl_context support
  - [x] 1.3 `config_manager.py:289`: documented intentional difference between DEFAULT section parsing and other sections
  - [x] 2.1 `te_api.py:25-29`: replaced global `warnings.filterwarnings` with `urllib3.disable_warnings()`
  - [x] 2.2 `path_handler.py:246`: fixed `self.logger` → `logger` in static method
  - [x] 2.3 `zip_archive.py:207`: added module-level logger, fixed `self.logger` → `logger` in static method
  - [x] 2.4 `te_api.py:264`: added comment documenting port 18194
  - [x] 3.1 same as 2.2 (path_handler.py) — resolved
  - [x] 3.2 `file_watcher.py:353-360`: moved initializations inside try block, use loop variable in except
  - [x] 3.3 `config_manager.py:564-575`: `email_imap_skip_tls_verify` already in `_bool_fields` — wiring confirmed
  - [x] 4.1 `te_file_handler.py:631-658`: added `elif verdict == "Unknown"` branch moving to error_directory
  - [x] 4.2 `file_watcher.py:143-171`: added NOTE comment documenting `on_closed` is dead code
  - [x] 4.3 `te_api.py:503-505`: added comment documenting Python 3.9+ Path pickling support
  - [x] 5.2 `te_api.py:368-374`: replaced raw stream writes with `logger.info("++++++++++")`
  - [x] 5.4 `te_file_handler.py:22-33`: updated class docstring with TEX processing step
  - [x] 5.5 `config_manager.py:494-501`: added `email_smtp_port` and `email_imap_port` to `_int_cli_keys`
  - [x] Left as-is per review: 1.2 (email_subject_template default), 4.4 (TEX redundant checks), 5.1 (handle_file() refactoring)

