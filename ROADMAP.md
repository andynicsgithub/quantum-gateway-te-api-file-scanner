# ROADMAP

<!-- Living task list — check off completed items, add new ones as they emerge -->
- [x] Date-numbered log rotation with auto-compression and retention cleanup
- [x] Code review fixes (v11.2): F1.1-F1.5, S2, L6, C1-C9, L1, L3-L6, M1-M3
- [x] claudereport.md fixes: C1 (tex_enabled env var), C2 (zip validation), CC1 (old_info), CC2 (docstring), CC3 (SMTP context), CC4 (dead param), L1 (race condition), L2 (dead sort)
- [x] report.md fixes: F1 (typing.Set NameError), F2 (TLS fallback), F3 (unguarded image_j access), F4 (TOCTOU race), F5 (--no-appliance-skip-tls-verify), F6 (watch_batch_delay comment), F7 (indent), F8 (docstring), F9 (IMAP flags)
- [x] report.md W10 fixed (`file_watcher.py:205` — `stale_files` grabs unclosed files at max_batch)
- [x] S14 (`te_file_handler.py:610–630` — verdict branch duplication): documented as deliberate decision, left as-is
- [ ] Review zip file logic — duplicate entries (`/jail/...` vs `jail/...`), `verdict_basename` empty warnings on benign files, consolidation path normalization

