# AGENTS.md

## Project
`te_api` is a Python CLI tool that scans files through the Check Point Threat Emulation (TE)
API. Files are submitted to an on-premises TE appliance and moved to benign/quarantine/error
directories based on the verdict. Supports one-shot mode (process and exit) and watch mode
(continuous directory monitoring). Cross-platform: Linux and Windows.

Current version: **11.1 (alpha)**

Key modules: `te_api.py` (entry point), `te_file_handler.py` (per-file TE flow),
`config_manager.py` (typed config), `file_watcher.py` (watchdog-based watch mode),
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
- Fixed `_process_tex_results()` missing `config` param (te_file_handler.py), IMAP indent error (notification.py), watch_batch_delay validation rejecting 0 (config_manager.py), 23 dead f-strings/imports auto-fixed, all 11 files formatted with ruff, config.ini.default cross-referenced with code usage
- Minor code fixes and added comments to config.ini.default for consistency

## ROADMAP
<!-- Living task list — check off completed items, add new ones as they emerge -->
- [ ]
