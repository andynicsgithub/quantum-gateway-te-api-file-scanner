# Branch Information

**Last Updated:** February 13, 2026

---

## Repository Structure

This repository uses a branch-based development workflow to ensure users always have access to stable, tested code.

### Branches

#### `main` - Stable Release Branch
- **Current Version:** v6.3.6
- **Status:** ✅ Stable, Production-Ready
- **Purpose:** Default branch for users who want tested, working code
- **Last Update:** February 11, 2026

**Use this branch if:**
- You want to use the TE API Scanner in production
- You need a stable, tested version
- You're deploying to end users

**Clone command:**
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
# Automatically uses main branch
```

---

#### `v7.0-dev` - Development Branch (Phase 1)
- **Current Version:** v7.0 Phase 1
- **Status:** 🚧 In Development/Testing
- **Purpose:** Cross-platform refactoring (Windows + Linux + SMB support)
- **Last Update:** February 13, 2026

**Features in v7.0-dev:**
- ✅ Cross-platform support (Windows & Linux)
- ✅ Windows UNC path support (`\\server\share`)
- ✅ Linux SMB mount support (`/mnt/share`)
- ✅ Robust file movement with retry logic
- ✅ Configuration management system
- ✅ Network path handling with checksums
- ⏳ Windows testing in progress
- ⏳ TE appliance integration testing

**Use this branch if:**
- You're testing the new v7.0 features
- You need Windows or SMB/UNC support
- You're contributing to development
- You want to help test before release

**Clone command:**
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
git checkout v7.0-dev
```

---

## Why Separate Branches?

### Problem
When v7.0 development started, commits were initially made to `main`. This meant anyone cloning the repository would get incomplete, untested code.

### Solution
On February 13, 2026, we reorganized:
1. Created `v7.0-dev` branch with all Phase 1 work
2. Reset `main` back to v6.3.6 (last stable release)
3. Users now get stable code by default
4. Developers can access v7.0 by switching branches

---

## Development Workflow

```
main (v6.3.6 - stable)
  │
  └─→ v7.0-dev (Phase 1 work)
       │
       ├─ Phase 1: Cross-platform support ✅ (code complete)
       ├─ Phase 1: Linux testing ✅ (complete)
       ├─ Phase 1: Windows testing ⏳ (in progress)
       │
       └─→ (After testing complete)
            └─ Merge to main as v7.0 release
            └─ Create v8.0-dev for Phase 2 (watch mode)
```

---

## Roadmap

### Current Phase: v7.0 Phase 1 Testing
- **Branch:** `v7.0-dev`
- **Status:** Code complete, testing in progress
- **ETA:** Depends on testing results

**Remaining Tasks:**
- [ ] Windows platform testing
- [ ] TE appliance integration testing
- [ ] Bug fixes (if any issues found)
- [ ] Merge to `main` as v7.0 release
- [ ] Tag v7.0 release

### Future: Phase 2 - Watch Mode
- **Branch:** TBD (likely `v7.1-dev` or `watch-mode-dev`)
- **Features:**
  - File system monitoring with `watchdog`
  - `--watch` flag implementation
  - Event-driven file processing
  - Windows service support
- **Status:** Not started (waiting for Phase 1 completion)

### Future: Phase 3 - Windows Service
- **Features:**
  - Windows service wrapper
  - Service installer/uninstaller
  - Windows Event Log integration
  - Auto-start configuration
- **Status:** Planned

---

## For Users

### I just want the stable version
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
# You're on main branch (v6.3.6) - ready to use
```

### I want to test the new v7.0 features
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
git checkout v7.0-dev
# Follow WINDOWS_TESTING_GUIDE.md or PHASE1_COMPLETE.md
```

### I want to contribute
1. Fork the repository
2. Clone your fork
3. Checkout `v7.0-dev` branch
4. Create feature branch: `git checkout -b feature/your-feature`
5. Make changes and test
6. Submit pull request to `v7.0-dev` branch

---

## Branch History

### February 11, 2026
- Phase 1 implementation completed
- Initial commits made to `main` branch
- Linux testing completed

### February 13, 2026
- Repository reorganized for safety
- `v7.0-dev` branch created with Phase 1 work
- `main` branch reset to v6.3.6
- Documentation updated to reflect branch structure

---

## Questions?

- **For stable version issues:** Open issue against `main` branch
- **For v7.0 development/testing:** Open issue against `v7.0-dev` branch
- **For general questions:** Check README.md or create a discussion

---

## Quick Reference

| Branch | Version | Status | Purpose |
|--------|---------|--------|---------|
| `main` | v6.3.6 | ✅ Stable | Production use |
| `v7.0-dev` | v7.0 Phase 1 | 🚧 Testing | Development/Testing |

**Default clone gets:** `main` (stable v6.3.6)  
**To get v7.0:** `git checkout v7.0-dev` after cloning
