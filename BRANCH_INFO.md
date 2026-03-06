# Branch Information

**Last Updated:** March 6, 2026

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

#### `7.0` - Stable Release Branch (v7.0)
- **Current Version:** v7.0
- **Status:** ✅ Stable, Production-Ready
- **Purpose:** Cross-platform refactoring (Windows + Linux + SMB support)
- **Last Update:** March 6, 2026

**Features in v7.0:**
- ✅ Cross-platform support (Windows & Linux)
- ✅ Windows UNC path support (`\\server\share`)
- ✅ Linux SMB mount support (`/mnt/share`)
- ✅ Robust file movement with retry logic
- ✅ Configuration management system
- ✅ Network path handling with checksums
- ✅ Windows testing completed
- ✅ TE appliance integration testing completed

**Use this branch if:**
- You want to use the v7.0 stable release
- You need Windows or SMB/UNC support
- You're using v7.0 in production

**Clone command:**
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
git checkout 7.0
```

---

#### `v7.01` - Development Branch (v7.01)
- **Current Version:** v7.01
- **Status:** 🚧 In Development/Testing
- **Purpose:** Latest development changes building on v7.0
- **Last Update:** March 6, 2026

**Features in v7.01:**
- ✅ All v7.0 features included
- 🔄 Additional enhancements and fixes
- ⏳ Testing in progress

**Use this branch if:**
- You're testing the latest v7.01 features
- You want the most recent development changes
- You're contributing to ongoing development

**Clone command:**
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
git checkout v7.01
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

On March 6, 2026, we completed the v7.0 release:
1. `v7.0-dev` renamed to `7.0` (stable release)
2. All testing completed successfully
3. Created `v7.01` for continued development
4. Updated documentation to reflect new structure

---

## Development Workflow

```
main (v6.3.6 - stable)
  │
  ├─→ 7.0 (v7.0 stable - renamed from v7.0-dev)
  │    │
  │    ├─ Phase 1: Cross-platform support ✅
  │    ├─ Phase 1: Linux testing ✅
  │    ├─ Phase 1: Windows testing ✅
  │    └─ Status: Stable Release
  │
  └─→ v7.01 (Development branch - latest changes)
       │
       ├─ Based on 7.0 stable
       ├─ Additional enhancements 🔄
       └─ Status: In Development
```

---

## Roadmap

### v7.0 - Released ✅
- **Branch:** `7.0` (renamed from `v7.0-dev`)
- **Status:** ✅ Released - Stable
- **Released:** March 6, 2026

**Completed Tasks:**
- [x] Windows platform testing
- [x] TE appliance integration testing
- [x] Bug fixes and stabilization
- [x] Renamed from `v7.0-dev` to `7.0`

### Current Phase: v7.01 Development
- **Branch:** `v7.01`
- **Status:** 🚧 In Development
- **Started:** March 6, 2026

**Current Work:**
- [ ] Additional enhancements on top of v7.0
- [ ] Testing and validation
- [ ] Bug fixes

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

### I want to use v7.0 stable
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
git checkout 7.0
# Ready to use v7.0 stable release
```

### I want to test the latest v7.01 development features
```bash
git clone https://github.com/andynicsgithub/quantum-gateway-te-api-file-scanner.git
cd quantum-gateway-te-api-file-scanner
git checkout v7.01
# Follow WINDOWS_TESTING_GUIDE.md or PHASE1_COMPLETE.md
```

### I want to contribute
1. Fork the repository
2. Clone your fork
3. Checkout `v7.01` branch (latest development)
4. Create feature branch: `git checkout -b feature/your-feature`
5. Make changes and test
6. Submit pull request to `v7.01` branch

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

### March 6, 2026
- `v7.0-dev` renamed to `7.0` - stable release
- v7.0 testing completed and released
- `v7.01` branch created for continued development
- BRANCH_INFO.md updated with new structure

---

## Questions?

- **For v6.3.6 stable issues:** Open issue against `main` branch
- **For v7.0 stable issues:** Open issue against `7.0` branch
- **For v7.01 development/testing:** Open issue against `v7.01` branch
- **For general questions:** Check README.md or create a discussion

---

## Quick Reference

| Branch | Version | Status | Purpose |
|--------|---------|--------|---------|
| `main` | v6.3.6 | ✅ Stable | Production use |
| `7.0` | v7.0 | ✅ Stable | v7.0 Release |
| `v7.01` | v7.01 | 🚧 Development | Latest changes |

**Default clone gets:** `main` (stable v6.3.6)  
**To get v7.0 stable:** `git checkout 7.0` after cloning  
**To get v7.01 development:** `git checkout v7.01` after cloning
