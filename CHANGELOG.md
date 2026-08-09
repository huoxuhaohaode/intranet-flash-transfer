# Changelog

## 0.2.3

- Removed the in-app update check button; downloads are handled from GitHub Releases.
- Added UI screenshots to the project homepage.

## 0.2.2

- Added accessibility deep-polish: focus traps, skip links, ARIA labels, live regions and keyboard-friendly dialogs.
- Completed zh/en i18n coverage for admin and visitor flows.
- Integrated GitHub Releases auto-update with signed updater artifacts and per-platform manifests.
- Removed all Electron remnants, sample screenshots and personal identifiers from the package.
- Rebuilt the updater signing pipeline with path remapping so binaries contain no local user paths.

## 0.2.1

- Reworked the controller and visitor interfaces with a clearer technology-focused visual system and restrained motion.
- Added QR-code sharing and retained mobile access as a per-share switch that defaults to off.
- Migrated the desktop runtime and LAN transfer server to Tauri 2 and Rust.
- Added APFS DMG packaging with a verified Applications drag target.
- Added deterministic decimal version increments and duplicate-version packaging protection.
- Added GitHub Actions builds for macOS arm64 DMG and Windows x64 NSIS EXE releases.

## 0.2.0

- Introduced the first Tauri-based macOS package and Rust transfer backend.
