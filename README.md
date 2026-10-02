# OmaSend - Zero-Knowledge AirBridge and E2EE Transfer for Omarchy Linux

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Release v1.7.0](https://img.shields.io/badge/Release-v1.7.0-38BDF8?style=for-the-badge&logo=rust)](https://github.com/ozdil/omarchy-omasend/releases)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

![omasend Preview](preview.png)

> **Cross-device sovereign file transfer, encrypted clipboard vault, 16-digit Luhn OmaID pairing, and global WAN portal with Zero-Knowledge AES-256-GCM encryption for Omarchy Linux, Android, and Modern Web Browsers.**

- **Author:** Ozan Özdil (ozdil)  
- **License:** MIT  
- **Plugin ID:** `ozdil.omasend`  
- **Version:** `1.7.0`  
- **Default Font:** `JetBrainsMono Nerd Font`

---

## Key Features

- **16-Digit Luhn Mod 10 OmaID Pairing & Blinded Rendezvous:**
  - Zero-account, zero-server device pairing using RFC 2104 HMAC-SHA256 Blinded Rendezvous topics and RFC 5869 HKDF-SHA256 symmetric key derivation.
  - Generates verifiable 16-digit device identifiers with Luhn mod 10 checksum validation (`XXXX-XXXX-XXXX-XXXX`).
  - Strict zero-trust connection filter: Unpaired devices are rejected before staging data.
- **Universal Multi-Format Clipboard Vault & WebP Micro-Thumbnails:**
  - Real-time bidirectional clipboard sync supporting text and image payloads (PNG, JPEG, WebP).
  - Integrated WebP Micro-Thumbnail Engine: Automatically generates ultra-compact 96x96 WebP thumbnails (3-5 KB) in an isolated sandbox for instant zero-latency preview rendering.
  - Compact Clipboard Vault UI: One-click copy, double-click lightbox modal preview, and instant export to `~/Pictures/OmaStudio_Exports/`.
  - Strict local staging isolation in `~/.local/state/omarchy/omasend/clip_staging/` with atomic mode 0600 file permissions and 50 MiB LRU eviction cap.
- **Omarchy AirBridge P2P (PC-to-PC, Android, and Web Direct Transfer):**
  - Instant Zero-Click Transfer: Transfers from paired/trusted devices are auto-accepted instantly without manual prompt friction, streaming directly to disk with mode 0600 security.
  - Hardware-accelerated radial sonar radar visualization expanding from the bar icon center.
  - Zero-Config Discovery: Automatically discovers neighboring Omarchy Linux desktops and Android devices on the same local network using UDP beacons (port 53317).
  - 3-Tier Visibility Control: Off, Known (Trusted Peers Only - Default), and Everyone (10 Minutes Temporary Discovery).
- **Zero-Knowledge End-to-End Encryption (E2EE):**
  - Hardware-accelerated AES-256-GCM encryption with BLAKE3 cryptographic integrity checksums.
  - Session key is passed strictly inside the URL hash fragment (`#key=...`), which never reaches HTTP request headers or server logs (RFC 3986).
- **Multi-Platform Ecosystem:**
  - **Linux Desktop Plugin:** Native Quickshell QML widget and hardened Rust daemon (`omasend-engine`).
  - **Android Native App:** Kotlin & Jetpack Compose app with CameraX zero-GMS QR/Barcode scanner and tactile haptic feedback ([ozdil/omasend-android](https://github.com/ozdil/omasend-android)).
  - **Web PWA Client:** Zero-install web client with Web Crypto API and offline service worker caching ([ozdil/omasend-web](https://github.com/ozdil/omasend-web)).
- **Hardened HANCORE Rust Engine:**
  - Compliant with Omarchy Linux Security Standards: isolated process groups (`process_group(0)`), monotonic execution deadlines, atomic temporary file operations (mode 0600), `prctl(PR_SET_DUMPABLE, 0)`, and RAM zeroization (`Zeroize`).

---

## Requirements

- `cargo` and `rustc` (Rust toolchain, for building the native engine)
- `quickshell` (Omarchy desktop panel runtime)
- `wl-clipboard` (provides `wl-copy` and `wl-paste` on Wayland)
- `libnotify` (desktop notifications via `notify-send`)
- `zenity` (GTK file selection dialog)
- `cloudflared` (optional, required for Global WAN Tunnel mode)

---

## Installation and Setup

### Step 1: Add the Plugin to Omarchy
```bash
omarchy plugin add https://github.com/ozdil/omarchy-omasend.git
```

### Step 2: Build the Native Engine
Navigate to the plugin directory and run the automated build script:
```bash
cd ~/.config/omarchy/plugins/ozdil.omasend && ./build.sh
```
This script compiles the engine using `cargo build --release --locked`, installs the binary (`omasend-engine`) with mode 0755 permissions, verifies cryptographic provenance, and restarts the Omarchy shell automatically.

### Step 3: Top Bar Placement (Optional)
If not automatically present in your panel, add `ozdil.omasend` to `bar.layout.right` in `~/.config/omarchy/shell.json`:
```json
{
  "id": "ozdil.omasend"
}
```
Then reload the shell:
```bash
omarchy-restart-shell
```

---

## Multi-Platform Ecosystem Links

- **Android Companion App:** [ozdil/omasend-android](https://github.com/ozdil/omasend-android)
- **Web PWA Client:** [ozdil/omasend-web](https://github.com/ozdil/omasend-web)
- **Google Play Closed Beta:** [Join Google Group](https://groups.google.com/g/omasend-testers) & [Opt-in on Google Play](https://play.google.com/apps/testing/io.omarchy.omasend)

---

## Security & Privacy Policy

OmaSend operates with a strict **Zero-Trust, Zero-Knowledge** architecture. It does not collect telemetry, track users, or transmit data through centralized intermediary servers. All communications are direct peer-to-peer or end-to-end encrypted with authenticated ephemeral keys.

For detailed security policies, review [PRIVACY_POLICY.md](PRIVACY_POLICY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
