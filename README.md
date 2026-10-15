# OmaSend - Peer-to-Peer AirBridge and Clipboard Sync for Omarchy Linux

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Release v1.9.1](https://img.shields.io/badge/Release-v1.9.1-38BDF8?style=for-the-badge&logo=rust)](https://github.com/ozdil/omarchy-omasend/releases)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

![omasend Preview](preview.png)

> **Direct peer-to-peer file transfer and clipboard sync between Omarchy Linux, Android, and modern web browsers, with an anonymous numbered identity (OmaID) and no accounts or cloud servers.**

> [!IMPORTANT]
> **Security status (v1.9.1):** Local network transfers are size- and (where provided) checksum-verified but are **not yet end-to-end encrypted or cryptographically authenticated**. Use OmaSend on networks you trust. Every incoming transfer requires your approval, and clipboard sync only works with explicitly paired devices. Per-device keys, QR pairing, and authenticated encryption are on the roadmap.

- **Author:** Ozan Özdil (ozdil)  
- **License:** MIT  
- **Plugin ID:** `ozdil.omasend`  
- **Version:** `1.9.1`  
- **Default Font:** `JetBrainsMono Nerd Font`

---

## Key Features

- **Anonymous Numbered Identity (Zero-Log OmaID) & My Devices:**
  - Free and open-source 16-digit Luhn mod-10 numbered identity (`XXXX-XXXX-XXXX-XXXX`) requiring zero registration, email, username, or personal data.
  - Enter the same 16-digit OmaID on your PC and Android phone (`--set-oma-id <OMAID>` or via UI) to group them under **My Devices** in the UI.
  - OmaID is an identifier, not a secret: it is visible on the local network. It therefore does **not** grant trust on its own. Every incoming transfer goes through Gatekeeper approval (`ACCEPT` / `REJECT`), and clipboard sync requires code-verified pairing. Zero-click transfers between your own devices will return once per-device cryptographic keys land.
- **Universal Multi-Format Clipboard Vault & WebP Micro-Thumbnails:**
  - Real-time bidirectional clipboard sync supporting text and image payloads (PNG, JPEG, WebP).
  - Integrated WebP Micro-Thumbnail Engine: Automatically generates ultra-compact 96x96 WebP thumbnails (3-5 KB) in an isolated sandbox for instant zero-latency preview rendering.
  - Compact Clipboard Vault UI: One-click copy, double-click lightbox modal preview, and instant export to `~/Pictures/OmaStudio_Exports/`.
  - Strict local staging isolation in `~/.local/state/omarchy/omasend/clip_staging/` with atomic mode 0600 file permissions and 50 MiB LRU eviction cap.
- **Omarchy AirBridge P2P & Authentic Samurai Audio Feedback:**
  - Streaming Transfer: Approved transfers stream directly to disk with mode 0600 permissions, a disk-space reservation, and size/checksum verification.
  - Authentic Samurai Soundscape: Integrated high-clarity vocal + katana audio feedback on send (*"OMAKASE!"*) and receive/accept (*"ONEGAI SHIMASU!"*).
  - Hardware-accelerated Wayland LayerShell magnetic drop dock and radial sonar visualization expanding from the bar icon center.
  - Zero-Config Discovery: Automatically discovers neighboring Omarchy Linux desktops and Android devices on the same local network using UDP beacons (port 53317).
  - 3-Tier Visibility Control: Off, Known (Trusted Peers Only - Default), and Everyone (10 Minutes Temporary Discovery).
- **Integrity & Encryption:**
  - Upload size must match the approved request; BLAKE3 / SHA-256 / MD5 checksums are verified when the sender provides them (the desktop engine does; the Android app does not yet).
  - Web portal: the session key is passed inside the URL hash fragment (`#key=...`), which is not sent in HTTP requests (RFC 3986).
  - Not yet available: end-to-end encryption and cryptographic peer authentication for LAN/P2P traffic (see the security status note above).
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

OmaSend does not collect telemetry, track users, or store data on central servers. Files and clipboard contents travel directly between your devices. LAN/P2P traffic is currently not end-to-end encrypted or cryptographically authenticated, so use it on trusted networks; every incoming transfer requires your approval. Security issues can be reported via GitHub.

For detailed security policies, review [PRIVACY_POLICY.md](PRIVACY_POLICY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
