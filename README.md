# OmaSend - Peer-to-Peer AirBridge and Clipboard Sync for Omarchy Linux

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Release v2.0.9](https://img.shields.io/badge/Release-v2.0.9-38BDF8?style=for-the-badge&logo=rust)](https://github.com/ozdil/omarchy-omasend/releases)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

![omasend Preview](preview.png)

> **Direct file transfer and clipboard sync between Omarchy Linux, Android and the browser. Pair once with a QR code; after that everything between your devices is end-to-end encrypted. With an optional anonymous OmaID your own devices also find each other over the internet. No sign-up, no e-mail, no tracking.**

> [!IMPORTANT]
> **Security status:** Devices paired by QR code (`omasend-engine --pair-offer`) use per-device Ed25519 keys and an encrypted, mutually authenticated QUIC/TLS 1.3 transport with BLAKE3-verified, resumable transfers. Devices that are *not* QR-paired still use the legacy HTTP path, which is **not encrypted** — use it only on networks you trust. Incoming transfers from anything other than your own paired devices always need your approval. Protocol details: [PROTOCOL_V2.md](PROTOCOL_V2.md).

- **Author:** Ozan Özdil (ozdil)  
- **License:** MIT  
- **Plugin ID:** `ozdil.omasend`  
- **Version:** `2.0.9`  
- **Default Font:** `JetBrainsMono Nerd Font`

---

## What's new in 2.0.9

The desktop, Android (2.0.9, versionCode 109) and web clients now share one version number.

**New**
- **OmaID, one anonymous number for all your devices.** A 16-digit number in the Mullvad style: no e-mail, no name, no phone number. The number itself is never sent; the registry at `id.omaid.app` only stores an Argon2id-derived id and an end-to-end encrypted, Ed25519-signed device list. A new device joins with the number plus a one-time approval on one of your devices (both show the same 6-digit code), or by scanning a join QR (`https://omaid.app/j#…`). Engine: `--account`, `--account-create`, `--account-join`, `--account-approve`, `--account-invite`, `--account-remove`, `--account-leave`.
- **Your own devices over the internet.** With an OmaID, devices that are not on the same network connect through iroh relays (n0) and switch to a direct connection when the networks allow it. Relays only carry end-to-end encrypted QUIC/TLS 1.3 traffic. A transfer over 4 GiB waits for a direct connection.
- **Shared clipboard, last copy wins.** Copies between your own devices carry their copy time; a copy older than 2 minutes, or older than the newest one already seen, is dropped, so a slow copy never overwrites a newer one. It is silent: no pop-up or sound per copy. On Android there is a Quick Settings tile ("Clipboard").
- **Pair a browser.** The pairing card has a Browser tab (`--pair-offer-web`); the engine serves the web client at `http://<desktop>:53317/web/`. Browsers can send files and text, not receive.
- **Six-digit pairing code.** After QR pairing both devices show the same code, derived from both keys. A wrong or swapped QR code shows two different codes. Also listed in `--devices`.
- **One ink, follows your theme.** Panel, dashboard and launcher icon use the Omarchy theme's foreground (logo option B); the Android app follows the phone's light/dark theme and the web client the browser's. Secondary text keeps WCAG AA contrast on every Omarchy theme.

**Improvements**
- Names from other devices are cleaned of bidi overrides and zero-width characters (`invoice<RLO>fdp.sh` can no longer look like `invoicehs.pdf`).
- Incoming executables and double extensions are flagged as risky files in the transfer request and its notification.
- The public OmaID is no longer used as a credential or key; the engine refuses public client addresses and keeps secrets out of status output.
- Clipboard and Downloads watchers are event driven.

**Bug fixes**
- Phone to PC sends failed with "Permission denied (os error 13)": the core now reads picked files through the open descriptor, and the sandboxed daemon stages outgoing files where it can read them.
- A refused transfer now reports the refusal instead of waiting until it times out.
- Android: "From gallery" pairs with a pairing QR saved as an image; the Quick Settings tile label is no longer cut off; "1 device" instead of "1 devices".

Full list: [CHANGELOG.md](CHANGELOG.md).

---

## Key Features

- **QR pairing & My Devices (protocol v2):**
  - Each device has its own Ed25519 key. Pair two devices once by scanning a QR code (bar panel → QR icon, or `omasend-engine --pair-offer --own`).
  - Paired devices talk over QUIC + TLS 1.3 (iroh) authenticated with those keys; transfers are BLAKE3-verified and resume where they stopped.
  - Devices you pair as **your own** accept transfers automatically and share the clipboard. Devices paired as someone else's always ask first and never receive your clipboard.
  - Paired devices are never silently downgraded to unencrypted HTTP: if the encrypted connection fails you get an error (usually a firewall blocking UDP 53318), not a plaintext transfer.
  - **Nearby** (unpaired) devices still work over the legacy HTTP path with approval on the receiver; that path is not encrypted.
- **Universal Multi-Format Clipboard Vault & WebP Micro-Thumbnails:**
  - Clipboard sync between your own paired devices (text, encrypted). Image clipboard sync is available with legacy code-paired devices.
  - Integrated WebP Micro-Thumbnail Engine: Automatically generates ultra-compact 96x96 WebP thumbnails (3-5 KB) in an isolated sandbox for instant zero-latency preview rendering.
  - Compact Clipboard Vault UI: One-click copy, double-click lightbox modal preview, and instant export to `~/Pictures/OmaStudio_Exports/`.
  - Strict local staging isolation in `~/.local/state/omarchy/omasend/clip_staging/` with atomic mode 0600 file permissions and 50 MiB LRU eviction cap.
- **Omarchy AirBridge P2P & Authentic Samurai Audio Feedback:**
  - Streaming Transfer: Approved transfers stream directly to disk with mode 0600 permissions, a disk-space reservation, and size/checksum verification.
  - Authentic Samurai Soundscape: Integrated high-clarity vocal + katana audio feedback on send (*"OMAKASE!"*) and receive/accept (*"ONEGAI SHIMASU!"*).
  - Hardware-accelerated Wayland LayerShell magnetic drop dock and radial sonar visualization expanding from the bar icon center.
  - Zero-Config Discovery: Automatically discovers neighboring Omarchy Linux desktops and Android devices on the same local network using UDP beacons (port 53317).
  - One switch to turn discovery and receiving on or off.
- **Integrity & Encryption:**
  - Upload size must match the approved request; BLAKE3 / SHA-256 / MD5 checksums are verified when the sender provides them (the desktop engine does; the Android app does not yet).
  - Web portal: the session key is passed inside the URL hash fragment (`#key=...`), which is not sent in HTTP requests (RFC 3986).
  - Encrypted transport for QR-paired devices (QUIC/TLS 1.3 on UDP `53318`). If you use a firewall, allow `53317/tcp`, `53317/udp` and `53318/udp` on your local network.
- **Multi-Platform Ecosystem:**
  - **Linux Desktop Plugin:** Native Quickshell QML widget and hardened Rust daemon (`omasend-engine`).
  - **Android Native App:** Kotlin & Jetpack Compose app with CameraX zero-GMS QR/Barcode scanner and tactile haptic feedback ([ozdil/omasend-android](https://github.com/ozdil/omasend-android)).
  - **Web Client:** Zero-install browser client served by the engine at `/web/`; pairs by QR and sends files and text (send-only, plain HTTP on the LAN) ([ozdil/omasend-web](https://github.com/ozdil/omasend-web)).
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

### Step 3: Pair your devices
1. Open the OmaSend panel in the bar and click the QR icon (or press `p`). Choose **My device** for your own phone or laptop.
2. On Android: OmaSend → **Pair a device** → **Scan QR code**. Between two desktops: `omasend-engine --pair-with '<link>'`, or the screen-scan button in the pairing card.
3. The device appears under **My devices**. Drop files on the bar icon, click a device to pick files, right-click to send the clipboard.

Command line: `--pair-offer [--own] [--json]`, `--pair-offer-web [--own]`, `--pair-with <link>`, `--devices`, `--unpair <device-id>`, `--send <device-id|ip|auto> <file>...`.

**Browser client (send-only):** any phone or computer with a browser can send files and clipboard text to this desktop without installing an app. `./build.sh` builds it from an `omasend-web` checkout next to this one (needs `npm`), and the engine serves it at `http://<desktop-ip>:53317/web/`. Run `omasend-engine --pair-offer-web` and scan the QR code with the phone's camera: the page opens and pairs itself. A browser cannot receive files. Its requests are signed with its own key but travel over plain HTTP on the LAN (authenticated, **not encrypted**), so use it on networks you trust; see [PROTOCOL_V2.md](PROTOCOL_V2.md#browser-client).

### Step 4: Top Bar Placement (Optional)
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
- **Web Client:** [ozdil/omasend-web](https://github.com/ozdil/omasend-web)
- **Google Play Closed Beta:** [Join Google Group](https://groups.google.com/g/omasend-testers) & [Opt-in on Google Play](https://play.google.com/apps/testing/io.omarchy.omasend)

---

## Security & Privacy Policy

OmaSend does not collect telemetry, track users, or store data on central servers. Files and clipboard contents travel directly between your devices. Traffic between QR-paired devices is end-to-end encrypted and authenticated; traffic with unpaired devices is not, so use that only on trusted networks. Security issues can be reported via GitHub.

For detailed security policies, review [PRIVACY_POLICY.md](PRIVACY_POLICY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
