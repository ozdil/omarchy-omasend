# 🚀 OmaSend • Zero-Knowledge AirBridge & E2EE Transfer for Omarchy Linux

> **Cross-device file transfer, encrypted clipboard bridge, and global WAN portal with Zero-Knowledge AES-256-GCM encryption for Omarchy Linux.**

Author: **Ozan Özdil (ozdil)**  
License: **MIT**  
Plugin ID: `ozdil.omasend`

---

## ✨ Features

- 🔒 **Zero-Knowledge End-to-End Encryption (E2EE):**
  - Uses hardware-accelerated **AES-256-GCM** encryption via the browser's native **Web Crypto API** (`crypto.subtle`).
  - Cryptographic session key is passed strictly inside the URL hash fragment (`#key=...`), which **never leaves the device's browser memory or reaches HTTP request headers** (`RFC 3986`).
  - Neither local Wi-Fi eavesdroppers nor intermediate WAN relay servers can inspect or decrypt transferred files or clipboard data.
- 🌐 **Hybrid Network Modes (LAN & Global WAN):**
  - **🏠 Yerel Ağ (LAN):** Full-speed local transfer (300–800 Mbps) over local Wi-Fi.
  - **🌐 Dış Ağ (Global WAN Tunnel):** One-click global HTTPS tunnel (Cloudflare Quick Tunnel / SSH). Transfer files directly over cellular 4G/5G or separate Wi-Fi networks worldwide without port forwarding or public IP requirements.
- 📡 **Omarchy AirDrop P2P & Bluetooth (PC-to-PC):**
  - Instant zero-config peer discovery across nearby Omarchy desktops using UDP multicast beacons (`8845`) and Bluetooth (BLE).
  - 3-tier AirDrop visibility controls: *Off*, *Known Peers Only (Default)*, and *Everyone for 10 Minutes*.
  - **Gatekeeper Consent:** Zero silent file acceptance. Recipient gets an explicit interactive desktop alert and panel prompt with sender name, file list, and total size before any bytes are accepted.
  - Universal bidirectional clipboard synchronization between Omarchy desktops.
- 📱 **Zero-Install Mobile Portal:** Point your smartphone camera at the native panel QR code to open the encrypted web portal in Safari or Chrome. No apps required on mobile!
- 🔑 **PIN & Session Security:** Generates dynamic 4-digit PINs and 256-bit cryptographic keys with one-click regeneration.
- 🔄 **Bidirectional File Transfers:**
  - **Mobile ➔ PC:** Send photos, 4K videos, documents, and archives directly into `~/Downloads/omasend/`.
  - **PC ➔ Mobile:** Place files into `~/Downloads/omasend/shared/` to make them instantly downloadable with in-memory browser decryption.
- 📋 **Live Encrypted Clipboard Sync:** Instant, encrypted clipboard synchronization between mobile browsers and Linux Wayland desktop (`wl-copy` / `wl-paste`).
- 🔔 **Native Wayland Notifications:** Desktop alerts via `notify-send` when incoming encrypted transfers or clipboard syncs arrive.
- 🎨 **100% Native Omarchy Design:** Zero hardcoded colors; dynamically inherits the active Omarchy theme (`Color.popups.*`, `Color.accent`, `Style.selectedFillFor`).
- ⚡ **Native Rust Engine:** High-performance multi-threaded daemon (`omasend-engine`) with streaming `Content-Length` reader for multi-gigabyte transfers without memory exhaustion.

---

## 📋 Requirements

- `qrencode` (for generating SVG QR codes)
- `wl-clipboard` (provides `wl-copy` and `wl-paste` on Wayland)
- `libnotify` (provides `notify-send` for desktop alerts)
- `cargo` (Rust toolchain, for building from source)

### WAN Tunnel Client (Optional, for Global WAN Tunnel mode)
For transferring files outside local Wi-Fi across the internet, OmaSend uses the official trusted system package `cloudflared`:
```bash
sudo pacman -S cloudflared
```
*Note: OmaSend strictly resolves and executes pre-installed immutable binaries from trusted system paths (`/usr/bin/cloudflared`, `/usr/local/bin/cloudflared`, `~/.local/bin/cloudflared`) and never downloads or executes mutable packages at runtime.*

---

## 🚀 Installation & Setup

### Install via Omarchy Marketplace
```bash
omarchy plugin add ozdil.omasend
```

### Or Build from Source
```bash
cargo build --release --locked
```

### Configuration
Add `ozdil.omasend` to `bar.layout.right` in `~/.config/omarchy/shell.json`:
```json
{
  "id": "ozdil.omasend"
}
```

Then restart the shell:
```bash
omarchy-restart-shell
```

---

## 📖 Usage

1. Click the paper plane icon (``) in the Omarchy top bar to summon the OmaSend panel.
2. Select your preferred network mode:
   - **🏠 Yerel Ağ (LAN):** For devices on the same Wi-Fi.
   - **🌐 Dış Ağ (WAN):** For devices on cellular data (4G/5G) or outside networks.
3. Scan the QR code with your mobile device. The portal automatically pairs with the 4-digit PIN and imports the AES-256-GCM encryption key.
4. Drag and drop files to upload, or use the clipboard box to send text directly to your Linux desktop clipboard!
