# OmaSend - Zero-Knowledge AirBridge and E2EE Transfer for Omarchy Linux

Cross-device file transfer, encrypted clipboard bridge, Omarchy AirDrop P2P, and global WAN portal with Zero-Knowledge AES-256-GCM encryption for Omarchy Linux.

Author: Ozan Ozdil (ozdil)  
License: MIT  
Plugin ID: ozdil.omasend

---

## Features

- Omarchy AirDrop P2P (PC-to-PC Direct Transfer):
  - Zero-Config Discovery: Automatically discovers neighboring Omarchy Linux desktops on the same local network using UDP beacons (port 8845) and Bluetooth (BLE).
  - 3-Tier Visibility Control: Off, Known (Trusted Peers Only - Default), and Everyone (10 Minutes Temporary Discovery).
  - Gatekeeper Consent: No files are accepted silently. Recipient receives an interactive desktop notification and panel prompt with sender name, file list, and total transfer size. Transfer begins only after explicit approval.
  - Universal Clipboard Sync: Bidirectional encrypted Wayland clipboard synchronization between Omarchy desktops with a single click.
- Zero-Knowledge End-to-End Encryption (E2EE):
  - Hardware-accelerated AES-256-GCM encryption via the native Web Crypto API (crypto.subtle).
  - Cryptographic session key is passed strictly inside the URL hash fragment (#key=...), which never reaches HTTP request headers or server logs (RFC 3986).
- Zero-Install Mobile Portal:
  - Scan the QR code with any smartphone camera to open the encrypted web portal in Safari or Chrome. No apps required on mobile devices.
  - Send photos, videos, and documents directly to your desktop.
- Hybrid Network Modes (LAN and Global WAN):
  - Local Area Network (LAN): Full-speed transfer (300-800 Mbps) over local Wi-Fi.
  - Wide Area Network (Global WAN Tunnel): Secure HTTPS tunnel using cloudflared without requiring router port forwarding or static IP.
- Hardened Rust Engine:
  - Compliant with Omarchy Linux Security Standards (AGENTS.md): isolated process groups, monotonic execution deadlines, atomic file operations (mode 0600), and buffer overrun protection.

---

## Requirements

- cargo and rustc (Rust toolchain, for building the native engine)
- qrencode (for generating QR codes in SVG format)
- wl-clipboard (provides wl-copy and wl-paste on Wayland)
- libnotify (desktop notifications via notify-send)
- zenity (GTK file selection dialog)
- cloudflared (optional, required for Global WAN Tunnel mode):
  ```bash
  sudo pacman -S cloudflared
  ```

---

## Installation and Setup

### Why Building from Source is Required
Under the Omarchy Linux Security Standards (AGENTS.md Rule 5.3), precompiled binaries are strictly forbidden from Git repositories to guarantee user system integrity. Therefore, the native engine must be compiled from source on your local machine after adding the plugin.

### Step 1: Add the Plugin to Omarchy
```bash
omarchy plugin add https://github.com/ozdil/omarchy-omasend.git
```

### Step 2: Build the Native Engine
Navigate to the plugin directory and run the automated build script:
```bash
cd ~/.config/omarchy/plugins/ozdil.omasend && ./build.sh
```
This script compiles the engine using `cargo build --release --locked`, installs the binary (`omasend-engine`) with proper permissions, and restarts the Omarchy shell automatically.

### Step 3: Configure Firewall (UFW)
To allow discovery and transfer between Omarchy machines on your local subnet (adjust the subnet to match your network, e.g., `192.168.1.0/24`):
```bash
# TCP 8844: File transfer and encrypted HTTP portal
sudo ufw allow from 192.168.1.0/24 to any port 8844 proto tcp

# UDP 8845: AirBridge P2P peer discovery beacons
sudo ufw allow from 192.168.1.0/24 to any port 8845 proto udp
```

### Step 4: Add to Top Bar (Optional)
If not automatically present in your panel, add `ozdil.omasend` to `bar.layout.right` in `~/.config/omarchy/shell.json`:
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

## How It Works and Usage Guide

Click the paper plane icon in the Omarchy top bar to open the OmaSend panel.

### 1. Omarchy AirDrop P2P (PC-to-PC Sharing)
- Device Discovery: Computers running OmaSend on the same local network automatically appear under "AIRBRIDGE DISCOVERED DEVICES" with their hostname and IP.
- Visibility Modes:
  - KNOWN PEERS ONLY (Default): Only previously paired devices can see you.
  - EVERYONE (10M): Temporarily visible to all nearby devices for 10 minutes.
- Sending Files: Click the "SEND" button next to any discovered peer to open the file picker. Selected files will be transmitted directly.
- Syncing Clipboard: Click the "CLIPBOARD" button to instantly sync your current Wayland desktop clipboard to the target computer.
- Recipient Consent: Incoming transfers show an interactive prompt with sender information and file details. Approved transfers are downloaded directly to `~/Downloads/omasend/`.

### 2. Mobile to PC Transfer (Web Portal)
1. Open the OmaSend panel and select LAN mode.
2. Scan the displayed QR code with your smartphone camera.
3. The portal automatically pairs with the 4-digit PIN and loads the AES-256 encryption key.
4. Upload files directly from your mobile browser into `~/Downloads/omasend/`.
5. Files placed in `~/Downloads/omasend/shared/` on your PC can be downloaded from the mobile portal.
6. Use the clipboard box to send text between mobile and PC in real time.

### 3. Global WAN Tunnel
- When devices are on different networks or cellular data, switch to "WAN" mode in the panel.
- OmaSend initiates an end-to-end encrypted HTTPS tunnel through cloudflared.
- Transfer files securely across the internet without opening ports.

---

## Security and Architecture Standards

OmaSend complies strictly with the Omarchy Linux Security Architecture (AGENTS.md):
- Subprocess Isolation: Processes run in isolated process groups (`cmd.process_group(0)`) with non-blocking I/O (`fcntl O_NONBLOCK`) and bounded polling.
- Strict File Permissions: Sensitive state files (`trusted_peers.json`, `device_id.key`) are written atomically with mode 0600. Symlinks are rejected.
- Network Limits: Absolute timeouts (15s) and header size caps (64 KiB) protect against Slowloris and resource exhaustion attacks.
- Plain Text UI: All dynamic strings in QML use `textFormat: Text.PlainText` to prevent script and markup injection.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
