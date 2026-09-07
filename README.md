# 🚀 OmaSend • LocalSend-like AirBridge for Omarchy Linux

> **Cross-device local Wi-Fi file transfer, clipboard bridge, and mobile web portal for Omarchy Linux.**

Author: **Ozan Özdil (ozdil)**  
License: **MIT**  
Plugin ID: `ozdil.omasend`

---

## ✨ Features

- 📱 **Camera-Scannable QR Pairing:** Instant QR code displayed in the native panel. Point your smartphone camera at the screen to immediately connect.
- 🔒 **PIN-Secured AirBridge:** Generates a persistent 4-digit security PIN to prevent unauthorized devices on the local network from sending or reading files.
- 🔄 **Bidirectional File Transfers:**
  - **Mobile ➔ PC:** Send photos, documents, and archives directly into `~/Downloads/omasend/`.
  - **PC ➔ Mobile:** Place files into `~/Downloads/omasend/shared/` to make them instantly downloadable on connected mobile devices.
- 📋 **Live Clipboard Synchronization:** One-tap clipboard sync between mobile browser and Linux desktop (`wl-copy` / `wl-paste`).
- 🔔 **Native Wayland Notifications:** Alerts via `notify-send` when incoming files or clipboard syncs arrive.
- 🎨 **100% Native Omarchy Design:** Zero hardcoded colors; dynamically inherits the active Omarchy theme (`Color.popups.*`, `Color.accent`, `Style.selectedFillFor`).
- ⚡ **Native Rust Engine:** High-performance multi-threaded daemon (`omasend-engine`) with bounded resource handling.

---

## 📋 Requirements

- `qrencode` (for generating SVG QR codes)
- `wl-clipboard` (provides `wl-copy` and `wl-paste` on Wayland)
- `libnotify` (provides `notify-send` for desktop alerts)
- `cargo` (Rust toolchain, for building from source)

---

## 🚀 Installation & Setup

### 1. Clone to Omarchy Plugins Directory
```bash
git clone https://github.com/ozdil/omarchy-omasend.git ~/.config/omarchy/plugins/ozdil.omasend
```

### 2. Build and Install Native Rust Engine
```bash
cd ~/.config/omarchy/plugins/ozdil.omasend
cargo build --release
cp target/release/omasend-engine ~/.local/bin/omasend-engine
chmod +x ~/.local/bin/omasend-engine
```

### 3. Add to Omarchy Shell Configuration
Add `ozdil.omasend` to `bar.layout.right` in `~/.config/omarchy/shell.json`:
```json
{
  "id": "ozdil.omasend"
}
```

### 4. Restart Shell
```bash
omarchy-restart-shell
```

---

## 📖 Usage

1. Click the paper plane icon (``) in the Omarchy top bar to open the OmaSend panel.
2. Scan the QR code with your mobile device or open the local IP URL in your mobile browser.
3. Enter the 4-digit PIN displayed on your panel to unlock the secure portal.
4. Drag and drop files to upload, or use the clipboard box to send text directly to your Linux desktop clipboard!
