# 🚀 omasend • Omarchy Wireless AirBridge & File Sharing

> **Cross-device wireless file transfer, local Wi-Fi QR AirBridge, and Bluetooth sharing plugin for Omarchy 4.0.2+.**

Author: **Ozan Özdil (ozdil)**  
License: **MIT**

---

## ✨ Features

- 📱 **Zero-App Mobile Sharing (QR-Drop):** Any iPhone, Android, or tablet on the same Wi-Fi can scan the generated QR code to immediately upload photos, videos, or documents directly to `~/Downloads` on your PC.
- 📤 **Instant Mobile Downloads:** Select any file on your computer to generate a single-use local QR download link for mobile devices.
- 📶 **Bluetooth Integration:** One-click launch for system Bluetooth file exchange.
- ⚡ **Zero External Dependencies:** Built with pure Python micro-HTTP server and native terminal ASCII QR renderer (`qrencode`).

---

## 🚀 Installation

```bash
# Clone to Omarchy plugins directory
git clone https://github.com/ozdil/omarchy-omasend.git ~/.config/omarchy/plugins/omasend
chmod +x ~/.config/omarchy/plugins/omasend/omasend-*
```

Add `{"id": "omasend", "exec": "$HOME/.config/omarchy/plugins/omasend/omasend-status", "onClick": "omarchy-launch-floating-terminal-with-presentation $HOME/.config/omarchy/plugins/omasend/omasend-dashboard"}` to `~/.config/omarchy/shell.json`.
