# 🚀 omasend • Omarchy Local Wi-Fi File & Clipboard Transfer

> **Cross-device local network file transfer and clipboard bridge plugin for Omarchy 4.0.2+.**

Author: **Ozan Özdil (ozdil)**  
License: **MIT**

---

## ✨ Features

- 📱 **QR Mobile Transfer:** Scan the terminal QR code from any smartphone on the local Wi-Fi to upload or download files directly.
- 📋 **Bidirectional Clipboard Bridge:** Copy Linux desktop clipboard to mobile and send mobile text back to Linux `wl-copy`.
- 🔒 **Bounded Resource Allocation:** Enforces 100MB file limits and 10,000-character clipboard boundaries.
- ⏱️ **Zero Hardcoded Paths:** Dynamically resolves plugin-relative components.

---

## 📋 Requirements

- `python3` (>= 3.10)
- `qrencode` (for terminal ASCII QR rendering)
- `wl-clipboard` (provides `wl-copy` and `wl-paste` on Wayland)

---

## 🚀 Installation & Removal

### Installation
```bash
git clone https://github.com/ozdil/omarchy-omasend.git ~/.config/omarchy/plugins/omasend
chmod +x ~/.config/omarchy/plugins/omasend/omasend-*
```

Add to `~/.config/omarchy/shell.json`:
```json
{
  "id": "omasend",
  "exec": "$HOME/.config/omarchy/plugins/omasend/omasend-status",
  "interval": 5,
  "onClick": "omarchy-launch-floating-terminal-with-presentation $HOME/.config/omarchy/plugins/omasend/omasend-dashboard"
}
```

### Removal
```bash
rm -rf ~/.config/omarchy/plugins/omasend
# Remove the "omasend" entry from ~/.config/omarchy/shell.json and run:
omarchy-restart-shell
```
