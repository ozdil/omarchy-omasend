# Privacy Policy for OmaSend

**Last Updated**: October 15, 2026

## 1. Overview

OmaSend ("the Application") is an open-source, peer-to-peer file transfer and clipboard synchronization application developed by Ozan Ozdil for Linux and Android devices. 

Your privacy is paramount. OmaSend follows a **Zero-Cloud, Local-First** operational model: the developer operates no servers that receive your files or clipboard contents.

**Transport security notice:** Local network (LAN/P2P) transfers are integrity-checked but are not yet end-to-end encrypted or cryptographically authenticated. Anyone on the same network may be able to observe this traffic. Use OmaSend on networks you trust.

---

## 2. Information Collection and Use

### 2.1 No Personal Data Collection
OmaSend does not collect, harvest, store, transmit, or monetize any personal information, device identifiers, IP addresses, or usage logs.

### 2.2 No Analytics or Telemetry
The Application does not include any third-party advertising SDKs, tracking pixels, analytics frameworks (such as Google Analytics or Firebase), crash-reporting services, or profiling tools.

### 2.3 Peer-to-Peer Transmission
All file transfers and clipboard synchronization events happen directly between peer devices:
- Devices discover each other on Local Area Networks (LAN) using UDP broadcast/multicast beacons on port `53317`.
- Data streams directly between peer devices over HTTP/TCP sockets on port `53317` (or optional user-initiated Cloudflare WAN tunnels / STUN endpoint discovery when WAN mode is enabled).
- No user files or clipboard contents are stored on any central cloud storage bucket operated by the developer.

---

## 3. Permissions Used by the Application

OmaSend requests only the strictly minimum Android system permissions necessary to operate:

- **INTERNET (`android.permission.INTERNET`)**:
  Used to bind TCP/HTTP sockets, exchange files and clipboard payloads with authorized peers over Wi-Fi/Ethernet, and perform optional STUN/WAN endpoint resolution when cross-subnet connectivity is active.
- **ACCESS_NETWORK_STATE & ACCESS_WIFI_STATE (`android.permission.ACCESS_NETWORK_STATE`, `android.permission.ACCESS_WIFI_STATE`)**:
  Used to detect network connectivity and determine the device's local IP address.
- **CHANGE_WIFI_MULTICAST_STATE (`android.permission.CHANGE_WIFI_MULTICAST_STATE`)**:
  Used to enable UDP multicast packet reception required for automatic discovery of nearby peers.
- **FOREGROUND_SERVICE & FOREGROUND_SERVICE_DATA_SYNC (`android.permission.FOREGROUND_SERVICE`, `android.permission.FOREGROUND_SERVICE_DATA_SYNC`)**:
  Used to maintain peer availability and complete active file transfers without interruption when the app is in the background.
- **POST_NOTIFICATIONS (`android.permission.POST_NOTIFICATIONS`)**:
  Used on Android 13+ to display the foreground service status and real-time file transfer progress in the system notification drawer.
- **VIBRATE (`android.permission.VIBRATE`)**:
  Used to provide tactile haptic feedback during peer discovery and file transfer completion.
- **CAMERA (`android.permission.CAMERA`)**:
  Used solely when the user explicitly opens the QR code scanner to pair or sync an OmaID.

---

## 4. Third-Party Services

OmaSend does not integrate with advertising networks, analytics SDKs, or data brokers.

---

## 5. Children's Privacy

The Application does not address anyone under the age of 13. We do not knowingly collect personally identifiable information from children under 13.

---

## 6. Security Architecture

In adherence to Omarchy Linux security standards:
- The Android companion client and Linux server communicate using explicit, bounded I/O buffers to prevent buffer overrun and memory exhaustion attacks.
- File writes on Android are restricted to the `Download/OmaSend` directory via MediaStore or explicit user-selected folders.
- Clipboard history and staged images are stored strictly inside user-private local state directories (`0700` directory / `0600` file permissions on Linux; `MODE_PRIVATE` internal storage on Android) and are excluded from cloud backups.

---

## 7. Open Source and Source Code Verification

The complete source code of OmaSend (both the Linux engine and the Android companion app) is open-source and publicly inspectable at:
[https://github.com/ozdil/omarchy-omasend](https://github.com/ozdil/omarchy-omasend)

Users and security researchers are welcome to review, audit, and build the application independently from source.

---

## 8. Changes to This Privacy Policy

We may update our Privacy Policy from time to time. Any modifications will be posted in this repository and reflected in future application updates.

---

## 9. Contact Us

If you have any questions, concerns, or inquiries regarding this Privacy Policy, you may contact the developer:

- **Developer**: Ozan Ozdil
- **GitHub**: [https://github.com/ozdil/omarchy-omasend](https://github.com/ozdil/omarchy-omasend)
