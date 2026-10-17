# Privacy Policy for OmaSend

**Last Updated**: October 17, 2026

## 1. Overview

OmaSend ("the Application") is an open-source, peer-to-peer file transfer and clipboard synchronization application developed by Ozan Ozdil for Linux and Android devices. 

Your privacy is paramount. OmaSend follows a **Zero-Cloud, Local-First** operational model: the developer operates no servers that receive your files or clipboard contents.

**Transport security notice:** Transfers between QR-paired devices are end-to-end encrypted and mutually authenticated (QUIC/TLS 1.3 with per-device Ed25519 keys). Transfers with devices that are not QR-paired use the legacy HTTP path, which is integrity-checked but not encrypted; anyone on the same network may be able to observe that traffic. Use it only on networks you trust.

---

## 2. Information Collection and Use

### 2.1 No Personal Data Collection
OmaSend does not collect, harvest, store, transmit, or monetize any personal information, device identifiers, IP addresses, or usage logs.

### 2.2 No Analytics or Telemetry
The Application does not include any third-party advertising SDKs, tracking pixels, analytics frameworks (such as Google Analytics or Firebase), crash-reporting services, or profiling tools.

### 2.3 Peer-to-Peer Transmission
All file transfers and clipboard synchronization events happen directly between peer devices:
- Devices discover each other on Local Area Networks (LAN) using UDP broadcast/multicast beacons on port `53317`.
- Data between QR-paired devices streams directly over encrypted QUIC on UDP port `53318`; other peers use HTTP/TCP on port `53317` (or optional user-initiated Cloudflare WAN tunnels / STUN endpoint discovery when WAN mode is enabled).
- No user files or clipboard contents are stored on any central cloud storage bucket operated by the developer.

### 2.4 Optional OmaID Account
An OmaID is an anonymous 16-digit account number that links your own devices. It is optional: nothing is sent to a server until you create or join an account. No email, phone number, name or password is ever asked for.

When you use an account, the registry at `id.omaid.app` stores:
- a lookup identifier derived from your number with Argon2id and HKDF (the number itself never leaves your devices);
- an end-to-end encrypted record (AES-256-GCM) holding your devices' public keys, the names you gave them, and how to reach them. The key never leaves your devices, so the registry cannot read it;
- per-device key boxes, each encrypted to one of your devices;
- join requests from new devices, encrypted, until they are approved or expire after 15 minutes;
- the record's version number and last update time.

The registry keeps no IP addresses, user agents or request logs. Its hosting provider, Cloudflare, processes connection metadata (such as IP addresses) to deliver requests and to enforce rate limits. Deleting the account (leaving with your last device) removes the record immediately. Records that are not updated for a long time are removed automatically.

### 2.5 Transfers over the Internet
When your own devices are not on the same network, OmaSend connects them through public relay servers operated by n0 (the iroh project), and switches to a direct connection when the networks allow it. Everything that passes through a relay is end-to-end encrypted with QUIC/TLS 1.3 and bound to your devices' keys. The relay can see the two devices' IP addresses and public keys, and how much data passes and when; it cannot see file names, contents or clipboard text. Files over 4 GiB are only sent over a direct connection.

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
  Used solely when the user explicitly opens the QR code scanner to pair a device or join an OmaID account.

---

## 4. Third-Party Services

OmaSend does not integrate with advertising networks, analytics SDKs, or data brokers.

Two services are used only for the optional features described above:
- **Cloudflare** hosts the OmaID registry (`id.omaid.app`) and the `omaid.app` website. The website sets no cookies, loads nothing from other sites and keeps no logs; as the infrastructure provider, Cloudflare processes connection metadata (such as IP addresses) to deliver each request and to block abuse, and keeps its own security logs for a limited time as described in its privacy policy.
- **n0 relays** (iroh) forward end-to-end encrypted traffic between your own devices when they are on different networks.

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
