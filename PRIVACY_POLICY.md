# Privacy Policy for OmaSend

**Last Updated**: September 9, 2026

## 1. Overview

OmaSend ("the Application") is an open-source, peer-to-peer file transfer and clipboard synchronization application developed by Ozan Ozdil for Linux and Android devices. 

Your privacy is paramount. OmaSend is architected from the ground up on a **Zero-Knowledge, Zero-Cloud, and Local-Only** operational model.

---

## 2. Information Collection and Use

### 2.1 No Personal Data Collection
OmaSend does not collect, harvest, store, transmit, or monetize any personal information, device identifiers, IP addresses, or usage logs.

### 2.2 No Analytics or Telemetry
The Application does not include any third-party advertising SDKs, tracking pixels, analytics frameworks (such as Google Analytics or Firebase), crash-reporting services, or profiling tools.

### 2.3 Peer-to-Peer Transmission
All file transfers and clipboard synchronization events happen directly and exclusively between devices located on the same Local Area Network (LAN):
- Devices discover each other using local UDP broadcast beacons on port `53317`.
- Data streams directly between peer devices over local HTTP/TCP sockets on port `53317`.
- No transmission ever passes through an external server, proxy, relay, or cloud storage bucket operated by the developer or any third party.

---

## 3. Permissions Used by the Application

OmaSend requests only the strictly minimum Android system permissions necessary to operate on local networks:

- **INTERNET (`android.permission.INTERNET`)**:
  Used solely to bind local TCP/HTTP sockets and exchange files directly with nearby peers over your local Wi-Fi or Ethernet connection. The application makes no outbound calls to external internet servers.
- **ACCESS_NETWORK_STATE & ACCESS_WIFI_STATE (`android.permission.ACCESS_NETWORK_STATE`, `android.permission.ACCESS_WIFI_STATE`)**:
  Used to detect local network connectivity and determine the device's local IP address.
- **CHANGE_WIFI_MULTICAST_STATE (`android.permission.CHANGE_WIFI_MULTICAST_STATE`)**:
  Used to enable UDP multicast packet reception required for automatic discovery of nearby peers.
- **FOREGROUND_SERVICE & FOREGROUND_SERVICE_CONNECTED_DEVICE (`android.permission.FOREGROUND_SERVICE`, `android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE`)**:
  Used to maintain continuous local peer availability and complete file transfers without interruption when the app is in the background.
- **POST_NOTIFICATIONS (`android.permission.POST_NOTIFICATIONS`)**:
  Used on Android 13+ to display the foreground service status and real-time file transfer progress in the system notification drawer.

---

## 4. Third-Party Services

OmaSend does not integrate with or share data with any third-party services, advertising networks, or data brokers.

---

## 5. Children's Privacy

The Application does not address anyone under the age of 13. We do not knowingly collect personally identifiable information from children under 13.

---

## 6. Security Architecture

In adherence to Omarchy Linux security standards:
- The Android companion client and server communicate using explicit, bounded I/O buffers to prevent buffer overrun attacks.
- File writes on Android are restricted to the public `Download/OmaSend` directory or explicit user-selected folders.
- Clipboard synchronizations are executed directly in-memory and are never written to persistent disk storage or shared outside the active session.

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
