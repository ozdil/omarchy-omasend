# OmaSend - Google Play Store Listing & Compliance Guide

This document contains all official store metadata, textual assets, and regulatory disclosures required for publishing OmaSend on the Google Play Console.

---

## 1. App Identity & Category

- **App Name**: OmaSend - Local P2P Transfer
- **Package Name**: `io.omarchy.omasend`
- **Default Language**: English (United States) - `en-US`
- **Secondary Language**: Turkish - `tr-TR`
- **Category**: Tools / Productivity
- **Tags / Keywords**: `peer-to-peer`, `file transfer`, `clipboard sync`, `local network`, `lan sharing`, `privacy`, `open source`
- **Target Audience**: Ages 13 and older (General Audience)
- **Contains Ads**: No
- **In-App Purchases**: No
- **Government App**: No
- **Financial / Health Features**: No

---

## 2. Store Descriptions

### English (en-US)

**Short Description (Max 80 characters):**
High-performance local peer-to-peer file transfer and Wayland clipboard sync.

**Full Description (Max 4000 characters):**
OmaSend is a high-performance, privacy-first peer-to-peer file and clipboard sharing application built for local networks. It provides seamless cross-platform parity between Omarchy Linux (and other modern Linux distributions) and Android devices.

OmaSend operates strictly within your local area network (LAN). It does not rely on third-party cloud servers, user accounts, remote databases, or external intermediaries. Your files and clipboard content travel directly from device to device at full local network speeds.

KEY CAPABILITIES

1. Instant Local Peer Discovery:
Using automated UDP broadcast beacons on port 53317, OmaSend discovers nearby devices instantly without manual IP entry or Bluetooth pairing delays.

2. High-Speed File Streaming:
Transfer photos, documents, archives, and media directly between your Android device and Linux workstations with zero compression, zero size limits, and real-time streaming progress tracking.

3. Bi-Directional Clipboard Synchronization:
Share text snippets, URLs, code blocks, and tokens seamlessly between your Android clipboard and Linux Wayland desktop environment with a single tap.

4. System Share Sheet Integration:
Send any file or text directly from your favorite Android apps using the native Android system share dialog.

5. Background Daemon & Radar Interface:
Monitor nearby devices and incoming transfers effortlessly with a low-power background service and a cybernetic radar interface.

PRIVACY AND ARCHITECTURE GUARANTEES

- Zero Cloud Dependency: All transmissions are direct socket-to-socket connections over your local Wi-Fi or Ethernet network.
- Zero Telemetry: OmaSend collects no analytics, no crash metrics, no device identifiers, and no user tracking data.
- Open Protocol Parity: Full wire compatibility with the official OmaSend Linux engine and desktop plugin.
- Strict Permission Discipline: Requests only the essential network and notification permissions required for direct transfers.

OmaSend is designed for users who demand speed, reliability, and absolute privacy on their local networks.

---

### Turkish (tr-TR)

**Kısa Açıklama (En fazla 80 karakter):**
Yerel ağ üzerinden hızlı P2P dosya transferi ve Wayland pano eşitleme.

**Tam Açıklama (En fazla 4000 karakter):**
OmaSend, yerel ağlar için geliştirilmiş yüksek performanslı ve gizlilik odaklı bir eşler arası (P2P) dosya ve pano paylaşım uygulamasıdır. Omarchy Linux ve modern Linux masaüstü ortamları ile Android cihazlar arasında doğrudan bağlantı sağlar.

OmaSend tamamen yerel ağınız (LAN) içerisinde çalışır. Üçüncü taraf bulut sunucularına, kullanıcı hesaplarına, uzak veritabanlarına veya aracılara ihtiyaç duymaz. Dosyalarınız ve pano içerikleriniz cihazlar arasında doğrudan yerel ağ hızında aktarılır.

TEMEL ÖZELLİKLER

1. Anında Yerel Eş Keşfi:
53317 portu üzerindeki otomatik UDP yayın sinyalleri sayesinde OmaSend, IP adresi girmeye veya Bluetooth eşleştirmesine gerek kalmadan yakındaki cihazları saniyeler içinde bulur.

2. Yüksek Hızlı Dosya Aktarımı:
Fotoğraf, video, belge ve arşiv dosyalarını Android cihazınız ile Linux bilgisayarınız arasında sıkıştırma olmadan, boyut sınırı olmaksızın ve anlık ilerleme takibiyle aktarın.

3. Çift Yönlü Pano (Clipboard) Eşitleme:
Metinleri, web adreslerini, kod parçacıklarını ve notları tek dokunuşla Android panonuz ile Linux Wayland masaüstünüz arasında eşitleyin.

4. Sistem Paylaşım Menüsü Entegrasyonu:
Android üzerindeki herhangi bir uygulamadan dosya veya metin paylaşırken doğrudan sistem paylaşım menüsü üzerinden OmaSend'i seçebilirsiniz.

5. Arka Plan Hizmeti ve Radar Arayüzü:
Düşük güç tüketimli arka plan servisi ve modern radar arayüzü ile ağdaki aktif cihazları ve gelen aktarımları kolayca izleyin.

GİZLİLİK VE MİMARİ İLKELER

- Sıfır Bulut Bağımlılığı: Tüm aktarımlar yerel Wi-Fi veya Ethernet ağınız üzerinden doğrudan soket bağlantısıyla yapılır.
- Sıfır Telemetri: OmaSend hiçbir analiz verisi, çökme raporu, cihaz kimliği veya kullanıcı izleme verisi toplamaz.
- Açık Protokol Uyumluluğu: Resmi OmaSend Linux motoru ve masaüstü eklentisiyle tam protokol uyumluluğu.
- Sıkı İzin Yönetimi: Yalnızca doğrudan aktarım için zorunlu olan yerel ağ ve bildirim izinlerini talep eder.

OmaSend, yerel ağlarında hız, kararlılık ve mutlak gizlilik isteyen kullanıcılar için tasarlanmıştır.

---

## 3. Data Safety (Veri Güvenliği) Questionnaire Answers

Google Play Console'da "Data safety" (Veri güvenliği) adımı için resmi yanıtlar:

1. **Does your app collect or share any of the required user data types?**
   - Answer: **NO** (OmaSend does not collect, store, or share any user data).
2. **Is all of the user data collected by your app encrypted in transit?**
   - Answer: **NOT APPLICABLE** (No data is collected by the developer or transmitted to developer servers).
3. **Do you provide a way for users to request that their data be deleted?**
   - Answer: **NOT APPLICABLE** (No user accounts or cloud storage exist).
4. **Is your app target audience including children?**
   - Answer: **NO** (Ages 13+).

---

## 4. Permissions & Justifications
 
- `android.permission.INTERNET`: Required to create local HTTP/TCP sockets and stream files across the local Wi-Fi network.
- `android.permission.ACCESS_NETWORK_STATE` & `ACCESS_WIFI_STATE`: Required to verify Wi-Fi connectivity and bind to local network interfaces.
- `android.permission.CHANGE_WIFI_MULTICAST_STATE`: Required to receive UDP multicast beacons for local peer discovery on port 53317.
- `android.permission.FOREGROUND_SERVICE` & `FOREGROUND_SERVICE_DATA_SYNC`: Required to maintain reliable background peer discovery and receive incoming files when screen is locked or app is in background.
- `android.permission.POST_NOTIFICATIONS`: Required on Android 13+ to show persistent service status and transfer progress indicators.
- `android.permission.BLUETOOTH`, `BLUETOOTH_ADMIN`, `BLUETOOTH_CONNECT`: Required to support alternative direct Bluetooth file sharing when local Wi-Fi networks have AP client isolation or are unavailable.

