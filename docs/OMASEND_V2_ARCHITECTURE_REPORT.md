# OmaSend V2 Konsolide Mimari Raporu ve Jev Nihai Sentezi

Bu belge; OmaSend V2 mimarisini mükemmelleştirmek amacıyla Mimo, Claude Code ve Codex uzman subagent'larının yaptığı derinlemesine teknik incelemelerin ve Jev Baş Güvenlik ve Mimarlık Ofisi'nin nihai eleştiri ve sentezinin özetidir.

---

## 1. Subagent Değerlendirmeleri ve Temel Çıkarımlar

### A. Mimo (Apple & Unix Sistem Mimarisi)
- **AirDrop / AWDL / BLE Akışı:** AirDrop'un sihirli kullanıcı deneyimi (UX), arka planda çalışan BLE (Bluetooth Low Energy) reklamları ve AWDL (Apple Wireless Direct Link) ad-hoc Wi-Fi bağlantısı sayesindedir. Kullanıcı dosya göndermek istediğinde cihazlar anında radar üzerinde parlar.
- **Sıfır Pencereli Omarchy Entegrasyonu:** Kullanıcı hiçbir pencere açmadan dosyayı sadece paneldeki tepsiye (DropArea) bıraktığında veya Wayland LayerShell HUD (baş üstü ekranı) ile en yakın cihaza fırlatabilmelidir.
- **Duyusal Geri Bildirim (Akustik / Haptik):** Aktarım başladığında ve bittiğinde PipeWire / WirePlumber üzerinden minimalist, tok ve profesyonel sistem sesleri (Apple AirDrop benzeri sub-bass 'pop/swoosh') çalınmalı, Android tarafında ise Jetpack Compose haptik titreşim motoru ile mesafe/yön hissi verilmelidir.

### B. Claude Code (Ağ Protokolü & Dağıtık Güvenlik Tasarımı)
- **Noise Protocol Framework (Noise_IKpsk2 / ChaCha20-Poly1305):** Mevcut OmaSend V1'deki P2P HTTP/1.1 düz metin açığı derhal kapatılmalıdır. Yerel ağdaki sniffing/Wireshark dinlemelerini engellemek için her P2P bağlantısı, bilinen cihaz anahtarlarıyla el sıkışan `Noise_IKpsk2` tüneli içine alınmalıdır.
- **QUIC / HTTP3 Taşımacılığı:** TCP'deki Head-of-Line engellemesini (yüksek paket kaybında tüm aktarımın durması) önlemek için QUIC UDP akışları kullanılmalıdır. Ağ değiştiğinde (örneğin Wi-Fi'dan mobil veriye geçildiğinde) aktarım kopmadan sürdürülebilmelidir (QUIC Connection Migration).
- **CRDT Tabanlı Çift Yönlü Pano Senkronizasyonu:** Sonsuz pano döngülerini (echo loops) önlemek için Lamport Timestamp ve Vector Clock mimarisi kurulmalı, panoya kopyalanan içerik sadece 10ms içinde şifreli olarak hedefe enjekte edilmelidir.
- **Grup / Çoklu Cihaza Eşzamanlı Dağıtım (Swarm Fan-out):** Tek bir dosya aynı anda birden fazla yerel cihaza çoklu akış (multi-stream) ile gönderilebilmelidir.

### C. Codex (Linux Çekirdeği, io_uring, Zero-Copy & Concurrency)
- **Zero-Copy I/O (`splice` ve `sendfile`):** V1'deki `safe_read_file` fonksiyonunun tüm 2-4 GB dosyayı heap belleğe (`Vec<u8>`) alması engellenmeli; dosya transferi çekirdek seviyesinde `splice(sock_fd -> pipe -> file_fd)` ile kullanıcı alanı belleğine hiç kopyalanmadan sıfır CPU yüküyle diske akıtılmalıdır.
- **Landlock LSM ABI v4/v5 & Seccomp Mikro-İzolasyonu:** Dinamik ABI müzakeresi ile Linux 6.7+ TCP kural seti (`LANDLOCK_ACCESS_NET_BIND_TCP`) eklenmeli; daemon'un yetkisiz port dinlemesi veya yerel ağ dışına taşması çekirdekte engellenmelidir. `openat2` ve `RESOLVE_BENEATH` ile TOCTOU/symlink yarışları elenmelidir.
- **`SO_REUSEPORT` & Multi-Worker Tokio Event Loop:** Thread-per-connection terk edilmeli, CPU çekirdeği başına bir worker atanarak kilit rekabetsiz ağ dinlemesi sağlanmalıdır.
- **Bellek Hijyeni:** `mlock` ile hassas anahtarlar RAM'e kilitlenmeli, swap alanına veya coredump'a dökülmesi `MADV_DONTDUMP` ile engellenmelidir.

---

## 2. Jev Nihai Mimari Eleştirisi ve Tasarım Yargısı

Jev, üç uzmanın raporlarını inceledikten sonra şu tespitleri yapmıştır:

1. **"Askeri Düzey" Pazarlamasından "Kurumsal Sıfır Güven (Zero-Trust)" Standardına Geçiş:**
   V1'deki "military" isimlendirmesi sektörde ciddiyetsiz bir pazarlama dili olarak algılanmaktadır. Güvenlik; sloganlarla değil, doğrulanabilir kriptografik tünelleme (`Noise_IKpsk2`), atomik izinler ve bellek izolasyonu ile tanımlanmalıdır.

2. **Kritik V1 Güvenlik Kusurunun Tespiti:**
   Mevcut sistemde web portalı AES-256-GCM ile korunurken, yerel P2P soket uçları (`/api/p2p/upload`, `/api/p2p/clipboard`) düz metin (plaintext) HTTP üzerinden çalışmaktadır. Bu durum yerel ağda bir saldırganın tüm pano verisini ve dosyaları dinlemesine açıktır. Acil müdahale şarttır.

3. **Kullanılabilirlik ve Apple Seviyesi Sadeliğin Anahtarı:**
   Kullanıcıya dosya gönderirken IP adresi, port, hash veya protokol ayarı sormak ilkel bir yaklaşımdır. Kullanıcı için deneyim şundan ibaret olmalıdır:
   - Masaüstünde: Dosyayı paneldeki OmaSend simgesine veya masaüstü kenarına sürükle-bırak.
   - Mobilde: Cihazı yaklaştır veya radar ekranında beliren tek düğmeye dokun.
   - Geri kalan tüm kriptografik el sıkışma, sıfır-kopyalama disk yazımı ve ağ geçişi arka planda görünmez şekilde tamamlanmalıdır.

---

## 3. OmaSend V2 Dönüşüm Yol Haritası

- **Faz 1 (Protokol & Güvenlik Düzeltmeleri - Hemen):**
  - P2P soketlerine Noise Protocol / ChaCha20-Poly1305 E2EE şifrelemesi eklenmesi.
  - Quickshell `DropArea` bileşeninde çoklu dosya sürükle-bırak döngü hatasının düzeltilmesi.
  - Dosya indirme ve yükleme yollarında `splice` / `sendfile` akışına geçilerek bellek şişmesinin önlenmesi.
- **Faz 2 (Asenkron Altyapı & Çekirdek İzolasyonu):**
  - Tokio asenkron runtime ve `SO_REUSEPORT` soket mimarisi.
  - Landlock LSM ABI v4 ağ kısıtlamaları ve atomik `openat2` koruması.
- **Faz 3 (Duyusal UX & Android Haptik):**
  - PipeWire minimalist ses efektleri entegrasyonu.
  - Android Jetpack Compose radarında titreşimli yön/mesafe kılavuzu.
