# OmaSend Değişiklik Günlüğü (Changelog)

Bu belgede OmaSend masaüstü ve Android uygulamaları için yapılan tüm sürüm geliştirmeleri ve teknik raporlar kayıt altında tutulur.

---

## [1.8.1] - 2026-10-14

### Full-Stack Denetim Düzeltmeleri (Masaüstü)
- **Pano (Wayland/X11):** `wl-copy`/`xclip` arka plan süreçleri yazma sonrası artık öldürülmüyor; pano içeriği kalıcı.
- **İndirme izleyici:** Mevcut dosyalar için ~61 sn'de bir tekrarlanan bildirim döngüsü giderildi (`known_files` takibi).
- **Panel performansı:** `--json` durumu STUN/qrencode çağrılarını önbellekten (30 sn) okuyor; panel donmaları giderildi.
- **P2P güvenliği:** `/api/p2p/decision` üzerinden uzaktan kendi kendini onaylama engellendi (yalnızca loopback veya oturumlu portal).
- **EVERYONE modu:** Eşleşmemiş cihazlar için onay (Gatekeeper) istemi artık erişilebilir.
- **Çoklu dosya:** Toplu gönderim tek istek + tek onay ile yapılıyor; sürükle-bırak tüm dosyaları tek seferde gönderiyor.
- **Görsel pano (Android uyumu):** BLAKE3 ve SHA-256 karma doğrulaması, `image_data_base64`/`sender_ip` alanları, `data:` öneki desteği, path/query tabanlı görsel uç noktası.
- **Web portal:** Dosya adı kaçışlama (XSS), dosya adı temizleme ve çoğaltılmış ad uyumluluğu düzeltildi.
- **Panel:** `omasend-engine` yolu çözümleme, 6 haneli eşleştirme kodu girişi.
- Tüm testler geçiyor (84/84).

---

## [1.6.4] - 2026-10-02 (Android Build: 43)

### Masaüstü & Mobil Eşzamanlı Sürüm ve Otomasyon Güncellemesi
- **Dinamik Sürüm Senkronizasyonu & Manifest İzleme:**
  - `Panel.qml` üzerindeki Hakkında / Info modalı manifest dosyasından (`manifest.json`) reaktif olarak beslenmektedir.
  - Sürüm numarası, lisans ve geliştirici bilgileri statik koddan arındırılmış olup, her derlemede otomatik güncellenmektedir.
- **Android Dağıtım Paketi:**
  - `versionCode = 43` ve `versionName = "1.6.4"` olarak güncellendi.
  - Proguard/R8 optimizasyonlu `.apk` ve `.aab` paketleri derlenerek `~/Projects/dist/` dizinine aktarıldı.
- **Masaüstü Motoru:**
  - Rust motoru `omasend-engine` v1.6.4 olarak derlendi ve yerel eklenti diziniyle eşitlendi.

---

## [1.6.3] - 2026-10-02 (Android Build: 42)

### Masaüstü & Mobil Dinamik Bilgi / Sürüm Senkronizasyonu
- **Dinamik Info / Hakkında Modalı:**
  - `Panel.qml` içerisindeki statik sürüm metni kaldırılarak `manifest.json` dosyasını reaktif izleyen Quickshell `FileView` entegrasyonu sağlandı.
  - Sürüm, Geliştirici, Lisans ve Açıklama alanları her derleme ve güncellemede otomatik olarak manifest kaynağından okunarak senkronize hale getirildi.
- **Sürüm Yükseltme & Paketleme:**
  - Masaüstü: `manifest.json` ve `Cargo.toml` v1.6.3 olarak güncellendi ve `./build.sh` ile yeniden derlendi.
  - Android: `versionCode = 42` ve `versionName = "1.6.3"` olarak yapılandırıldı; birim testleri ve release paketleri (`.apk`, `.aab`) derlenip `~/Projects/dist/` dizinine aktarıldı.

---

## [1.6.2] - 2026-10-02 (Android Build: 41)

### IEEE 802.11 Yüksek Verim & Soket Optimizasyonu
- **Soket Düzeyinde Tuning:**
  - Nagle algoritması kaynaklı Delayed-ACK kilitlenmesini önlemek için Linux (`TcpStream`) ve Android istemcilerinde `TCP_NODELAY = true` koşulsuz aktif edildi.
  - Soket tamponları (`sendBufferSize` / `receiveBufferSize`) 256 KiB boyutuna hizalanarak IEEE 802.11 A-MPDU / A-MSDU çerçeve agregasyon performansı maksimize edildi.
- **Tek Geçişli (Single-Pass) Disk Staging & Hashing:**
  - Rust motorunda disk staging sırasında BLAKE3, SHA-256 ve MD5 özetleri tek geçişte hesaplanarak çift disk okuma darboğazı giderildi.
  - P2P dosya gönderiminde tüm dosyayı RAM'e almadan `safe_verify_file` ile 128 KiB bloklar halinde akış aktarımı sağlandı.
- **Android Wi-Fi Power-Save Kilidi:**
  - Transfer sırasında Android'in Wi-Fi kartını güç tasarrufu moduna almasını önlemek amacıyla `WIFI_MODE_FULL_HIGH_PERF` ve `PARTIAL_WAKE_LOCK` güvencesi entegre edildi.

### Masaüstü & Mobil Arayüz İyileştirmeleri
- **Masaüstü OmaID Modal Refactoring:**
  - `Panel.qml` içerisindeki modal buton çakışması giderildi; duyarlı akrilik `Rectangle` + `RowLayout` + `MouseArea` yapısına geçildi.
  - `[ 󰄳 Ekrandan Tara ]` ve `[ 󰅍 Panodan Al ]` butonları 2 eşit esnek kolona ayrıldı.
  - Alt aksiyon butonları `[ 󰌆 Cihazı Bağla ]` (tam genişlik) ve `[ İptal ]` (sabit 60px) olarak netleştirildi.
- **Android OmaID & Pano Deneyimi:**
  - CameraX ve ZXing ile açık kaynaklı QR / Barkod okuyucu entegrasyonu tamamlandı.
  - Pano Kasasında WebP mikro-önizleme dokuları ve 48dp yuvarlatılmış kartlar aktive edildi.
- **Google Play Console Dağıtım Hazırlığı:**
  - Google Play Console kapalı test kanalı sürüm çakışmasını gidermek için `versionCode = 41` ve `versionName = "1.6.2"` olarak güncellendi.

---

## [1.5.0] - 2026-09-30

- Çoklu ortam pano kasası (Clipboard Vault) eklendi.
- WebP mikro-önizleme motoru Linux ve Android platformlarına dahil edildi.
- HANCORE askeri düzeyde güvenlik, `prctl(PR_SET_DUMPABLE, 0)` ve Mode 0600/0700 dosya izolasyonu standartlaştırıldı.
