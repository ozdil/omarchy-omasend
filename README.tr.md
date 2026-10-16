# OmaSend - Omarchy Linux İçin Eşler Arası AirBridge ve Pano Senkronu

[![Omarchy Onaylı Eklenti](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Sürüm v2.0.0](https://img.shields.io/badge/S%C3%BCr%C3%BCm-v2.0.0-38BDF8?style=for-the-badge&logo=rust)](https://github.com/ozdil/omarchy-omasend/releases)
[![Kahve Ismarla](https://img.shields.io/badge/Buy_Me_A_Coffee-Geli%C5%9Ftiriciye_Destek-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)
[![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-blue?style=for-the-badge)](LICENSE)

![OmaSend Önizleme](preview.png)

> **Yerel ağınızda Omarchy Linux ile Android arasında doğrudan dosya aktarımı ve pano senkronu. Cihazları bir kez QR kodla eşleştirin; sonrasında aralarındaki her şey uçtan uca şifrelenir. Hesap yok, bulut yok.**

> [!IMPORTANT]
> **Güvenlik durumu:** QR kodla eşleştirilen cihazlar (`omasend-engine --pair-offer`) cihaz başına Ed25519 anahtarları ve şifreli, karşılıklı kimlik doğrulamalı QUIC/TLS 1.3 aktarımı kullanır; transferler BLAKE3 ile doğrulanır ve kaldığı yerden devam eder. QR ile eşleştirilmemiş cihazlar hâlâ eski HTTP yolunu kullanır ve bu yol **şifreli değildir** — yalnızca güvendiğiniz ağlarda kullanın. Kendi eşleştirilmiş cihazlarınız dışındaki tüm gelen transferler onayınızı bekler. Protokol ayrıntıları: [PROTOCOL_V2.md](PROTOCOL_V2.md).

- **Geliştirici:** Ozan Özdil (ozdil)  
- **Lisans:** MIT  
- **Eklenti Kimliği:** `ozdil.omasend`  
- **Sürüm:** `2.0.0`  
- **Varsayılan Yazı Tipi:** `JetBrainsMono Nerd Font`

---

## Öne Çıkan Yetenekler

- **QR ile eşleşme ve Cihazlarım (protokol v2):**
  - Her cihazın kendi Ed25519 anahtarı vardır. İki cihazı bir kez QR kod okutarak eşleştirin (bar paneli → QR simgesi ya da `omasend-engine --pair-offer --own`).
  - Eşleşmiş cihazlar bu anahtarlarla kimliği doğrulanan QUIC + TLS 1.3 (iroh) üzerinden konuşur; aktarımlar BLAKE3 ile doğrulanır ve kaldığı yerden devam eder.
  - **Kendi cihazınız** olarak eşleştirdikleriniz aktarımları otomatik kabul eder ve panoyu paylaşır. Başkasının cihazı olarak eşleştirilenler her zaman onay ister ve panonuzu asla almaz.
  - Eşleşmiş cihazlar hiçbir zaman sessizce şifresiz HTTP'ye düşürülmez: şifreli bağlantı kurulamazsa (genellikle UDP 53318'i engelleyen güvenlik duvarı) düz metin aktarım değil, hata alırsınız.
  - **Yakındakiler** (eşleştirilmemiş cihazlar) eski HTTP yolunu alıcı onayıyla kullanmaya devam eder; bu yol şifreli değildir.
- **Evrensel Çok Formatlı Pano Kasası ve WebP Mikro Önizleme Motoru:**
  - Kendi eşleşmiş cihazlarınız arasında pano senkronu (metin, şifreli). Görsel pano senkronu eski kod-eşleşmeli cihazlarla kullanılabilir.
  - Dahili WebP Mikro Önizleme Motoru: Kopyalanan görseller için izole sandbox içinde otomatik olarak 96x96 piksel ultra hafif önizlemeler (~3-5 KB) üretir; büyük dosyalar indirilmeden sıfır gecikmeli görsel sunumu sağlar.
  - Kompakt Pano Kasası Arayüzü: Tek tıklamayla panoya kopyalama, çift tıklamayla tam ekran önizleme ve `~/Pictures/OmaStudio_Exports/` dizinine anında aktarım.
  - Güvenli İzolasyon: `~/.local/state/omarchy/omasend/clip_staging/` altında atomik 0600 dosya izinleri ve 50 MiB LRU temizleme sınırı.
- **Omarchy AirBridge P2P ve Samuray Ses Efektleri:**
  - Akışlı Aktarım: Onaylanan transferler 0600 izinleri, disk alanı ayırma ve boyut/sağlama toplamı doğrulamasıyla doğrudan diske akıtılır.
  - Otantik Samuray Ses Efektleri: Dosya gönderiminde (*"OMAKASE!"* + Katana) ve dosya alım/kabulünde (*"ONEGAI SHIMASU!"* + Katana) yüksek netlikli sesli geri bildirim.
  - Donanım hızlandırmalı Wayland LayerShell manyetik sürükle-bırak (Drop HUD) kapsülü ve dairesel sonar radar görselleştirmesi.
  - Sıfır Yapılandırmalı Keşif: Yerel ağdaki Omarchy Linux masaüstü ve Android cihazları UDP işaretçileri (53317 portu) ile otomatik keşfeder.
  - Keşfi ve alımı tek düğmeyle açıp kapatma.
- **Bütünlük ve Şifreleme:**
  - Yüklenen dosyanın boyutu onaylanan istekle eşleşmek zorundadır; BLAKE3 / SHA-256 / MD5 sağlama toplamları gönderici sağladığında doğrulanır (masaüstü motoru sağlar, Android uygulaması henüz sağlamaz).
  - Web portalı: oturum anahtarı URL'nin karma (`#key=...`) bölümünde taşınır ve HTTP isteklerine eklenmez (RFC 3986).
  - QR ile eşleştirilmiş cihazlar için şifreli aktarım (UDP `53318` üzerinde QUIC/TLS 1.3). Güvenlik duvarı kullanıyorsanız yerel ağda `53317/tcp`, `53317/udp` ve `53318/udp` portlarına izin verin.
- **Çoklu Platform Ekosistemi:**
  - **Linux Masaüstü Eklentisi:** Yerel Quickshell QML widget'ı ve sertleştirilmiş Rust arka plan motoru (`omasend-engine`).
  - **Android Yerel Uygulaması:** Kotlin ve Jetpack Compose ile sıfır GMS bağımlılıklı CameraX QR/Barkod vizörü ve dokunsal titreşim desteği ([ozdil/omasend-android](https://github.com/ozdil/omasend-android)).
  - **Web PWA İstemcisi:** Web Crypto API ve çevrimdışı Service Worker önbelleklemesi sunan kurulumsuz web istemcisi ([ozdil/omasend-web](https://github.com/ozdil/omasend-web)).
- **Sertleştirilmiş HANCORE Rust Motoru:**
  - Omarchy Linux Güvenlik Standartları ile tam uyum: Ayrı süreç grupları (`process_group(0)`), monoton yürütme sınırları, atomik geçici dosya yazımları (0600), `prctl(PR_SET_DUMPABLE, 0)` ve bellek sıfırlama (`Zeroize`).

---

## Sistem Gereksinimleri

- `cargo` ve `rustc` (Rust derleme zinciri, motor inşası için)
- `quickshell` (Omarchy masaüstü panel çalışma zamanı)
- `wl-clipboard` (Wayland pano komutları `wl-copy` ve `wl-paste` için)
- `libnotify` (Masaüstü bildirimleri için `notify-send`)
- `zenity` (GTK dosya seçim diyaloğu)
- `cloudflared` (Opsiyonel, Küresel WAN Tünel modu için)

---

## Kurulum ve Başlatma

### 1. Adım: Eklentiyi Omarchy'ye Ekleyin
```bash
omarchy plugin add https://github.com/ozdil/omarchy-omasend.git
```

### 2. Adım: Yerel Motoru Derleyin
Eklenti dizinine giderek otomatik kurulum betiğini çalıştırın:
```bash
cd ~/.config/omarchy/plugins/ozdil.omasend && ./build.sh
```
Bu betik motoru `cargo build --release --locked` ile derler, `omasend-engine` ikilisini 0755 izinleriyle kurar, kriptografik doğrulamayı yapar ve Omarchy kabuğunu otomatik olarak yeniden başlatır.

### 3. Adım: Cihazlarınızı eşleştirin
1. Bardaki OmaSend panelini açın ve QR simgesine tıklayın (ya da `p`). Kendi telefonunuz/bilgisayarınız için **Benim cihazım**'ı seçin.
2. Android'de: OmaSend → **Cihaz eşleştir** → **QR kodu tara**. İki masaüstü arasında: `omasend-engine --pair-with '<bağlantı>'` ya da eşleşme kartındaki ekran tarama düğmesi.
3. Cihaz **Cihazlarım** altında görünür. Dosyaları bar simgesine bırakın, dosya seçmek için cihaza tıklayın, panoyu göndermek için sağ tıklayın.

Komut satırı: `--pair-offer [--own] [--json]`, `--pair-with <bağlantı>`, `--devices`, `--unpair <cihaz-kimliği>`, `--send <cihaz-kimliği|ip|auto> <dosya>...`.

### 4. Adım: Üst Bara Yerleştirme (Opsiyonel)
Panelde otomatik görünmezse `~/.config/omarchy/shell.json` dosyasındaki `bar.layout.right` dizisine `ozdil.omasend` ekleyin:
```json
{
  "id": "ozdil.omasend"
}
```
Ardından kabuğu yeniden yükleyin:
```bash
omarchy-restart-shell
```

---

## Çoklu Platform Bağlantıları

- **Android Uygulaması:** [ozdil/omasend-android](https://github.com/ozdil/omasend-android)
- **Web PWA İstemcisi:** [ozdil/omasend-web](https://github.com/ozdil/omasend-web)
- **Google Play Kapalı Beta:** [Google Grubuna Katıl](https://groups.google.com/g/omasend-testers) & [Google Play Test Programına Katıl](https://play.google.com/apps/testing/io.omarchy.omasend)

---

## Güvenlik ve Gizlilik Politikası

OmaSend telemetri toplamaz, kullanıcıları izlemez ve verileri merkezi sunucularda saklamaz. Dosyalar ve pano içeriği doğrudan cihazlarınız arasında gider. QR ile eşleştirilmiş cihazlar arasındaki trafik uçtan uca şifreli ve kimliği doğrulanmıştır; eşleştirilmemiş cihazlarla olan trafik değildir, onu yalnızca güvendiğiniz ağlarda kullanın. Güvenlik sorunlarını GitHub üzerinden bildirebilirsiniz.

Detaylı güvenlik ilkeleri için [PRIVACY_POLICY.md](PRIVACY_POLICY.md) ve [CONTRIBUTING.md](CONTRIBUTING.md) belgelerini inceleyin.

---

## Lisans

Bu proje **MIT Lisansı** ile lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.
