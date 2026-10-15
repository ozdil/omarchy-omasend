# OmaSend - Omarchy Linux İçin Eşler Arası AirBridge ve Pano Senkronu

[![Omarchy Onaylı Eklenti](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Sürüm v1.9.1](https://img.shields.io/badge/S%C3%BCr%C3%BCm-v1.9.1-38BDF8?style=for-the-badge&logo=rust)](https://github.com/ozdil/omarchy-omasend/releases)
[![Kahve Ismarla](https://img.shields.io/badge/Buy_Me_A_Coffee-Geli%C5%9Ftiriciye_Destek-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)
[![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-blue?style=for-the-badge)](LICENSE)

![OmaSend Önizleme](preview.png)

> **Omarchy Linux, Android ve modern web tarayıcıları arasında doğrudan eşler arası dosya aktarımı ve pano senkronu; anonim numaralı kimlik (OmaID), hesap ve bulut sunucusu yok.**

> [!IMPORTANT]
> **Güvenlik durumu (v1.9.1):** Yerel ağ aktarımlarında boyut ve (gönderildiğinde) sağlama toplamı doğrulanır, ancak trafik **henüz uçtan uca şifreli veya kriptografik olarak kimliği doğrulanmış değildir**. OmaSend'i güvendiğiniz ağlarda kullanın. Gelen her transfer onayınızı bekler, pano senkronu yalnızca açıkça eşleştirilmiş cihazlarla çalışır. Cihaz başına anahtarlar, QR ile eşleşme ve kimliği doğrulanmış şifreleme yol haritasındadır.

- **Geliştirici:** Ozan Özdil (ozdil)  
- **Lisans:** MIT  
- **Eklenti Kimliği:** `ozdil.omasend`  
- **Sürüm:** `1.9.1`  
- **Varsayılan Yazı Tipi:** `JetBrainsMono Nerd Font`

---

## Öne Çıkan Yetenekler

- **Anonim Numaralı Kimlik (Sıfır Kayıt OmaID) ve Kendi Cihazlarım:**
  - Kayıt, e-posta, kullanıcı adı veya kişisel veri gerektirmeyen ücretsiz ve açık kaynaklı 16 haneli Luhn mod-10 numaralı kimlik (`XXXX-XXXX-XXXX-XXXX`).
  - Bilgisayarınıza ve Android telefonunuza aynı 16 haneli OmaID'yi girdiğinizde (`--set-oma-id <OMAID>` veya arayüz üzerinden) cihazlar arayüzde **Kendi Cihazlarım** altında gruplanır.
  - OmaID bir sır değil, bir tanımlayıcıdır: yerel ağda görülebilir. Bu yüzden tek başına güven sağlamaz. Gelen her transfer Gatekeeper onayından (`KABUL ET` / `REDDET`) geçer, pano senkronu kod doğrulamalı eşleşme gerektirir. Kendi cihazlarınız arasında onaysız aktarım, cihaz başına kriptografik anahtarlar geldiğinde geri dönecektir.
- **Evrensel Çok Formatlı Pano Kasası ve WebP Mikro Önizleme Motoru:**
  - Metin ve görsel verilerini (PNG, JPEG, WebP) masaüstü ile mobil arasında çift yönlü ve anlık senkronize eder.
  - Dahili WebP Mikro Önizleme Motoru: Kopyalanan görseller için izole sandbox içinde otomatik olarak 96x96 piksel ultra hafif önizlemeler (~3-5 KB) üretir; büyük dosyalar indirilmeden sıfır gecikmeli görsel sunumu sağlar.
  - Kompakt Pano Kasası Arayüzü: Tek tıklamayla panoya kopyalama, çift tıklamayla tam ekran önizleme ve `~/Pictures/OmaStudio_Exports/` dizinine anında aktarım.
  - Güvenli İzolasyon: `~/.local/state/omarchy/omasend/clip_staging/` altında atomik 0600 dosya izinleri ve 50 MiB LRU temizleme sınırı.
- **Omarchy AirBridge P2P ve Samuray Ses Efektleri:**
  - Akışlı Aktarım: Onaylanan transferler 0600 izinleri, disk alanı ayırma ve boyut/sağlama toplamı doğrulamasıyla doğrudan diske akıtılır.
  - Otantik Samuray Ses Efektleri: Dosya gönderiminde (*"OMAKASE!"* + Katana) ve dosya alım/kabulünde (*"ONEGAI SHIMASU!"* + Katana) yüksek netlikli sesli geri bildirim.
  - Donanım hızlandırmalı Wayland LayerShell manyetik sürükle-bırak (Drop HUD) kapsülü ve dairesel sonar radar görselleştirmesi.
  - Sıfır Yapılandırmalı Keşif: Yerel ağdaki Omarchy Linux masaüstü ve Android cihazları UDP işaretçileri (53317 portu) ile otomatik keşfeder.
  - 3 Kademeli Görünürlük Kontrolü: Kapalı (Off), Yalnızca Tanınanlar (Known - Varsayılan) ve Herkes (Everyone - 10 dakikalık geçici keşif).
- **Bütünlük ve Şifreleme:**
  - Yüklenen dosyanın boyutu onaylanan istekle eşleşmek zorundadır; BLAKE3 / SHA-256 / MD5 sağlama toplamları gönderici sağladığında doğrulanır (masaüstü motoru sağlar, Android uygulaması henüz sağlamaz).
  - Web portalı: oturum anahtarı URL'nin karma (`#key=...`) bölümünde taşınır ve HTTP isteklerine eklenmez (RFC 3986).
  - Henüz yok: yerel ağ/P2P trafiği için uçtan uca şifreleme ve kriptografik eş kimlik doğrulaması (yukarıdaki güvenlik durumu notuna bakın).
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

### 3. Adım: Üst Bara Yerleştirme (Opsiyonel)
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

OmaSend telemetri toplamaz, kullanıcıları izlemez ve verileri merkezi sunucularda saklamaz. Dosyalar ve pano içeriği doğrudan cihazlarınız arasında gider. Yerel ağ/P2P trafiği şu an uçtan uca şifreli veya kriptografik olarak kimliği doğrulanmış değildir; güvendiğiniz ağlarda kullanın. Gelen her transfer onayınızı bekler. Güvenlik sorunlarını GitHub üzerinden bildirebilirsiniz.

Detaylı güvenlik ilkeleri için [PRIVACY_POLICY.md](PRIVACY_POLICY.md) ve [CONTRIBUTING.md](CONTRIBUTING.md) belgelerini inceleyin.

---

## Lisans

Bu proje **MIT Lisansı** ile lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.
