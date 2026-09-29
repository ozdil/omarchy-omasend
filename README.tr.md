# OmaSend - Omarchy Linux İçin Sıfır Bilgili AirBridge ve E2EE Dosya Aktarım Merkezi

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)

Omarchy Linux için çapraz platform dosya aktarımı, şifreli pano köprüsü, yerel AirBridge P2P ve küresel WAN tüneli sunan, AES-256-GCM uçtan uca şifreli (E2EE) aktarım eklentisi.

Geliştirici: Ozan Özdil (ozdil)  
Lisans: MIT  
Eklenti Kimliği: ozdil.omasend  

---

## Öne Çıkan Özellikler

- Omarchy AirBridge P2P (Masaüstü ve Mobil Doğrudan Aktarım):
  - Sıfır Yapılandırmalı Keşif: Aynı yerel ağdaki Omarchy masaüstü ve Android cihazları UDP işaretçileri (53317 portu) ile anında bulur.
  - Yerel Android İstemcisi: Sistem paylaşım menüsü, çift yönlü aktarımlar ve evrensel pano köprüsü.
  - 3 Kademeli Görünürlük Kontrolü: Kapalı (Off), Yalnızca Tanınanlar (Known - Varsayılan) ve Herkes (Everyone - 10 dakikalık geçici keşif).
  - Gatekeeper İzin Kapısı: Hiçbir dosya sessizce kabul edilmez. Alıcıya gönderici adı, dosya listesi ve boyutuyla onay bildirimi çıkarılır; transfer yalnızca açık onay ile başlar.
  - Evrensel Pano Senkronizasyonu: Omarchy Wayland ve Android panoları arasında çift yönlü şifreli pano eşitlemesi.
- Sıfır Bilgili Uçtan Uca Şifreleme (E2EE):
  - Donanım hızlandırmalı AES-256-GCM ve BLAKE3 kriptografik bütünlük doğrulaması.
  - Oturum anahtarı URL'nin karma (#key=...) bölümünde taşınarak sunucu loglarına ve başlıklara açık sızması imkansız kılınır (RFC 3986).
- Sıfır Kurulumlu Mobil Web Portalı:
  - Akıllı telefon kamerasıyla QR kodu taratarak Safari veya Chrome üzerinden doğrudan şifreli web portalına erişim.
- Askeri Düzeyde HANCORE Güvenliği:
  - `prctl(PR_SET_DUMPABLE, 0)` ile tersine mühendislik ve bellek dökümü koruması.
  - Bellekteki hassas anahtarların sıfırlanması (`Zeroize`).

---

## Gereksinimler

- cargo ve rustc (Rust derleme zinciri)
- quickshell (Arayüz kabuğu)
- wl-clipboard (Wayland pano entegrasyonu için)

---

## Kurulum ve Derleme

```bash
# Eklenti dizinine gidin
cd ~/.config/omarchy/plugins/ozdil.omasend

# Motoru derleyin
cargo build --release

# İkiliyi kurun
install -m 755 target/release/omasend-engine ./omasend-engine
install -m 755 target/release/omasend-engine ~/.local/bin/omasend-engine
```

---

## Doğrulama ve Testler

```bash
# Birim ve güvenlik testlerini çalıştırın
cargo test

# Omarchy eklenti doğrulamasını çalıştırın
omarchy plugin validate .
```
