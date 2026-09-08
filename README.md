# 🚀 OmaSend • Zero-Knowledge AirBridge & E2EE Transfer for Omarchy Linux

> **Cross-device file transfer, encrypted clipboard bridge, Omarchy AirDrop P2P, and global WAN portal with Zero-Knowledge AES-256-GCM encryption for Omarchy Linux.**

Author: **Ozan Özdil (ozdil)**  
License: **MIT**  
Plugin ID: `ozdil.omasend`

---

## ✨ Features / Özellikler

- 📡 **Omarchy AirDrop P2P (PC-to-PC Direct Transfer):**
  - **Zero-Config Keşif:** Aynı yerel ağdaki Omarchy Linux masaüstü bilgisayarlarını UDP multicast beacon (`8845`) ve Bluetooth (BLE) ile anında otomatik bulur.
  - **3 Aşamalı Görünürlük Denetimi:** *OFF* (Kapalı), *KNOWN (Sadece Tanınan Eşler - Varsayılan)* ve *EVERYONE (10 Dakika Herkese Açık)*.
  - **🛡️ Gatekeeper Onay Mekanizması:** İzniniz olmadan hiçbir dosya arka planda sessizce indirilemez. Gönderen cihaz adı, dosya listesi ve boyutu masaüstü uyarısı ve panelde onay istemi olarak görünür; alıcı "Kabul Et" demeden aktarım başlamaz. Bir kez onaylanan cihazlar kalıcı güvenilir listeye (`trusted_peers.json`) eklenir.
  - **Universal Pano Eşitleme:** Bilgisayarlar arasında tek tıkla şifreli Wayland panosu (`wl-copy` / `wl-paste`) transferi.
- 🔒 **Zero-Knowledge End-to-End Encryption (E2EE):**
  - Web Crypto API (`crypto.subtle`) üzerinden donanım hızlandırmalı **AES-256-GCM** şifreleme.
  - 256-bit oturum anahtarı URL'nin hash parçacığında (`#key=...`) taşınır; **HTTP başlıklarına veya sunucu kayıtlarına asla ulaşmaz** (`RFC 3986`). Yerel ağdaki veya internetteki hiç kimse aktarılan dosyaları veya panoyu deşifre edemez.
- 📱 **Zero-Install Mobile Portal (Akıllı Telefon Transferi):**
  - Telefona hiçbir ek uygulama yüklemeden doğrudan kamera ile QR kodu tarayın.
  - Safari veya Chrome üzerinde uçtan uca şifreli portal açılır; fotoğraflar, 4K videolar ve belgeler saniyeler içinde bilgisayara akar.
- 🌐 **Hybrid Network Modes (LAN & Global WAN):**
  - **🏠 Yerel Ağ (LAN):** Yerel Wi-Fi üzerinden maksimum hızda (300–800 Mbps) transfer.
  - **🌐 Dış Ağ (Global WAN Tüneli):** Port açmaya veya statik IP'ye gerek kalmadan Cloudflare Tunnel (`cloudflared`) ile hücresel 4G/5G veya uzak ağlar üzerinden dünya çapında transfer.
- 🔑 **Dinamik PIN & Anahtar Güvenliği:** Tek tıkla yenilenebilen 4 haneli PIN ve 256-bit kriptografik anahtar doğrulaması.
- 🔔 **Yerel Wayland Bildirimleri:** Dosya veya pano geldiğinde `notify-send` ile anlık masaüstü bildirimleri.
- 🎨 **100% Native Omarchy Tasarımı:** Aktif Omarchy renk paletini ve tipografisini (`Color.popups.*`, `Color.accent`, `Style.selectedFillFor`) dinamik olarak kullanır.
- ⚡ **Sertleştirilmiş Rust Motoru:** Omarchy Güvenlik Standartlarına (`AGENTS.md`) %100 uyumlu; yalıtılmış süreç grupları (`process_group`), zorunlu zaman sınırları (monotonic deadlines), atomik dosya yazımı (`0600`) ve tampon sınırı (buffer cap) korumalı.

---

## 📋 Requirements / Gereksinimler

- `cargo` & `rustc` (Rust geliştirme araçları, motoru kaynaktan derlemek için)
- `qrencode` (SVG formatında QR kod üretimi için)
- `wl-clipboard` (Wayland üzerinde `wl-copy` ve `wl-paste` desteği için)
- `libnotify` (Masaüstü bildirimleri için `notify-send`)
- `zenity` (Dosya gönderme diyalog penceresi için)
- `cloudflared` *(İsteğe bağlı, Dış Ağ / Global WAN Tüneli modu için)*:
  ```bash
  sudo pacman -S cloudflared
  ```

---

## 🚀 Installation & Setup / Kurulum Rehberi

> [!IMPORTANT]
> **Neden Kaynaktan Derleme Gereklidir? (Zero Prebuilt Binaries Kuralı):**  
> Omarchy Linux Güvenlik Standartları (**AGENTS.md Kural 5.3**) gereği, önceden derlenmiş ikili dosyalar güvenlik ve sistem bütünlüğü nedeniyle Git depolarında barındırılmaz. Bu nedenle eklenti eklendikten sonra yerel motorun tek bir komutla derlenmesi gerekir.

### Adım 1: Eklentiyi Omarchy'ye Ekleyin
```bash
omarchy plugin add https://github.com/ozdil/omarchy-omasend.git
```

### Adım 2: Yerel Motoru Derleyin (Build Engine)
Eklenti klasörüne gidip otomatik derleme betiğini çalıştırın:
```bash
cd ~/.config/omarchy/plugins/ozdil.omasend && ./build.sh
```
*Bu betik `cargo build --release --locked` çalıştırır, motoru (`omasend-engine`) kök dizine kopyalar ve Quickshell kabuğunu otomatik olarak yeniden başlatır.*

### Adım 3: Güvenlik Duvarı (UFW) İzinleri
İki cihazın yerel ağda birbirini otomatik keşfetmesi ve dosya aktarabilmesi için terminalde güvenlik duvarı izinlerini verin (yerel alt ağınıza göre ayarlayın, örn: `192.168.1.0/24`):
```bash
# TCP 8844: Dosya transferi ve şifreli HTTP portalı
sudo ufw allow from 192.168.1.0/24 to any port 8844 proto tcp

# UDP 8845: AirBridge P2P otomatik cihaz keşfi
sudo ufw allow from 192.168.1.0/24 to any port 8845 proto udp
```

### Adım 4: Üst Bara (Bar) Ekleyin
Eğer barınızda henüz görünmüyorsa, `~/.config/omarchy/shell.json` dosyasındaki `bar.layout.right` listesine `ozdil.omasend` ekleyin:
```json
{
  "id": "ozdil.omasend"
}
```
Ardından kabuğu yeniden başlatın:
```bash
omarchy-restart-shell
```

---

## 📖 How It Works & User Guide / Nasıl Çalışır ve Kullanım

Üst bardaki kâğıt uçak simgesine (``) tıklayarak OmaSend panelini açın.

### 1. 📡 Omarchy AirDrop (PC'den PC'ye Doğrudan Aktarım)
- **Cihaz Keşfi:** Aynı yerel ağda OmaSend çalıştıran bilgisayarlar panelin altındaki **"AIRBRIDGE DISCOVERED DEVICES"** listesinde yeşil renk ve bilgisayar adıyla otomatik olarak belirir.
- **Görünürlük Ayarı:** 
  - `KNOWN PEERS ONLY (VARSAYILAN):` Sadece daha önce izin verdiğiniz cihazlar sizi görür.
  - `EVERYONE (10M):` Yeni bir cihazla eşleşmek için 10 dakikalığına herkese görünür olun.
- **Dosya Gönderme:**
  - Listede hedef bilgisayarın yanındaki **`📁 GÖNDER`** butonuna tıklayın.
  - Açılan pencereden göndermek istediğiniz dosyaları seçin ve onaylayın.
- **Pano Gönderme:**
  - Karşı bilgisayarın yanındaki **`📋 PANO`** butonuna tıklayın. Panonuzdaki metin anında karşı bilgisayarın panosuna (`wl-copy`) kopyalanır.
- **Alıcı Onayı (Gatekeeper):**
  - Karşı taraftan dosya geldiğinde ekranınızda gönderenin adı ve dosya bilgisiyle birlikte masaüstü bildirimi ve panelde **"KABUL ET / REDDET"** seçeneği belirir.
  - Kabul edilen dosyalar doğrudan `~/Downloads/omasend/` klasörüne kaydedilir.

### 2. 📱 Mobil Cihaz ↔ PC Aktarımı (Uygulamasız Web Portalı)
1. Paneli açın ve **🏠 YEREL AĞ (LAN)** modunu seçin.
2. Akıllı telefonunuzun kamerasıyla ekrandaki **QR Kodu** tarayın.
3. Tarayıcıda açılan portal, 4 haneli PIN ve AES-256 şifreleme anahtarını otomatik tanır.
4. **Telefondan PC'ye:** Fotoğraf, video veya belge seçip gönderin; dosyalar `~/Downloads/omasend/` dizinine anında iner.
5. **PC'den Telefona:** Bilgisayarınızda `~/Downloads/omasend/shared/` klasörüne bıraktığınız tüm dosyalar telefondaki web portalında tek tıkla indirilebilir hale gelir.
6. **Pano Eşitleme:** Telefondaki web portalında panoya yazdığınız herhangi bir metin bilgisayarınızın panosuna kopyalanır; bilgisayardaki panonuz da telefona aktarılır.

### 3. 🌐 Dış Ağ / Uzak Transfer (Global WAN Tüneli)
- Farklı Wi-Fi ağlarında veya mobil hücresel bağlantıdayken (4G/5G) paneldeki **"🌐 DIŞ AĞ (WAN)"** seçeneğini seçin.
- `cloudflared` aracılığıyla uçtan uca şifreli küresel bir HTTPS tüneli oluşturulur.
- Dünyanın herhangi bir yerindeki cihazla şifreli dosya ve pano paylaşımı yapabilirsiniz.

---

## 🛡️ Güvenlik ve Mimari Standartlar (`AGENTS.md`)

OmaSend, Omarchy Linux Resmi Güvenlik Standartlarına tam uyumlu olarak tasarlanmıştır:
1. **İzole Süreçler & Deadlines:** Tüm komutlar bağımsız süreç gruplarında (`cmd.process_group(0)`), non-blocking I/O (`fcntl O_NONBLOCK`) ve POSIX `poll()` döngüleriyle çalıştırılır. Yetim veya kilitlenen süreçler RAII `ProcessGroupGuard` ile anında imha edilir.
2. **Sıkı Dosya İzinleri (0600 & 0700):** PIN, oturum anahtarları ve eş listesi umask değerlerine güvenilmeden `0600` izniyle ve atomik geçici dosyalar (`fs::rename`) üzerinden yazılır. Symlink takibi kesinlikle engellenmiştir.
3. **Bellek & Ağ Sınırları:** TCP soketleri üzerinde Slowloris/DoS saldırılarına karşı 15 saniyelik mutlak okuma/yazma zaman aşımları ve 64 KiB başlık sınırı uygulanır.
4. **XSS & Kod Enjeksiyonu Koruması:** QML arayüzünde tüm dinamik çıktılar zorunlu `textFormat: Text.PlainText` ile güvenli kılınmıştır.

---

## 📄 Lisans

Bu proje MIT lisansı ile lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakabilirsiniz.
