.pragma library

var SUPPORTED_LANGS = [
  "tr", "en", "de", "fr", "es", "it", "pt", "ru", "ar", "zh",
  "ja", "ko", "nl", "pl", "uk", "az", "kk", "uz", "fa", "hi", "id"
];

function detectLang(rawEnv, qtLocaleName) {
  var candidates = [rawEnv || "", qtLocaleName || ""];
  for (var i = 0; i < candidates.length; i++) {
    var raw = String(candidates[i]).trim();
    if (!raw || raw === "C" || raw === "C.UTF-8" || raw === "POSIX") continue;
    var base = raw.split(".")[0].split("@")[0].replace(/-/g, "_");
    var lower = base.toLowerCase();
    var primary = lower.split("_")[0];
    if (SUPPORTED_LANGS.indexOf(primary) !== -1) {
      return primary;
    }
  }
  return "en";
}

var DICT = {
  "account_copied": {
    tr: "Hesap numarası kopyalandı",
    en: "Account number copied"
  },
  "account_copy_tooltip": {
    tr: "Numarayı kopyala",
    en: "Copy number"
  },
  "account_hide_tooltip": {
    tr: "Numarayı gizle",
    en: "Hide number"
  },
  "account_number_label": {
    tr: "HESAP NUMARANIZ (OmaID)",
    en: "YOUR ACCOUNT NUMBER (OmaID)"
  },
  "account_show_tooltip": {
    tr: "Numarayı göster",
    en: "Show number"
  },
  "link_btn": {
    tr: "Bağla",
    en: "Link"
  },
  "link_failed": {
    tr: "Bağlanamadı",
    en: "Could not link"
  },
  "link_hint": {
    tr: "Numara ağda gönderilmez, yalnızca bağlantıyı doğrulamak için kullanılır. Kimseyle paylaşmayın: bu numarayı bilen, cihazınızı kendi cihazı gibi bağlayabilir.",
    en: "The number is never sent over the network; it only proves the link. Do not share it: anyone who knows it can link a device as yours."
  },
  "link_instructions": {
    tr: "Kendi cihazlarınızı bağlamak için diğer cihazın hesap numarasını buraya yazın. İki cihaz da aynı ağda ve açık olmalı.",
    en: "To link your own devices, type the other device's account number here. Both devices must be on and on the same network."
  },
  "link_invalid": {
    tr: "Geçersiz numara: 16 haneli OmaID girin.",
    en: "Invalid number: enter the 16-digit OmaID."
  },
  "link_ok": {
    tr: "Bağlandı: %1",
    en: "Linked: %1"
  },
  "link_working": {
    tr: "Bağlanıyor…",
    en: "Linking…"
  },
  "pair_mode_omaid": {
    tr: "OmaID",
    en: "OmaID"
  },
  "pair_mode_qr": {
    tr: "QR kod",
    en: "QR code"
  },
  "add_device": {
    tr: "Cihaz ekle",
    en: "Add device"
  },
  "add_device_sub": {
    tr: "QR ile",
    en: "with QR"
  },
  "badge_own_short": {
    tr: "senin",
    en: "yours"
  },
  "close_btn": {
    tr: "Kapat",
    en: "Close"
  },
  "details_header": {
    tr: "AYRINTILAR",
    en: "DETAILS"
  },
  "hidden_short": {
    tr: "gizli",
    en: "hidden"
  },
  "incoming_encrypted": {
    tr: "Uçtan uca şifreli, eşleşmiş cihazdan",
    en: "End-to-end encrypted, from a paired device"
  },
  "incoming_not_encrypted": {
    tr: "Şifresiz, eşleşmemiş cihaz. Beklemiyorsanız reddedin.",
    en: "Not encrypted, unpaired device. Decline if you did not expect it."
  },
  "incoming_wants_to_share": {
    tr: "%1 paylaşmak istiyor",
    en: "%1 wants to share"
  },
  "nearby_unencrypted_header": {
    tr: "YAKINDAKİLER · ŞİFRESİZ (%1)",
    en: "NEARBY · NOT ENCRYPTED (%1)"
  },
  "security_blocked_title": {
    tr: "ENGELLİ",
    en: "BLOCKED"
  },
  "security_off_sub": {
    tr: "Görünmez, dosya alınmıyor.",
    en: "Invisible and not receiving."
  },
  "security_off_title": {
    tr: "KAPALI",
    en: "OFF"
  },
  "security_secure_sub": {
    tr: "Uçtan uca şifreli · %1/%2 cihazınız çevrimiçi",
    en: "End-to-end encrypted · %1 of %2 devices online"
  },
  "security_secure_sub_empty": {
    tr: "Uçtan uca şifreli · henüz eşleşmiş cihaz yok",
    en: "End-to-end encrypted · no paired devices yet"
  },
  "security_secure_title": {
    tr: "GÜVENLİ",
    en: "SECURE"
  },
  "send_empty_hint": {
    tr: "Telefonunuzu eklemek için Cihaz ekle'ye tıklayın. Eşleşmiş cihazlar arasında her şey uçtan uca şifrelidir.",
    en: "Click Add device to pair your phone. Everything between paired devices is end-to-end encrypted."
  },
  "send_hint": {
    tr: "Dosya seçmek için cihaza tıklayın, sağ tık panoyu gönderir.",
    en: "Click a device to pick files. Right-click sends the clipboard."
  },
  "send_hint_default": {
    tr: "Dosyaları bar ikonuna bırakın, %1 cihazına gider.",
    en: "Drop files on the bar icon to send them to %1."
  },
  "send_to_header": {
    tr: "GÖNDER",
    en: "SEND TO"
  },
  "tile_unpair_armed": {
    tr: "tekrar × ile kaldır",
    en: "× again to remove"
  },
  "visible_to_your_devices": {
    tr: "cihazlarınıza görünür",
    en: "visible to your devices"
  },
  "about_line": {
    tr: "OmaSend · QR ile eşleştirilen cihazlar arasında uçtan uca şifreli (QUIC · TLS 1.3, UDP 53318). Eşleştirilmemiş cihazlarla şifresiz HTTP (53317), her aktarım onay ister. MIT lisanslı.",
    en: "OmaSend · end-to-end encrypted between QR-paired devices (QUIC · TLS 1.3, UDP 53318). Unpaired devices use unencrypted HTTP (53317) and every transfer needs approval. MIT licensed."
  },
  "about_tooltip": {
    tr: "OmaSend Hakkında ve Sistem Bilgisi",
    en: "About OmaSend & System Info",
    de: "Über OmaSend & Systeminfo",
    fr: "À propos d'OmaSend et infos système",
    es: "Acerca de OmaSend e información del sistema",
    it: "Informazioni su OmaSend e sistema",
    pt: "Sobre o OmaSend e informações do sistema",
    ru: "Об OmaSend и сведения о системе",
    ar: "حول OmaSend ومعلومات النظام",
    zh: "关于 OmaSend 与系统信息",
    ja: "OmaSend について・システム情報",
    ko: "OmaSend 정보 및 시스템 정보",
    nl: "Over OmaSend & systeeminformatie",
    pl: "O programie OmaSend i informacje o systemie",
    uk: "Про OmaSend та інформація про систему",
    az: "OmaSend Haqqında və Sistem Məlumatı",
    kk: "OmaSend туралы және жүйе ақпараты",
    uz: "OmaSend haqida va tizim ma'lumoti",
    fa: "درباره OmaSend و اطلاعات سیستم",
    hi: "OmaSend के बारे में और सिस्टम जानकारी",
    id: "Tentang OmaSend & Info Sistem"
  },
  "accept_btn": {
    tr: "Kabul Et",
    en: "Accept",
    de: "Annehmen",
    fr: "Accepter",
    es: "Aceptar",
    it: "Accetta",
    pt: "Aceitar",
    ru: "Принять",
    ar: "قبول",
    zh: "接受",
    ja: "承認",
    ko: "수락",
    nl: "Accepteren",
    pl: "Akceptuj",
    uk: "Прийняти",
    az: "Qəbul Et",
    kk: "Қабылдау",
    uz: "Qabul qilish",
    fa: "پذیرش",
    hi: "स्वीकार करें",
    id: "Terima"
  },
  "active_transfer_header": {
    tr: "Aktif Dosya Aktarımı",
    en: "Active File Transfer",
    de: "Aktive Dateiübertragung",
    fr: "Transfert de fichiers actif",
    es: "Transferencia activa",
    it: "Trasferimento attivo",
    pt: "Transferência ativa",
    ru: "Активная передача",
    ar: "نقل الملفات النشط",
    zh: "正在传输文件",
    ja: "アクティブな転送",
    ko: "활성 파일 전송",
    nl: "Actieve bestandsoverdracht",
    pl: "Aktywny transfer plików",
    uk: "Активна передача файлів",
    az: "Aktiv Fayl Köçürməsi",
    kk: "Белсенді файл тасымалдау",
    uz: "Faol fayl uzatish",
    fa: "انتقال فایل فعال",
    hi: "सक्रिय फ़ाइल स्थानांतरण",
    id: "Transfer File Aktif"
  },
  "badge_own": {
    tr: "SENİN",
    en: "YOURS"
  },
  "badge_paired": {
    tr: "EŞLEŞMİŞ",
    en: "PAIRED"
  },
  "cancel_btn": {
    tr: "Aktarımı İptal Et",
    en: "Cancel Transfer",
    de: "Übertragung abbrechen",
    fr: "Annuler le transfert",
    es: "Cancelar transferencia",
    it: "Annulla trasferimento",
    pt: "Cancelar transferência",
    ru: "Отменить передачу",
    ar: "إلغاء النقل",
    zh: "取消传输",
    ja: "転送をキャンセル",
    ko: "전송 취소",
    nl: "Overdracht annuleren",
    pl: "Anuluj transfer",
    uk: "Скасувати передачу",
    az: "Köçürməni Ləğv Et",
    kk: "Тасымалдауды болдырмау",
    uz: "Uzatishni bekor qilish",
    fa: "لغو انتقال",
    hi: "स्थानांतरण रद्द करें",
    id: "Batalkan Transfer"
  },
  "copy_ip_tooltip": {
    tr: "IP Adresini Kopyala",
    en: "Copy IP Address",
    de: "IP-Adresse kopieren",
    fr: "Copier l'adresse IP",
    es: "Copiar dirección IP",
    it: "Copia indirizzo IP",
    pt: "Copiar endereço IP",
    ru: "Скопировать IP-адрес",
    ar: "نسخ عنوان IP",
    zh: "复制 IP 地址",
    ja: "IP アドレスをコピー",
    ko: "IP 주소 복사",
    nl: "IP-adres kopiëren",
    pl: "Kopiuj adres IP",
    uk: "Скопіювати IP-адресу",
    az: "IP Ünvanını Kopyala",
    kk: "IP мекенжайын көшіру",
    uz: "IP manzilni nusxalash",
    fa: "کپی نشانی IP",
    hi: "IP पता कॉपी करें",
    id: "Salin Alamat IP"
  },
  "downloads_footer": {
    tr: "İndirilenler",
    en: "Downloads",
    de: "Downloads",
    fr: "Téléchargements",
    es: "Descargas",
    it: "Scaricati",
    pt: "Downloads",
    ru: "Загрузки",
    ar: "التنزيلات",
    zh: "下载",
    ja: "ダウンロード",
    ko: "다운로드",
    nl: "Downloads",
    pl: "Pobrane",
    uk: "Завантаження",
    az: "Yükləmələr",
    kk: "Жүктеулер",
    uz: "Yuklanmalar",
    fa: "دریافت‌ها",
    hi: "डाउनलोड",
    id: "Unduhan"
  },
  "drop_choose_target": {
    tr: "Hedef seçilmedi: paneli açıp cihaz seçin",
    en: "No target: open the panel and pick a device"
  },
  "drop_encrypted_hint": {
    tr: "Bırakın: uçtan uca şifreli gönderilir",
    en: "Drop to send, end-to-end encrypted"
  },
  "drop_here_hint": {
    tr: "Göndermek için buraya veya ikona bırakın",
    en: "Drop here or on the icon to send",
    de: "Zum Senden hier oder auf dem Symbol ablegen",
    fr: "Déposez ici ou sur l'icône pour envoyer",
    es: "Suelta aquí o en el icono para enviar",
    it: "Rilascia qui o sull'icona per inviare",
    pt: "Solte aqui ou no ícone para enviar",
    ru: "Перетащите сюда или на значок для отправки",
    ar: "أفلت هنا أو على الأيقونة للإرسال",
    zh: "拖放到此处或图标上即可发送",
    ja: "ここまたはアイコンにドロップして送信",
    ko: "여기에 또는 아이콘에 놓아 전송",
    nl: "Zet hier of op het pictogram neer om te verzenden",
    pl: "Upuść tutaj lub na ikonę, aby wysłać",
    uk: "Перетягніть сюди або на значок, щоб надіслати",
    az: "Göndərmək üçün bura və ya ikona buraxın",
    kk: "Жіберу үшін осында немесе белгішеге тастаңыз",
    uz: "Yuborish uchun shu yerga yoki belgiga tashlang",
    fa: "برای ارسال اینجا یا روی آیکون رها کنید",
    hi: "भेजने के लिए यहाँ या आइकन पर छोड़ें",
    id: "Lepaskan di sini atau pada ikon untuk mengirim"
  },
  "drop_transfer_started": {
    tr: "AKTARIM BAŞLATILDI",
    en: "TRANSFER STARTED",
    de: "ÜBERTRAGUNG GESTARTET",
    fr: "TRANSFERT DÉMARRÉ",
    es: "TRANSFERENCIA INICIADA",
    it: "TRASFERIMENTO AVVIATO",
    pt: "TRANSFERÊNCIA INICIADA",
    ru: "ПЕРЕДАЧА НАЧАТА",
    ar: "بدأ النقل",
    zh: "传输已开始",
    ja: "転送を開始しました",
    ko: "전송 시작됨",
    nl: "OVERDRACHT GESTART",
    pl: "ROZPOCZĘTO TRANSFER",
    uk: "ПЕРЕДАЧУ РОЗПОЧАТО",
    az: "KÖÇÜRMƏ BAŞLADI",
    kk: "ТАСЫМАЛДАУ БАСТАЛДЫ",
    uz: "O'TKAZMA BOSHLANDI",
    fa: "انتقال آغاز شد",
    hi: "ट्रांसफ़र शुरू हुआ",
    id: "TRANSFER DIMULAI"
  },
  "encrypted": {
    tr: "şifreli",
    en: "encrypted"
  },
  "files_unit": {
    tr: "dosya",
    en: "files",
    de: "Dateien",
    fr: "fichiers",
    es: "archivos",
    it: "file",
    pt: "arquivos",
    ru: "файлов",
    ar: "ملفات",
    zh: "个文件",
    ja: "ファイル",
    ko: "개 파일",
    nl: "bestanden",
    pl: "plików",
    uk: "файлів",
    az: "fayl",
    kk: "файл",
    uz: "fayl",
    fa: "فایل",
    hi: "फ़ाइलें",
    id: "file"
  },
  "firewall_warning_label": {
    tr: "Güvenlik duvarı OmaSend'i engelliyor olabilir: ufw allow 53317 ve ufw allow 53318/udp",
    en: "A firewall may block OmaSend: ufw allow 53317 and ufw allow 53318/udp"
  },
  "hero_sub_on": {
    tr: "ŞİFRELİ AKTARIM · %1 CİHAZ ÇEVRİMİÇİ",
    en: "ENCRYPTED TRANSFER · %1 DEVICES ONLINE"
  },
  "incoming_transfer_header": {
    tr: "GELEN AKTARIM ONAYI",
    en: "INCOMING TRANSFER"
  },
  "label_device_id": {
    tr: "Cihaz ID",
    en: "Device ID",
    de: "Geräte-ID",
    fr: "ID Appareil",
    es: "ID Dispositivo",
    it: "ID Dispositivo",
    pt: "ID Dispositivo",
    ru: "ID Устройства",
    ar: "معرّف الجهاز",
    zh: "设备 ID",
    ja: "デバイス ID",
    ko: "기기 ID",
    nl: "Apparaat-ID",
    pl: "ID Urządzenia",
    uk: "ID Пристрою",
    az: "Cihaz ID",
    kk: "Құрылғы ID",
    uz: "Qurilma ID",
    fa: "شناسه دستگاه",
    hi: "डिवाइस ID",
    id: "ID Perangkat"
  },
  "label_ip_address": {
    tr: "IP Adresi",
    en: "IP Address",
    de: "IP-Adresse",
    fr: "Adresse IP",
    es: "Dirección IP",
    it: "Indirizzo IP",
    pt: "Endereço IP",
    ru: "IP-адрес",
    ar: "عنوان IP",
    zh: "IP 地址",
    ja: "IP アドレス",
    ko: "IP 주소",
    nl: "IP-adres",
    pl: "Adres IP",
    uk: "IP-адреса",
    az: "IP Ünvanı",
    kk: "IP мекенжайы",
    uz: "IP manzil",
    fa: "نشانی IP",
    hi: "IP पता",
    id: "Alamat IP"
  },
  "label_paired": {
    tr: "Eşleşmiş",
    en: "Paired"
  },
  "label_received": {
    tr: "Alınan",
    en: "Received",
    de: "Empfangen",
    fr: "Reçus",
    es: "Recibidos",
    it: "Ricevuti",
    pt: "Recebidos",
    ru: "Получено",
    ar: "المستلمة",
    zh: "已接收",
    ja: "受信済み",
    ko: "수신됨",
    nl: "Ontvangen",
    pl: "Odebrane",
    uk: "Отримано",
    az: "Qəbul edilən",
    kk: "Қабылданған",
    uz: "Qabul qilingan",
    fa: "دریافت‌شده",
    hi: "प्राप्त",
    id: "Diterima"
  },
  "my_devices_header": {
    tr: "CİHAZLARIM",
    en: "MY DEVICES"
  },
  "nearby_empty": {
    tr: "Yakında başka OmaSend bulunamadı.",
    en: "No other OmaSend found nearby."
  },
  "nearby_footnote": {
    tr: "Eşleştirilmemiş cihazlarla aktarım şifresizdir ve onay ister. Yalnızca güvendiğiniz ağlarda kullanın.",
    en: "Transfers with unpaired devices are not encrypted and need approval. Use them only on networks you trust."
  },
  "nearby_header": {
    tr: "YAKINDAKİLER",
    en: "NEARBY"
  },
  "needs_approval": {
    tr: "şifresiz · onaylı",
    en: "unencrypted · needs approval"
  },
  "no_paired_devices": {
    tr: "Henüz eşleşmiş cihaz yok. QR simgesine tıklayın ve telefonda OmaSend → Cihaz eşleştir → QR kodu tara.",
    en: "No paired devices yet. Click the QR icon, then on your phone: OmaSend → Pair a device → Scan QR code."
  },
  "not_encrypted": {
    tr: "şifresiz",
    en: "not encrypted"
  },
  "not_seen": {
    tr: "görünmüyor",
    en: "not seen"
  },
  "online": {
    tr: "çevrimiçi",
    en: "online"
  },
  "open_downloads_tooltip": {
    tr: "İndirilenler Klasörünü Aç",
    en: "Open Downloads Folder",
    de: "Download-Ordner öffnen",
    fr: "Ouvrir le dossier Téléchargements",
    es: "Abrir carpeta de descargas",
    it: "Apri cartella Scaricati",
    pt: "Abrir pasta de downloads",
    ru: "Открыть папку загрузок",
    ar: "فتح مجلد التنزيلات",
    zh: "打开下载文件夹",
    ja: "ダウンロードフォルダを開く",
    ko: "다운로드 폴더 열기",
    nl: "Map Downloads openen",
    pl: "Otwórz folder Pobrane",
    uk: "Відкрити папку завантажень",
    az: "Yükləmələr Qovluğunu Aç",
    kk: "Жүктеулер бумасын ашу",
    uz: "Yuklanmalar jildini ochish",
    fa: "باز کردن پوشه دریافت‌ها",
    hi: "डाउनलोड फ़ोल्डर खोलें",
    id: "Buka Folder Unduhan"
  },
  "pair_connecting": {
    tr: "Ekrandaki eşleşme kodu bulundu, bağlanılıyor…",
    en: "Pairing code found on screen, connecting…"
  },
  "pair_expires": {
    tr: "%1 sn geçerli · tek kullanımlık",
    en: "Valid for %1 s · single use"
  },
  "pair_failed": {
    tr: "Eşleşme başarısız",
    en: "Pairing failed"
  },
  "pair_instructions": {
    tr: "Telefonda OmaSend → Cihaz eşleştir → QR kodu tara",
    en: "On your phone: OmaSend → Pair a device → Scan QR code"
  },
  "pair_no_qr_on_screen": {
    tr: "Ekranda OmaSend eşleşme kodu bulunamadı.",
    en: "No OmaSend pairing code found on screen."
  },
  "pair_other": {
    tr: "Başkasının",
    en: "Someone else's"
  },
  "pair_other_hint": {
    tr: "Bu cihazdan gelen her aktarım onay ister; pano eşitlenmez.",
    en: "Every transfer from that device needs approval; the clipboard is not synced."
  },
  "pair_own": {
    tr: "Benim cihazım",
    en: "My device"
  },
  "pair_own_hint": {
    tr: "Kendi cihazınız: aktarımlar otomatik kabul edilir, pano otomatik eşitlenir.",
    en: "Your own device: transfers are accepted automatically and the clipboard syncs."
  },
  "pair_qr_failed": {
    tr: "Eşleşme kodu oluşturulamadı.",
    en: "Could not create a pairing code."
  },
  "pair_scan_screen_tooltip": {
    tr: "Ekrandaki eşleşme QR'ını oku (başka bir masaüstü)",
    en: "Read a pairing QR shown on screen (another desktop)"
  },
  "pair_scanning_screen": {
    tr: "Ekran taranıyor…",
    en: "Scanning the screen…"
  },
  "pair_title": {
    tr: "CİHAZ EŞLEŞTİR",
    en: "PAIR A DEVICE"
  },
  "pair_tooltip": {
    tr: "Cihaz eşleştir (QR)",
    en: "Pair a device (QR)"
  },
  "paired_ok": {
    tr: "Eşleşme tamamlandı",
    en: "Paired"
  },
  "paired_with": {
    tr: "Eşleşti: %1",
    en: "Paired with %1"
  },
  "refresh_scan_tooltip": {
    tr: "Cihaz Taramasını Yenile",
    en: "Refresh Device Scan",
    de: "Gerätesuche aktualisieren",
    fr: "Actualiser l'analyse des appareils",
    es: "Actualizar búsqueda de dispositivos",
    it: "Aggiorna scansione dispositivi",
    pt: "Atualizar busca de dispositivos",
    ru: "Обновить поиск устройств",
    ar: "تحديث البحث عن الأجهزة",
    zh: "刷新设备扫描",
    ja: "デバイススキャンを更新",
    ko: "기기 스캔 새로고침",
    nl: "Apparaatscan vernieuwen",
    pl: "Odśwież skanowanie urządzeń",
    uk: "Оновити сканування пристроїв",
    az: "Cihaz Axtarışını Yenilə",
    kk: "Құрылғыларды іздеуді жаңарту",
    uz: "Qurilmalar qidiruvini yangilash",
    fa: "بازخوانی اسکن دستگاه‌ها",
    hi: "डिवाइस स्कैन रीफ़्रेश करें",
    id: "Muat Ulang Pemindaian Perangkat"
  },
  "reject_btn": {
    tr: "Reddet",
    en: "Decline",
    de: "Ablehnen",
    fr: "Refuser",
    es: "Rechazar",
    it: "Rifiuta",
    pt: "Recusar",
    ru: "Отклонить",
    ar: "رفض",
    zh: "拒绝",
    ja: "拒否",
    ko: "거절",
    nl: "Weigeren",
    pl: "Odrzuć",
    uk: "Відхилити",
    az: "Rədd Et",
    kk: "Қабылдамау",
    uz: "Rad etish",
    fa: "رد کردن",
    hi: "अस्वीकार करें",
    id: "Tolak"
  },
  "send_clipboard_tooltip": {
    tr: "Panoyu gönder (şifreli)",
    en: "Send clipboard (encrypted)"
  },
  "sending_files": {
    tr: "dosya gönderiliyor...",
    en: "files sending...",
    de: "Dateien werden gesendet...",
    fr: "fichiers en cours d'envoi...",
    es: "enviando archivos...",
    it: "invio file in corso...",
    pt: "enviando arquivos...",
    ru: "отправка файлов...",
    ar: "جارٍ إرسال الملفات...",
    zh: "个文件正在发送...",
    ja: "ファイルを送信中...",
    ko: "개 파일 전송 중...",
    nl: "bestanden verzenden...",
    pl: "wysyłanie plików...",
    uk: "надсилання файлів...",
    az: "fayl göndərilir...",
    kk: "файл жіберілуде...",
    uz: "fayl yuborilmoqda...",
    fa: "فایل در حال ارسال...",
    hi: "फ़ाइलें भेजी जा रही हैं...",
    id: "file sedang dikirim..."
  },
  "service_disabled_sub": {
    tr: "SERVİS DEVRE DIŞI",
    en: "SERVICE DISABLED",
    de: "DIENST DEAKTIVIERT",
    fr: "SERVICE DÉSACTIVÉ",
    es: "SERVICIO DESACTIVADO",
    it: "SERVIZIO DISATTIVATO",
    pt: "SERVIÇO DESATIVADO",
    ru: "СЛУЖБА ОТКЛЮЧЕНА",
    ar: "الخدمة معطلة",
    zh: "服务已禁用",
    ja: "サービス無効",
    ko: "서비스 비활성화됨",
    nl: "SERVICE UITGESCHAKELD",
    pl: "USŁUGA WYŁĄCZONA",
    uk: "СЛУЖБУ ВИМКНЕНО",
    az: "XİDMƏT DEAKTİVDİR",
    kk: "ҚЫЗМЕТ ӨШІРІЛГЕН",
    uz: "XIZMAT O'CHIRILGAN",
    fa: "سرویس غیرفعال است",
    hi: "सेवा निष्क्रिय है",
    id: "LAYANAN DINONAKTIFKAN"
  },
  "sound_off_tooltip": {
    tr: "Ses efektleri kapalı (Açmak için tıkla)",
    en: "Sound effects muted (Click to unmute)",
    de: "Soundeffekte stumm (Klicken zum Aktivieren)",
    fr: "Effets sonores coupés (Cliquer pour activer)",
    es: "Efectos de sonido silenciados (Clic para activar)",
    it: "Effetti sonori disattivati (Clic per attivare)",
    pt: "Efeitos sonoros silenciados (Clique para ativar)",
    ru: "Звуковые эффекты выключены (Нажмите, чтобы включить)",
    ar: "المؤثرات الصوتية مكتومة",
    zh: "音效已静音（点击开启）",
    ja: "効果音ミュート（クリックでオン）",
    ko: "효과음 꺼짐 (클릭하여 켜기)",
    nl: "Geluidseffecten gedempt (Klik om in te schakelen)",
    pl: "Efekty dźwiękowe wyciszone (Kliknij, aby włączyć)",
    uk: "Звукові ефекти вимкнено",
    az: "Səs effektləri bağlıdır",
    kk: "Дыбыс әсерлері өшірулі",
    uz: "Ovoz effektlari o'chirilgan",
    fa: "جلوه‌های صوتی بی‌صدا است",
    hi: "ध्वनि प्रभाव बंद हैं",
    id: "Efek suara dibisukan"
  },
  "sound_on_tooltip": {
    tr: "Ses efektleri açık (Kapatmak için tıkla)",
    en: "Sound effects enabled (Click to mute)",
    de: "Soundeffekte aktiv (Klicken zum Stummschalten)",
    fr: "Effets sonores activés (Cliquer pour couper)",
    es: "Efectos de sonido activados (Clic para silenciar)",
    it: "Effetti sonori attivi (Clic per disattivare)",
    pt: "Efeitos sonoros ativados (Clique para silenciar)",
    ru: "Звуковые эффекты включены (Нажмите, чтобы выключить)",
    ar: "المؤثرات الصوتية مفعلة",
    zh: "音效已开启（点击静音）",
    ja: "効果音オン（クリックでミュート）",
    ko: "효과음 켜짐 (클릭하여 음소거)",
    nl: "Geluidseffecten aan (Klik om te dempen)",
    pl: "Efekty dźwiękowe włączone (Kliknij, aby wyciszyć)",
    uk: "Звукові ефекти увімкнено",
    az: "Səs effektləri açıqdır",
    kk: "Дыбыс әсерлері қосулы",
    uz: "Ovoz effektlari yoqilgan",
    fa: "جلوه‌های صوتی فعال است",
    hi: "ध्वनि प्रभाव चालू हैं",
    id: "Efek suara aktif"
  },
  "tooltip_devices": {
    tr: "%1/%2 cihaz çevrimiçi",
    en: "%1/%2 devices online"
  },
  "turn_off_service": {
    tr: "OmaSend servisini kapat",
    en: "Turn off OmaSend service",
    de: "OmaSend-Dienst ausschalten",
    fr: "Désactiver le service OmaSend",
    es: "Desactivar servicio OmaSend",
    it: "Disattiva servizio OmaSend",
    pt: "Desativar serviço OmaSend",
    ru: "Отключить службу OmaSend",
    ar: "إيقاف خدمة OmaSend",
    zh: "关闭 OmaSend 服务",
    ja: "OmaSend サービスをオフにする",
    ko: "OmaSend 서비스 끄기",
    nl: "OmaSend-service uitschakelen",
    pl: "Wyłącz usługę OmaSend",
    uk: "Вимкнути службу OmaSend",
    az: "OmaSend xidmətini bağla",
    kk: "OmaSend қызметін өшіру",
    uz: "OmaSend xizmatini o'chirish",
    fa: "خاموش کردن سرویس OmaSend",
    hi: "OmaSend सेवा बंद करें",
    id: "Matikan layanan OmaSend"
  },
  "turn_on_service": {
    tr: "OmaSend servisini aç",
    en: "Turn on OmaSend service",
    de: "OmaSend-Dienst einschalten",
    fr: "Activer le service OmaSend",
    es: "Activar servicio OmaSend",
    it: "Attiva servizio OmaSend",
    pt: "Ativar serviço OmaSend",
    ru: "Включить службу OmaSend",
    ar: "تشغيل خدمة OmaSend",
    zh: "开启 OmaSend 服务",
    ja: "OmaSend サービスをオンにする",
    ko: "OmaSend 서비스 켜기",
    nl: "OmaSend-service inschakelen",
    pl: "Włącz usługę OmaSend",
    uk: "Увімкнути службу OmaSend",
    az: "OmaSend xidmətini aç",
    kk: "OmaSend қызметін қосу",
    uz: "OmaSend xizmatini yoqish",
    fa: "روشن کردن سرویس OmaSend",
    hi: "OmaSend सेवा चालू करें",
    id: "Nyalakan layanan OmaSend"
  },
  "unpair_armed": {
    tr: "Eşleşmeyi kaldırmak için tekrar tıklayın",
    en: "Click again to remove the pairing"
  },
  "unpair_confirm_tooltip": {
    tr: "Onayla: eşleşmeyi kaldır",
    en: "Confirm: remove pairing"
  },
  "unpair_tooltip": {
    tr: "Eşleşmeyi kaldır",
    en: "Remove pairing"
  }
};

function tr(lang, key) {
  var entry = DICT[key];
  if (!entry) return key;
  var l = lang || "en";
  if (entry[l] !== undefined) return entry[l];
  if (entry["en"] !== undefined) return entry["en"];
  if (entry["tr"] !== undefined) return entry["tr"];
  return key;
}
