import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import "theme"

Rectangle {
    id: root
    color: Theme.bgBase

    property string localIp: "127.0.0.1"
    property int port: 53317
    property string pin: "----"
    property string sessionKey: ""
    property string activeMode: "LAN"
    property string visibility: "KNOWN"
    property int visibilityRemainingSecs: 0
    property string qrPath: ""
    property string omaidQrPath: ""
    property string savePath: "~/Downloads/omasend"
    property int totalReceived: 0
    property string omaId: ""
    property bool omaIdRevealed: true
    property bool omaIdCopied: false
    property string syncInputOmaId: ""
    property bool showSyncBox: false
    property bool showQrBox: false
    property bool showInfoBox: false
    property string directTargetInput: ""
    property string statusMsg: ""
    property bool statusError: false
    property var peers: []
    property var recentFiles: []
    property var pendingTransfer: null
    property var transferProgress: null
    property bool soundEnabled: true
    property bool isRefreshing: false
    property int refreshNonce: 0

    property string pluginVersion: "1.9.1"
    property string pluginDescription: "OmaSend OmaID & AirBridge P2P Dosya Aktarım Sistemi"
    property string pluginAuthor: "Ozan Özdil (@ozdil)"
    property string pluginLicense: "MIT"

    readonly property var ownPeers: {
        if (root.visibility === "OFF" || !root.peers) return [];
        var myClean = String(root.omaId || "").replace(/[^0-9]/g, "");
        var out = [];
        for (var i = 0; i < root.peers.length; i++) {
            var p = root.peers[i];
            if (!p) continue;
            var pClean = String(p.oma_id || "").replace(/[^0-9]/g, "");
            var sameOwner = Boolean(p.is_same_owner) || (myClean.length === 16 && pClean === myClean);
            if (sameOwner) out.push(p);
        }
        return out;
    }

    readonly property var otherPeers: {
        if (root.visibility === "OFF" || !root.peers) return [];
        var myClean = String(root.omaId || "").replace(/[^0-9]/g, "");
        var out = [];
        for (var i = 0; i < root.peers.length; i++) {
            var p = root.peers[i];
            if (!p) continue;
            var pClean = String(p.oma_id || "").replace(/[^0-9]/g, "");
            var sameOwner = Boolean(p.is_same_owner) || (myClean.length === 16 && pClean === myClean);
            if (!sameOwner) out.push(p);
        }
        return out;
    }

    function formatOmaId(id, revealed) {
        if (!id || String(id).trim() === "") return "---- ---- ---- ----";
        var clean = String(id).replace(/[^0-9]/g, "");
        if (!revealed) {
            if (clean.length >= 16) return "••••-••••-••••-" + clean.slice(12, 16);
            return "••••-••••-••••-••••";
        }
        if (clean.length === 16) {
            return clean.slice(0, 4) + "-" + clean.slice(4, 8) + "-" + clean.slice(8, 12) + "-" + clean.slice(12, 16);
        }
        return clean;
    }

    function formatInputOmaId(val) {
        if (!val) return "";
        var clean = String(val).replace(/[^0-9]/g, "").slice(0, 16);
        var parts = [];
        for (var i = 0; i < clean.length; i += 4) {
            parts.push(clean.slice(i, i + 4));
        }
        return parts.join("-");
    }

    function isValidLuhnOmaId(val) {
        var clean = String(val || "").replace(/[^0-9]/g, "");
        if (clean.length !== 16) return false;
        var sum = 0;
        for (var i = 0; i < 16; i++) {
            var d = parseInt(clean.charAt(15 - i), 10);
            if (isNaN(d)) return false;
            if (i % 2 === 1) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
        }
        return (sum % 10) === 0;
    }

    function resolveEnginePath() {
        var home = Quickshell.env("HOME") || "";
        return home ? (home + "/.local/bin/omasend-engine") : Qt.resolvedUrl("../omasend-engine").toString().replace(/^file:\/\//, "");
    }

    function refreshStatus() {
        if (!statusProc.running) {
            isRefreshing = true;
            statusProc.running = true;
        }
    }

    Timer {
        interval: 2000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: root.refreshStatus()
    }

    Timer {
        id: copyFeedbackTimer
        interval: 1800
        repeat: false
        onTriggered: root.omaIdCopied = false
    }

    Process {
        id: statusProc
        command: [root.resolveEnginePath(), "--json"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                statusProc.running = false;
                root.isRefreshing = false;
                var raw = String(text || "").trim();
                if (!raw) return;
                try {
                    var s = JSON.parse(raw);
                    if (s.local_ip) root.localIp = s.local_ip;
                    if (s.port) root.port = s.port;
                    if (s.pin) root.pin = s.pin;
                    if (s.session_key) root.sessionKey = s.session_key;
                    if (s.active_mode) root.activeMode = s.active_mode;
                    if (s.download_dir) root.savePath = s.download_dir;
                    if (s.total_received !== undefined) root.totalReceived = Number(s.total_received) || 0;
                    if (s.omaid_qr_path) root.omaidQrPath = s.omaid_qr_path;
                    if (s.p2p_visibility) root.visibility = s.p2p_visibility;
                    if (s.p2p_visibility_remaining_secs !== undefined) root.visibilityRemainingSecs = s.p2p_visibility_remaining_secs;
                    if (s.p2p_discovered_peers) root.peers = s.p2p_discovered_peers;
                    else if (s.p2p_peers) root.peers = s.p2p_peers;
                    root.pendingTransfer = s.p2p_pending_transfer || null;
                    root.transferProgress = s.p2p_transfer_progress || null;
                    if (s.sound_enabled !== undefined) root.soundEnabled = Boolean(s.sound_enabled);
                    if (s.recent_files) root.recentFiles = s.recent_files;
                    if (s.oma_id) root.omaId = s.oma_id;
                    root.refreshNonce++;
                } catch(e) {}
            }
        }
    }

    Process {
        id: actionProc
        onExited: {
            actionProc.running = false;
            root.refreshStatus();
        }
    }

    Process {
        id: copyProc
    }

    Process {
        id: folderProc
    }

    Process {
        id: pasteProc
        property string targetMode: "direct"
        command: ["wl-paste", "--no-newline"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                pasteProc.running = false;
                var raw = String(text || "").trim();
                if (!raw) return;
                var clean = raw.replace(/[^0-9]/g, "");
                if (pasteProc.targetMode === "sync") {
                    if (clean.length >= 16) {
                        root.syncInputOmaId = root.formatInputOmaId(clean.slice(0, 16));
                        root.statusMsg = "Panodan OmaID aktarıldı.";
                        root.statusError = false;
                    } else {
                        root.statusMsg = "Panoda 16 haneli OmaID bulunamadı.";
                        root.statusError = true;
                    }
                } else {
                    if (clean.length === 16) {
                        root.directTargetInput = root.formatInputOmaId(clean);
                    } else {
                        root.directTargetInput = raw.slice(0, 24);
                    }
                }
            }
        }
    }

    Process {
        id: screenScanProc
        property bool forSync: false
        command: ["bash", "-c", "rm -f /tmp/oma_qr_scan.png && /usr/bin/grim /tmp/oma_qr_scan.png 2>/dev/null && (/usr/bin/zbarimg -q --raw /tmp/oma_qr_scan.png 2>/dev/null || true) && rm -f /tmp/oma_qr_scan.png"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                screenScanProc.running = false;
                var raw = String(text || "").trim();
                var clean = raw.replace(/[^0-9]/g, "");
                if (clean.length >= 16) {
                    var formatted = root.formatInputOmaId(clean.slice(0, 16));
                    if (screenScanProc.forSync) {
                        root.syncInputOmaId = formatted;
                    } else {
                        root.directTargetInput = formatted;
                    }
                    root.statusMsg = "Ekrandan QR OmaID okundu: " + formatted;
                    root.statusError = false;
                } else {
                    root.statusMsg = "Ekranda 16 haneli OmaID QR kodu bulunamadı.";
                    root.statusError = true;
                }
            }
        }
    }

    Process {
        id: newOmaIdProc
        command: [root.resolveEnginePath(), "--new-oma-id"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                newOmaIdProc.running = false;
                var val = String(text || "").trim();
                if (val.length >= 16) {
                    root.omaId = val;
                    root.syncInputOmaId = root.formatInputOmaId(val);
                    root.statusMsg = "Yeni anonim OmaID üretildi: " + root.formatOmaId(val, true);
                    root.statusError = false;
                    root.refreshStatus();
                }
            }
        }
    }

    Process {
        id: syncOwnProc
        property string targetFormatted: ""
        onExited: function(code) {
            syncOwnProc.running = false;
            if (code === 0) {
                root.omaId = syncOwnProc.targetFormatted;
                root.showSyncBox = false;
                root.statusMsg = "OmaID kimliği eşitlendi: " + syncOwnProc.targetFormatted;
                root.statusError = false;
                root.refreshStatus();
            } else {
                root.statusMsg = "OmaID kaydedilemedi.";
                root.statusError = true;
            }
        }
    }

    function runEngineAction(args) {
        if (actionProc.running) actionProc.running = false;
        actionProc.command = [root.resolveEnginePath()].concat(args);
        actionProc.running = true;
    }

    function applyOwnOmaId(candidate) {
        var clean = String(candidate || "").replace(/[^0-9]/g, "");
        if (!root.isValidLuhnOmaId(clean)) {
            root.statusMsg = "Geçersiz 16 haneli OmaID (Luhn doğrulaması başarısız).";
            root.statusError = true;
            return;
        }
        var formatted = root.formatOmaId(clean, true);
        if (syncOwnProc.running) syncOwnProc.running = false;
        syncOwnProc.targetFormatted = formatted;
        syncOwnProc.command = [root.resolveEnginePath(), "--set-oma-id", formatted];
        syncOwnProc.running = true;
    }

    function sendDirectTarget(targetStr) {
        var trimmed = String(targetStr || "").trim();
        if (trimmed === "") {
            root.statusMsg = "16 haneli OmaID veya IP adresi girin.";
            root.statusError = true;
            return;
        }
        var digitsOnly = trimmed.replace(/[^0-9]/g, "");
        var isIp = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(trimmed);
        if (!isIp && digitsOnly.length === 16) {
            if (!root.isValidLuhnOmaId(digitsOnly)) {
                root.statusMsg = "Geçersiz 16 haneli OmaID (Luhn hatası).";
                root.statusError = true;
                return;
            }
            trimmed = root.formatOmaId(digitsOnly, true);
        } else if (!isIp) {
            root.statusMsg = "Geçerli bir 16 haneli OmaID veya IP girin.";
            root.statusError = true;
            return;
        }
        root.statusMsg = "Dosya seçici açılıyor (" + trimmed + ")...";
        root.statusError = false;
        root.runEngineAction(["--send-dialog", trimmed]);
    }

    function openDownloadsFolder() {
        if (folderProc.running) folderProc.running = false;
        folderProc.command = ["xdg-open", root.savePath];
        folderProc.running = true;
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        // 1. Header with Quickbar Paper Plane Icon ()
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Rectangle {
                width: 40
                height: 40
                radius: Theme.radiusMd
                color: Theme.bgCard
                border.color: Theme.accent

                Text {
                    anchors.centerIn: parent
                    text: ""
                    font.family: Theme.iconFont
                    font.pixelSize: 18
                    color: Theme.accent
                }
            }

            ColumnLayout {
                spacing: 2
                RowLayout {
                    spacing: 8
                    Text {
                        text: "OMASEND"
                        font.family: Theme.fontFamily
                        font.pixelSize: 17
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.textMain
                    }
                    Text {
                        text: "v" + root.pluginVersion
                        font.family: Theme.monoFont
                        font.pixelSize: 11
                        font.bold: true
                        color: Theme.accent
                    }
                }
                Text {
                    text: "AIRBRIDGE · " + root.localIp + ":" + root.port + " · ANONİM ZERO-CLICK OMAID"
                    font.family: Theme.fontFamily
                    font.pixelSize: 10
                    font.bold: true
                    color: Theme.textMuted
                }
            }

            Item { Layout.fillWidth: true }

            // Visibility Mode Pill
            Rectangle {
                height: 30
                implicitWidth: visRow.implicitWidth + 16
                radius: Theme.radiusSm
                color: Theme.bgCard
                border.color: Theme.border

                RowLayout {
                    id: visRow
                    anchors.centerIn: parent
                    spacing: 6

                    Text {
                        text: "󰌆"
                        font.family: Theme.iconFont
                        font.pixelSize: 12
                        color: root.visibility === "OFF" ? Theme.textDim : Theme.accent
                    }
                    Text {
                        text: "MOD: " + (root.visibility === "EVERYONE" ? "HERKES" : (root.visibility === "KNOWN" ? "OMAID" : "KAPALI"))
                        font.family: Theme.fontFamily
                        font.pixelSize: 10
                        font.bold: true
                        color: Theme.textMain
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        var nextMode = root.visibility === "KNOWN" ? "EVERYONE" : (root.visibility === "EVERYONE" ? "OFF" : "KNOWN");
                        root.runEngineAction(["--set-visibility", nextMode]);
                    }
                }
            }

            // Sound Toggle Button (󰕾 / 󰖁)
            Rectangle {
                width: 30
                height: 30
                radius: Theme.radiusSm
                color: soundMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard
                border.color: Theme.border

                Text {
                    anchors.centerIn: parent
                    text: root.soundEnabled ? "󰕾" : "󰖁"
                    font.family: Theme.iconFont
                    font.pixelSize: 13
                    color: root.soundEnabled ? Theme.textMain : Theme.textDim
                }

                MouseArea {
                    id: soundMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        root.soundEnabled = !root.soundEnabled;
                        root.runEngineAction(["--toggle-sound"]);
                    }
                }
            }

            // Open Downloads Folder Button (󰉋)
            Rectangle {
                width: 30
                height: 30
                radius: Theme.radiusSm
                color: folderMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard
                border.color: Theme.border

                Text {
                    anchors.centerIn: parent
                    text: "󰉋"
                    font.family: Theme.iconFont
                    font.pixelSize: 13
                    color: Theme.textMain
                }

                MouseArea {
                    id: folderMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.openDownloadsFolder()
                }
            }

            // Refresh Button (󰑐)
            Rectangle {
                width: 30
                height: 30
                radius: Theme.radiusSm
                color: refreshMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard
                border.color: Theme.border

                Text {
                    anchors.centerIn: parent
                    text: "󰑐"
                    font.family: Theme.iconFont
                    font.pixelSize: 13
                    color: root.isRefreshing ? Theme.accent : Theme.textMain
                }

                MouseArea {
                    id: refreshMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        root.runEngineAction(["--force-scan"]);
                        root.refreshStatus();
                    }
                }
            }

            // Info / About Button (󰋽)
            Rectangle {
                width: 30
                height: 30
                radius: Theme.radiusSm
                color: root.showInfoBox ? Theme.bgCardHover : (infoMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard)
                border.color: root.showInfoBox ? Theme.accent : Theme.border

                Text {
                    anchors.centerIn: parent
                    text: "󰋽"
                    font.family: Theme.iconFont
                    font.pixelSize: 13
                    color: root.showInfoBox ? Theme.accent : Theme.textMain
                }

                MouseArea {
                    id: infoMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.showInfoBox = !root.showInfoBox
                }
            }
        }

        // 1.B Incoming Transfer Gatekeeper Banner (If Pending)
        Rectangle {
            visible: root.pendingTransfer !== null && root.pendingTransfer.status === "PENDING"
            Layout.fillWidth: true
            implicitHeight: 54
            radius: Theme.radiusMd
            color: Theme.bgCard
            border.color: Theme.accent

            RowLayout {
                anchors.fill: parent
                anchors.margins: 12
                spacing: 10

                Text {
                    text: "󰇚"
                    font.family: Theme.iconFont
                    font.pixelSize: 18
                    color: Theme.accent
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text {
                        text: root.pendingTransfer ? ("GELEN DOSYA İSTEĞİ: " + String(root.pendingTransfer.sender_name || "Misafir Cihaz")) : ""
                        font.family: Theme.fontFamily
                        font.pixelSize: 12
                        font.bold: true
                        color: Theme.textMain
                    }
                    Text {
                        text: root.pendingTransfer
                              ? ((root.pendingTransfer.file_names || []).join(", ") + " · " + ((root.pendingTransfer.total_size_bytes || 0) / 1024 / 1024).toFixed(1) + " MB")
                              : ""
                        font.family: Theme.monoFont
                        font.pixelSize: 10
                        color: Theme.textMuted
                    }
                }

                Rectangle {
                    height: 30; implicitWidth: 92; radius: Theme.radiusSm
                    color: Theme.accent
                    Text { anchors.centerIn: parent; text: "󰄬 Kabul Et"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: "#000000" }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: if (root.pendingTransfer) root.runEngineAction(["--accept-transfer", root.pendingTransfer.token])
                    }
                }

                Rectangle {
                    height: 30; implicitWidth: 84; radius: Theme.radiusSm
                    color: Theme.bgSurface; border.color: Theme.accentDanger
                    Text { anchors.centerIn: parent; text: "󰅖 Reddet"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: Theme.accentDanger }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: if (root.pendingTransfer) root.runEngineAction(["--reject-transfer", root.pendingTransfer.token])
                    }
                }
            }
        }

        // 1.B2 Active Transfer Progress & Cancel Banner
        Rectangle {
            visible: root.transferProgress !== null
            Layout.fillWidth: true
            implicitHeight: 54
            radius: Theme.radiusMd
            color: Theme.bgCard
            border.color: Theme.accent

            RowLayout {
                anchors.fill: parent
                anchors.margins: 12
                spacing: 10

                Text {
                    text: (root.transferProgress && root.transferProgress.direction === "sending") ? "" : "󰇚"
                    font.family: Theme.iconFont
                    font.pixelSize: 18
                    color: Theme.accent
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text {
                        text: root.transferProgress
                              ? (String(root.transferProgress.file_name || "") + " (" + Number(root.transferProgress.percent || 0) + "%)")
                              : ""
                        font.family: Theme.fontFamily
                        font.pixelSize: 12
                        font.bold: true
                        color: Theme.textMain
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        height: 4
                        radius: 2
                        color: Theme.bgSurface

                        Rectangle {
                            width: parent.width * Math.max(0.02, Math.min(1.0, (root.transferProgress ? Number(root.transferProgress.percent || 0) : 0) / 100.0))
                            height: parent.height
                            radius: parent.radius
                            color: Theme.accent
                        }
                    }
                }

                Rectangle {
                    height: 30; implicitWidth: 84; radius: Theme.radiusSm
                    color: Theme.bgSurface; border.color: Theme.accentDanger
                    Text { anchors.centerIn: parent; text: "󰅖 İptal Et"; font.family: Theme.fontFamily; font.pixelSize: 11; font.bold: true; color: Theme.accentDanger }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            root.transferProgress = null;
                            root.runEngineAction(["--cancel-transfer"]);
                        }
                    }
                }
            }
        }

        // 1.C Expandable Info / About Card (Hakkında ve Sistem Bilgisi)
        Rectangle {
            visible: root.showInfoBox
            Layout.fillWidth: true
            implicitHeight: infoCardLayout.implicitHeight + 24
            radius: Theme.radiusMd
            color: Theme.bgCard
            border.color: Theme.accent

            ColumnLayout {
                id: infoCardLayout
                anchors.fill: parent
                anchors.margins: 12
                spacing: 6

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10

                    Text {
                        text: ""
                        font.family: Theme.iconFont
                        font.pixelSize: 16
                        color: Theme.accent
                    }

                    Text {
                        text: "OmaSend v" + root.pluginVersion + " · Omarchy Verified Plugin"
                        font.family: Theme.fontFamily
                        font.pixelSize: 12
                        font.bold: true
                        color: Theme.accent
                    }

                    Item { Layout.fillWidth: true }

                    Rectangle {
                        width: 24; height: 24; radius: Theme.radiusSm
                        color: Theme.bgSurface; border.color: Theme.border
                        Text { anchors.centerIn: parent; text: "󰅖"; font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMuted }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: root.showInfoBox = false
                        }
                    }
                }

                Text {
                    text: root.pluginDescription
                    font.family: Theme.fontFamily
                    font.pixelSize: 11
                    color: Theme.textMain
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 18

                    Text {
                        text: "󰌆 Kimlik: 16-Haneli Luhn OmaID"
                        font.family: Theme.fontFamily
                        font.pixelSize: 10
                        color: Theme.textMuted
                    }
                    Text {
                        text: "󰒃 Kriptografi: AES-256-GCM E2EE + BLAKE3"
                        font.family: Theme.fontFamily
                        font.pixelSize: 10
                        color: Theme.textMuted
                    }
                    Text {
                        text: "󰉋 Kayıt: " + root.savePath + " (" + root.totalReceived + " alınan)"
                        font.family: Theme.fontFamily
                        font.pixelSize: 10
                        color: Theme.textMuted
                    }
                }

                Text {
                    text: "Geliştirici: " + root.pluginAuthor + " · Lisans: " + root.pluginLicense
                    font.family: Theme.fontFamily
                    font.pixelSize: 10
                    color: Theme.textDim
                }
            }
        }

        // 2. Anonymous Numbered Identity Card
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: idCardLayout.implicitHeight + 24
            radius: Theme.radiusMd
            color: Theme.bgCard
            border.color: Theme.borderLight

            ColumnLayout {
                id: idCardLayout
                anchors.fill: parent
                anchors.margins: 12
                spacing: 8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10

                    Text {
                        text: "󰌆"
                        font.family: Theme.iconFont
                        font.pixelSize: 15
                        color: Theme.accent
                    }

                    Text {
                        text: root.omaIdCopied ? "OMAID KOPYALANDI:" : "OMAID KİMLİĞİM:"
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        font.bold: true
                        color: root.omaIdCopied ? Theme.accent : Theme.textMuted
                    }

                    Text {
                        text: root.formatOmaId(root.omaId, root.omaIdRevealed)
                        font.family: Theme.monoFont
                        font.pixelSize: 15
                        font.bold: true
                        font.letterSpacing: 1.2
                        color: Theme.textMain
                    }

                    Item { Layout.fillWidth: true }

                    // Copy (󰆏)
                    Rectangle {
                        width: 28; height: 28; radius: Theme.radiusSm
                        color: Theme.bgSurface; border.color: root.omaIdCopied ? Theme.accent : Theme.border
                        Text { anchors.centerIn: parent; text: root.omaIdCopied ? "󰄬" : "󰆏"; font.family: Theme.iconFont; font.pixelSize: 13; color: root.omaIdCopied ? Theme.accent : Theme.textMain }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                if (root.omaId) {
                                    copyProc.command = ["wl-copy", root.omaId];
                                    copyProc.running = true;
                                    root.omaIdCopied = true;
                                    copyFeedbackTimer.restart();
                                }
                            }
                        }
                    }

                    // Reveal/Hide (󰈈)
                    Rectangle {
                        width: 28; height: 28; radius: Theme.radiusSm
                        color: Theme.bgSurface; border.color: Theme.border
                        Text { anchors.centerIn: parent; text: root.omaIdRevealed ? "󰈈" : "󰈉"; font.family: Theme.iconFont; font.pixelSize: 13; color: root.omaIdRevealed ? Theme.accent : Theme.textMuted }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: root.omaIdRevealed = !root.omaIdRevealed
                        }
                    }

                    // QR Code Button (󰄲)
                    Rectangle {
                        width: 28; height: 28; radius: Theme.radiusSm
                        color: root.showQrBox ? Theme.bgCardHover : Theme.bgSurface
                        border.color: root.showQrBox ? Theme.accent : Theme.border
                        Text { anchors.centerIn: parent; text: "󰄲"; font.family: Theme.iconFont; font.pixelSize: 13; color: root.showQrBox ? Theme.accent : Theme.textMain }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                root.showQrBox = !root.showQrBox;
                                root.showSyncBox = false;
                                if (root.showQrBox) root.runEngineAction(["--oma-id-qr"]);
                            }
                        }
                    }

                    // Kimliği Değiştir / Eşitle Button
                    Rectangle {
                        height: 28
                        implicitWidth: syncLabel.implicitWidth + 20
                        radius: Theme.radiusSm
                        color: root.showSyncBox ? Theme.bgCardHover : Theme.bgSurface
                        border.color: Theme.accent
                        Text {
                            id: syncLabel
                            anchors.centerIn: parent
                            text: "󰑐 Kimliği Değiştir / Eşitle"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                root.syncInputOmaId = root.formatInputOmaId(root.omaId);
                                root.showSyncBox = !root.showSyncBox;
                                root.showQrBox = false;
                            }
                        }
                    }
                }

                // Inline QR View
                RowLayout {
                    visible: root.showQrBox
                    Layout.fillWidth: true
                    spacing: 14

                    Rectangle {
                        width: 110; height: 110; radius: Theme.radiusSm
                        color: "#ffffff"
                        Image {
                            anchors.centerIn: parent
                            width: 98; height: 98
                            source: root.omaidQrPath ? ("file://" + root.omaidQrPath + "?v=" + root.refreshNonce) : ""
                            fillMode: Image.PreserveAspectFit
                            cache: false
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4
                        Text {
                            text: "OMAID HIZLI EŞİTLEME QR KODU"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.accent
                        }
                        Text {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "Android uygulamasında bu QR kodu okutarak telefonunuzu aynı OmaID kimliğine geçirebilirsiniz. Cihazlarınız 'Kendi Cihazlarım' altında görünür; gelen her transfer onayınızı bekler."
                            font.family: Theme.fontFamily
                            font.pixelSize: 10
                            color: Theme.textMuted
                        }
                    }
                }

                // Inline Identity Sync Box
                RowLayout {
                    visible: root.showSyncBox
                    Layout.fillWidth: true
                    spacing: 8

                    Rectangle {
                        Layout.fillWidth: true
                        height: 32
                        radius: Theme.radiusSm
                        color: Theme.bgBase
                        border.color: Theme.accent

                        TextInput {
                            id: syncInput
                            anchors.fill: parent
                            anchors.margins: 6
                            verticalAlignment: Text.AlignVCenter
                            text: root.syncInputOmaId
                            font.family: Theme.monoFont
                            font.pixelSize: 12
                            font.bold: true
                            color: Theme.textMain
                            maximumLength: 19
                            onTextChanged: root.syncInputOmaId = root.formatInputOmaId(text)
                            onAccepted: root.applyOwnOmaId(root.syncInputOmaId)
                        }
                    }

                    // Paste from Clipboard (󰅍)
                    Rectangle {
                        width: 32; height: 32; radius: Theme.radiusSm
                        color: Theme.bgSurface; border.color: Theme.border
                        Text { anchors.centerIn: parent; text: "󰅍"; font.family: Theme.iconFont; font.pixelSize: 13; color: Theme.textMain }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                pasteProc.targetMode = "sync";
                                pasteProc.running = true;
                            }
                        }
                    }

                    // Scan Screen QR (󰄳)
                    Rectangle {
                        width: 32; height: 32; radius: Theme.radiusSm
                        color: Theme.bgSurface; border.color: Theme.border
                        Text { anchors.centerIn: parent; text: "󰄳"; font.family: Theme.iconFont; font.pixelSize: 13; color: Theme.textMain }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                screenScanProc.forSync = true;
                                screenScanProc.running = true;
                            }
                        }
                    }

                    // Generate New OmaID (󰑓)
                    Rectangle {
                        height: 32
                        implicitWidth: 108
                        radius: Theme.radiusSm
                        color: Theme.bgSurface
                        border.color: Theme.borderLight
                        Text {
                            anchors.centerIn: parent
                            text: "󰑓 Yeni Üret"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: newOmaIdProc.running = true
                        }
                    }

                    // Apply Own OmaID (󰄬)
                    Rectangle {
                        height: 32
                        implicitWidth: 126
                        radius: Theme.radiusSm
                        color: Theme.accent
                        Text {
                            anchors.centerIn: parent
                            text: "󰄬 Kimliği Uygula"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: "#000000"
                        }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: root.applyOwnOmaId(root.syncInputOmaId)
                        }
                    }
                }

                Text {
                    visible: root.statusMsg.length > 0
                    text: root.statusMsg
                    font.family: Theme.fontFamily
                    font.pixelSize: 10
                    color: root.statusError ? Theme.accentDanger : Theme.accent
                }
            }
        }

        // 3. Two-Column Device List: KENDİ CİHAZLARIM vs DİĞER CİHAZLAR / FARKLI OMAID
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 16

            // Left Column: KENDİ CİHAZLARIM (Aynı OmaID - ZERO-CLICK)
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 50
                radius: Theme.radiusMd
                color: Theme.bgCard
                border.color: Theme.border

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 14
                    spacing: 10

                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                            text: "KENDİ CİHAZLARIM (AYNI OMAID)"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                        Item { Layout.fillWidth: true }
                        Rectangle {
                            height: 18
                            implicitWidth: zcHeaderText.implicitWidth + 10
                            radius: 4
                            color: Theme.bgBase
                            border.color: Theme.accent
                            Text {
                                id: zcHeaderText
                                anchors.centerIn: parent
                                text: "ZERO-CLICK"
                                font.family: Theme.fontFamily
                                font.pixelSize: 9
                                font.bold: true
                                color: Theme.accent
                            }
                        }
                    }

                    ListView {
                        id: ownPeerList
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 8
                        model: root.ownPeers

                        delegate: Rectangle {
                            width: ownPeerList.width
                            height: 58
                            radius: Theme.radiusSm
                            color: Theme.bgSurface
                            border.color: Theme.borderLight

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 10
                                spacing: 10

                                Text {
                                    text: (modelData.name && String(modelData.name).toLowerCase().indexOf("android") !== -1) ? "󰏲" : "󰌢"
                                    font.family: Theme.iconFont
                                    font.pixelSize: 18
                                    color: Theme.accent
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    RowLayout {
                                        spacing: 6
                                        Text {
                                            text: modelData.name || "Cihazım"
                                            font.family: Theme.fontFamily
                                            font.pixelSize: 12
                                            font.bold: true
                                            color: Theme.textMain
                                        }
                                        Text {
                                            text: "[ZERO-CLICK]"
                                            font.family: Theme.fontFamily
                                            font.pixelSize: 9
                                            font.bold: true
                                            color: Theme.accent
                                        }
                                    }
                                    Text {
                                        text: modelData.ip + "  •  Sıfır İzinle Anında Aktarım"
                                        font.family: Theme.monoFont
                                        font.pixelSize: 10
                                        color: Theme.textMuted
                                    }
                                }

                                // Sync Clipboard Button (󰅍)
                                Rectangle {
                                    width: 30; height: 30; radius: Theme.radiusSm
                                    color: Theme.bgCard; border.color: Theme.border
                                    Text { anchors.centerIn: parent; text: "󰅍"; font.family: Theme.iconFont; font.pixelSize: 13; color: Theme.textMain }
                                    MouseArea {
                                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                        onClicked: root.runEngineAction(["--sync-clipboard", modelData.ip || modelData.oma_id])
                                    }
                                }

                                // Send File Button ()
                                Rectangle {
                                    width: 30; height: 30; radius: Theme.radiusSm
                                    color: Theme.bgCard; border.color: Theme.accent
                                    Text { anchors.centerIn: parent; text: ""; font.family: Theme.iconFont; font.pixelSize: 13; color: Theme.accent }
                                    MouseArea {
                                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                        onClicked: root.runEngineAction(["--send-dialog", modelData.ip || modelData.oma_id])
                                    }
                                }
                            }
                        }

                        Text {
                            anchors.centerIn: parent
                            visible: root.ownPeers.length === 0
                            width: parent.width - 20
                            wrapMode: Text.WordWrap
                            horizontalAlignment: Text.AlignHCenter
                            text: "Aynı OmaID'ye sahip başka cihazınız henüz algılanmadı."
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            color: Theme.textDim
                        }
                    }
                }
            }

            // Right Column: DİĞER CİHAZLAR / FARKLI OMAID
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 50
                radius: Theme.radiusMd
                color: Theme.bgCard
                border.color: Theme.border

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 14
                    spacing: 10

                    Text {
                        text: "DİĞER CİHAZLAR / FARKLI OMAID'YE GÖNDER"
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        font.bold: true
                        color: Theme.textMain
                    }

                    // Quick Direct Send Input
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 6

                        Rectangle {
                            Layout.fillWidth: true
                            height: 32
                            radius: Theme.radiusSm
                            color: Theme.bgBase
                            border.color: Theme.borderLight

                            TextInput {
                                id: directInput
                                anchors.fill: parent
                                anchors.margins: 6
                                verticalAlignment: Text.AlignVCenter
                                text: root.directTargetInput
                                font.family: Theme.monoFont
                                font.pixelSize: 11
                                color: Theme.textMain
                                maximumLength: 24
                                onTextChanged: {
                                    var raw = text;
                                    var onlyDigitsAndDashes = /^[0-9-]+$/.test(raw);
                                    if (onlyDigitsAndDashes && raw.indexOf(".") === -1) {
                                        var formatted = root.formatInputOmaId(raw);
                                        if (formatted !== raw) {
                                            text = formatted;
                                            root.directTargetInput = formatted;
                                            return;
                                        }
                                    }
                                    root.directTargetInput = raw;
                                }
                                onAccepted: root.sendDirectTarget(root.directTargetInput)

                                Text {
                                    anchors.fill: parent
                                    visible: !directInput.text && !directInput.activeFocus
                                    text: "16 haneli OmaID veya IP gir..."
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 10
                                    color: Theme.textDim
                                    verticalAlignment: Text.AlignVCenter
                                }
                            }
                        }

                        // Paste into Direct Target (󰅍)
                        Rectangle {
                            width: 32; height: 32; radius: Theme.radiusSm
                            color: Theme.bgSurface; border.color: Theme.border
                            Text { anchors.centerIn: parent; text: "󰅍"; font.family: Theme.iconFont; font.pixelSize: 13; color: Theme.textMain }
                            MouseArea {
                                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    pasteProc.targetMode = "direct";
                                    pasteProc.running = true;
                                }
                            }
                        }

                        // Scan Screen QR into Direct Target (󰄳)
                        Rectangle {
                            width: 32; height: 32; radius: Theme.radiusSm
                            color: Theme.bgSurface; border.color: Theme.border
                            Text { anchors.centerIn: parent; text: "󰄳"; font.family: Theme.iconFont; font.pixelSize: 13; color: Theme.textMain }
                            MouseArea {
                                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    screenScanProc.forSync = false;
                                    screenScanProc.running = true;
                                }
                            }
                        }

                        Rectangle {
                            height: 32
                            implicitWidth: 92
                            radius: Theme.radiusSm
                            color: Theme.bgSurface
                            border.color: Theme.accent
                            Text {
                                anchors.centerIn: parent
                                text: " Gönder"
                                font.family: Theme.fontFamily
                                font.pixelSize: 11
                                font.bold: true
                                color: Theme.textMain
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.sendDirectTarget(root.directTargetInput)
                            }
                        }
                    }

                    ListView {
                        id: otherPeerList
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 8
                        model: root.otherPeers

                        delegate: Rectangle {
                            width: otherPeerList.width
                            height: 54
                            radius: Theme.radiusSm
                            color: Theme.bgSurface
                            border.color: Theme.border

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 10
                                spacing: 10

                                Text {
                                    text: ""
                                    font.family: Theme.iconFont
                                    font.pixelSize: 16
                                    color: Theme.textMuted
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text {
                                        text: modelData.name || "Ağ Cihazı"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 12
                                        font.bold: true
                                        color: Theme.textMain
                                    }
                                    Text {
                                        text: (modelData.oma_id || modelData.ip)
                                        font.family: Theme.monoFont
                                        font.pixelSize: 10
                                        color: Theme.textMuted
                                    }
                                }

                                Text {
                                    text: ""
                                    font.family: Theme.iconFont
                                    font.pixelSize: 13
                                    color: Theme.textMain
                                }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.runEngineAction(["--send-dialog", modelData.ip || modelData.oma_id])
                            }
                        }
                    }
                }
            }
        }
    }
}
