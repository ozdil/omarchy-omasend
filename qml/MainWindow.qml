import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Shapes
import Quickshell
import Quickshell.Io
import "theme"
import "OmaI18n.js" as OmaI18n

// Standalone OmaSend window (used by `omasend-dashboard` when the bar plugin is not running).
// Same model as the bar panel: QR-paired devices (encrypted) and nearby devices (legacy).
Rectangle {
    id: root
    color: Theme.bgBase

    readonly property string lang: OmaI18n.detectLang(Quickshell.env("LC_ALL") || Quickshell.env("LC_MESSAGES") || Quickshell.env("LANG") || "", Qt.locale().name)
    function t(key) { return OmaI18n.tr(root.lang, key) }
    function tf(key, a, b) {
        var s = OmaI18n.tr(root.lang, key)
        if (a !== undefined) s = s.replace("%1", a)
        if (b !== undefined) s = s.replace("%2", b)
        return s
    }

    property string localIp: "127.0.0.1"
    property string savePath: "~/Downloads/omasend"
    property int totalReceived: 0
    property string visibility: "KNOWN"
    property var discovered: []
    property var pairedDevices: []
    property var pendingTransfer: null
    property var transferProgress: null
    property bool soundEnabled: true
    property string deviceKeyId: ""
    property string hostname: "Omarchy"
    property int refreshNonce: 0

    property bool showPair: false
    property bool pairOwn: true
    property string pairQrPath: ""
    property int pairExpiresAt: 0
    property int nowSecs: 0
    property int pairedCountAtOpen: 0
    property string statusMsg: ""
    property bool statusError: false
    property string armedUnpair: ""

    readonly property bool serviceOn: root.visibility !== "OFF"
    readonly property var nearby: {
        if (!root.serviceOn) return []
        var out = []
        for (var i = 0; i < root.discovered.length; i++) {
            var p = root.discovered[i]
            if (p && !p.key_trust) out.push(p)
        }
        return out
    }
    readonly property int onlineCount: {
        var n = 0
        for (var i = 0; i < root.pairedDevices.length; i++) if (root.pairedDevices[i].online) n++
        return n
    }

    // Source installs (build.sh) put the engine in ~/.local/bin, the package in /usr/bin.
    property string enginePath: {
        var home = Quickshell.env("HOME") || ""
        return home ? (home + "/.local/bin/omasend-engine") : Qt.resolvedUrl("../omasend-engine").toString().replace(/^file:\/\//, "")
    }
    function engine() { return root.enginePath }
    Process {
        id: engineLocator
        running: true
        command: ["sh", "-c", "for p in \"$HOME/.local/bin/omasend-engine\" /usr/bin/omasend-engine; do if [ -x \"$p\" ]; then echo \"$p\"; exit 0; fi; done"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                var p = String(text || "").trim()
                if (p) root.enginePath = p
                root.refreshStatus()
            }
        }
    }
    function run(args) {
        if (actionProc.running) actionProc.running = false
        actionProc.command = [root.engine()].concat(args)
        actionProc.running = true
    }
    function refreshStatus() { if (!statusProc.running) statusProc.running = true }
    function setStatus(msg, isError) { root.statusMsg = msg; root.statusError = Boolean(isError); statusClear.restart() }
    function sendFileTo(address) {
        if (dialogProc.running) dialogProc.running = false
        dialogProc.command = [root.engine(), "--send-dialog", address]
        dialogProc.running = true
    }
    function openPairing() {
        root.showPair = true
        root.pairedCountAtOpen = root.pairedDevices.length
        root.newPairOffer()
    }
    function newPairOffer() {
        root.pairQrPath = ""
        if (pairProc.running) pairProc.running = false
        pairProc.command = [root.engine(), "--pair-offer", "--json"].concat(root.pairOwn ? ["--own"] : [])
        pairProc.running = true
    }
    function requestUnpair(deviceId) {
        if (root.armedUnpair === deviceId) {
            root.armedUnpair = ""
            root.run(["--unpair", deviceId])
        } else {
            root.armedUnpair = deviceId
            unpairArm.restart()
        }
    }

    onPairedDevicesChanged: {
        if (root.showPair && root.pairedDevices.length > root.pairedCountAtOpen) {
            var d = root.pairedDevices[root.pairedDevices.length - 1]
            root.showPair = false
            root.setStatus(root.tf("paired_with", d ? d.name : ""), false)
        }
    }

    Timer {
        interval: 1500
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: {
            root.refreshStatus()
            root.nowSecs = Math.floor(Date.now() / 1000)
            if (root.showPair && root.pairQrPath !== "" && root.nowSecs >= root.pairExpiresAt - 5) root.newPairOffer()
        }
    }
    Timer { id: statusClear; interval: 6000; onTriggered: root.statusMsg = "" }
    Timer { id: unpairArm; interval: 4000; onTriggered: root.armedUnpair = "" }

    Process {
        id: statusProc
        command: [root.engine(), "--json"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                statusProc.running = false
                try {
                    var s = JSON.parse(String(text || "").slice(0, 262144))
                    root.localIp = String(s.local_ip || "127.0.0.1")
                    root.savePath = String(s.download_dir || root.savePath)
                    root.totalReceived = Number(s.total_received) || 0
                    root.visibility = (String(s.p2p_visibility || "KNOWN") === "OFF") ? "OFF" : "KNOWN"
                    root.discovered = s.p2p_discovered_peers || []
                    root.pairedDevices = s.paired_devices || []
                    root.pendingTransfer = s.p2p_pending_transfer || null
                    root.transferProgress = s.p2p_transfer_progress || null
                    if (s.sound_enabled !== undefined) root.soundEnabled = Boolean(s.sound_enabled)
                    root.deviceKeyId = String(s.device_key_id || "")
                    root.hostname = String(s.p2p_hostname || "Omarchy")
                    root.refreshNonce++
                } catch (e) {}
            }
        }
    }
    Process {
        id: pairProc
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                pairProc.running = false
                try {
                    var d = JSON.parse(String(text || ""))
                    root.pairQrPath = String(d.qr_svg || "")
                    root.pairExpiresAt = Math.floor(Date.now() / 1000) + (Number(d.expires_in_secs) || 300)
                    root.refreshNonce++
                } catch (e) { root.setStatus(root.t("pair_qr_failed"), true) }
            }
        }
    }
    Process { id: actionProc; onExited: { actionProc.running = false; root.refreshStatus() } }
    Process { id: dialogProc; onExited: { dialogProc.running = false; root.refreshStatus() } }
    Process { id: folderProc }

    // ------------------------------------------------------------------ layout
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 18
        spacing: 14

        // Header
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            // OmaSend mark (same path as assets/omasend-symbolic.svg)
            Item {
                implicitWidth: 28
                implicitHeight: 28
                Shape {
                    width: 300
                    height: 300
                    scale: 28 / 300
                    transformOrigin: Item.TopLeft
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        fillColor: root.serviceOn ? Theme.textMain : Theme.textDim
                        strokeColor: "transparent"
                        strokeWidth: 0
                        PathSvg { path: "M0 0h180v20h-180zM200 0h100v20h-100zM0 20h20v20h-20zM140 20h20v20h-20zM240 20h60v20h-60zM0 40h20v20h-20zM40 40h120v20h-120zM220 40h40v20h-40zM280 40h20v20h-20zM0 60h20v20h-20zM40 60h20v20h-20zM200 60h40v20h-40zM280 60h20v20h-20zM0 80h20v20h-20zM40 80h20v20h-20zM180 80h40v20h-40zM0 100h20v20h-20zM40 100h20v20h-20zM160 100h40v20h-40zM240 100h20v20h-20zM280 100h20v20h-20zM0 120h20v20h-20zM40 120h20v20h-20zM160 120h20v20h-20zM240 120h20v20h-20zM280 120h20v20h-20zM0 140h60v20h-60zM240 140h20v20h-20zM280 140h20v20h-20zM0 160h20v20h-20zM40 160h20v20h-20zM240 160h20v20h-20zM280 160h20v20h-20zM0 180h20v20h-20zM40 180h20v20h-20zM240 180h20v20h-20zM280 180h20v20h-20zM0 200h20v20h-20zM40 200h20v20h-20zM240 200h20v20h-20zM280 200h20v20h-20zM0 220h20v20h-20zM40 220h20v20h-20zM240 220h20v20h-20zM280 220h20v20h-20zM0 240h20v20h-20zM40 240h220v20h-220zM280 240h20v20h-20zM0 260h20v20h-20zM140 260h20v20h-20zM280 260h20v20h-20zM0 280h160v20h-160zM180 280h120v20h-120z" }
                    }
                }
            }
            ColumnLayout {
                spacing: 2
                Text {
                    text: "OmaSend · " + root.hostname
                    font.family: Theme.fontFamily
                    font.pixelSize: 17
                    font.bold: true
                    color: Theme.textMain
                }
                Text {
                    text: (root.serviceOn ? root.tf("hero_sub_on", root.onlineCount) : root.t("service_disabled_sub"))
                          + "  ·  " + root.localIp + "  ·  " + root.deviceKeyId
                    font.family: Theme.fontFamily
                    font.pixelSize: 10
                    font.bold: true
                    color: Theme.textMuted
                }
            }
            Item { Layout.fillWidth: true }
            IconButton { glyph: "󰐲"; tip: root.t("pair_tooltip"); highlighted: root.showPair; onActivated: { if (root.showPair) root.showPair = false; else root.openPairing() } }
            IconButton { glyph: root.soundEnabled ? "󰕾" : "󰖁"; tip: root.soundEnabled ? root.t("sound_on_tooltip") : root.t("sound_off_tooltip"); onActivated: { root.soundEnabled = !root.soundEnabled; root.run(["--toggle-sound"]) } }
            IconButton { glyph: "󰉋"; tip: root.t("open_downloads_tooltip"); onActivated: { folderProc.command = ["xdg-open", root.savePath]; folderProc.running = true } }
            IconButton { glyph: "󰑐"; tip: root.t("refresh_scan_tooltip"); onActivated: root.run(["--force-scan"]) }
            IconButton { glyph: "󰐥"; tip: root.serviceOn ? root.t("turn_off_service") : root.t("turn_on_service"); highlighted: root.serviceOn; onActivated: root.run(["--set-visibility", root.serviceOn ? "OFF" : "KNOWN"]) }
        }

        Text {
            visible: root.statusMsg !== ""
            Layout.fillWidth: true
            text: root.statusMsg
            color: root.statusError ? Theme.accentDanger : Theme.accent
            font.family: Theme.fontFamily
            font.pixelSize: 11
            wrapMode: Text.WordWrap
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 14

            // Left: pairing + transfers
            ColumnLayout {
                Layout.preferredWidth: 300
                Layout.fillHeight: true
                spacing: 12

                Card {
                    Layout.fillWidth: true
                    visible: root.showPair
                    implicitHeight: pairCol.implicitHeight + 24

                    ColumnLayout {
                        id: pairCol
                        anchors.fill: parent
                        anchors.margins: 12
                        spacing: 8

                        Text { text: root.t("pair_title"); font.family: Theme.fontFamily; font.pixelSize: 10; font.bold: true; color: Theme.accent }
                        Rectangle {
                            Layout.alignment: Qt.AlignHCenter
                            width: 190; height: 190; radius: Theme.radiusMd; color: "#ffffff"
                            Image {
                                anchors.centerIn: parent
                                width: 178; height: 178
                                source: root.pairQrPath ? ("file://" + root.pairQrPath + "?v=" + root.refreshNonce) : ""
                                sourceSize.width: 512; sourceSize.height: 512
                                fillMode: Image.PreserveAspectFit
                                smooth: false
                                cache: false
                            }
                        }
                        Text { Layout.fillWidth: true; text: root.t("pair_instructions"); font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                        Text { Layout.fillWidth: true; text: root.tf("pair_expires", Math.max(0, root.pairExpiresAt - root.nowSecs)); font.family: Theme.fontFamily; font.pixelSize: 10; color: Theme.textMuted; horizontalAlignment: Text.AlignHCenter }
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            Pill { label: root.t("pair_own"); selected: root.pairOwn; onActivated: { if (!root.pairOwn) { root.pairOwn = true; root.newPairOffer() } } }
                            Pill { label: root.t("pair_other"); selected: !root.pairOwn; onActivated: { if (root.pairOwn) { root.pairOwn = false; root.newPairOffer() } } }
                        }
                        Text { Layout.fillWidth: true; text: root.pairOwn ? root.t("pair_own_hint") : root.t("pair_other_hint"); font.family: Theme.fontFamily; font.pixelSize: 10; color: Theme.textMuted; wrapMode: Text.WordWrap }
                    }
                }

                Card {
                    Layout.fillWidth: true
                    visible: root.pendingTransfer !== null && root.pendingTransfer.status === "PENDING"
                    implicitHeight: pendingCol.implicitHeight + 24

                    ColumnLayout {
                        id: pendingCol
                        anchors.fill: parent
                        anchors.margins: 12
                        spacing: 6
                        Text { text: root.t("incoming_transfer_header"); font.family: Theme.fontFamily; font.pixelSize: 10; font.bold: true; color: Theme.accentWarning }
                        Text { Layout.fillWidth: true; text: root.pendingTransfer ? String(root.pendingTransfer.sender_name || "") : ""; font.family: Theme.fontFamily; font.pixelSize: 13; font.bold: true; color: Theme.textMain; elide: Text.ElideRight }
                        Text {
                            Layout.fillWidth: true
                            text: root.pendingTransfer
                                  ? ((root.pendingTransfer.transport === "quic" ? root.t("encrypted") : root.t("not_encrypted")) + " · " + (root.pendingTransfer.file_names || []).join(", "))
                                  : ""
                            font.family: Theme.fontFamily; font.pixelSize: 10; color: Theme.textMuted; elide: Text.ElideRight
                        }
                        RowLayout {
                            spacing: 8
                            Pill { label: root.t("accept_btn"); selected: true; onActivated: if (root.pendingTransfer) root.run(["--accept-transfer", root.pendingTransfer.token]) }
                            Pill { label: root.t("reject_btn"); onActivated: if (root.pendingTransfer) root.run(["--reject-transfer", root.pendingTransfer.token]) }
                        }
                    }
                }

                Card {
                    Layout.fillWidth: true
                    visible: root.transferProgress !== null
                    implicitHeight: progCol.implicitHeight + 24

                    ColumnLayout {
                        id: progCol
                        anchors.fill: parent
                        anchors.margins: 12
                        spacing: 6
                        Text { text: root.t("active_transfer_header"); font.family: Theme.fontFamily; font.pixelSize: 10; font.bold: true; color: Theme.accent }
                        Text {
                            Layout.fillWidth: true
                            text: root.transferProgress ? (String(root.transferProgress.file_name || "") + " (" + Number(root.transferProgress.percent || 0) + "%)") : ""
                            font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain; elide: Text.ElideRight
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            height: 4; radius: 2; color: Theme.border
                            Rectangle {
                                width: parent.width * Math.max(0.02, Math.min(1.0, (root.transferProgress ? Number(root.transferProgress.percent || 0) : 0) / 100.0))
                                height: parent.height; radius: 2; color: Theme.accent
                            }
                        }
                        Pill { label: root.t("cancel_btn"); onActivated: { root.transferProgress = null; root.run(["--cancel-transfer"]) } }
                    }
                }

                Text {
                    Layout.fillWidth: true
                    visible: !root.showPair
                    text: root.t("about_line")
                    font.family: Theme.fontFamily
                    font.pixelSize: 10
                    color: Theme.textDim
                    wrapMode: Text.WordWrap
                }
                Item { Layout.fillHeight: true }
            }

            // Right: devices
            Flickable {
                Layout.fillWidth: true
                Layout.fillHeight: true
                contentHeight: devCol.implicitHeight
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                ColumnLayout {
                    id: devCol
                    width: parent.width
                    spacing: 8

                    Text { text: root.t("my_devices_header") + "  " + root.onlineCount + "/" + root.pairedDevices.length; font.family: Theme.fontFamily; font.pixelSize: 10; font.bold: true; color: Theme.accent }
                    Repeater {
                        model: root.pairedDevices
                        DeviceCard {
                            required property var modelData
                            Layout.fillWidth: true
                            paired: true
                            name: String(modelData.name || "")
                            address: String(modelData.device_id || "")
                            own: Boolean(modelData.own_device)
                            online: Boolean(modelData.online)
                            detail: (Boolean(modelData.online) ? root.t("online") + " · " + String(modelData.ip || "") : root.t("not_seen")) + " · " + String(modelData.device_id || "")
                        }
                    }
                    Text { visible: root.pairedDevices.length === 0; Layout.fillWidth: true; text: root.t("no_paired_devices"); font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMuted; wrapMode: Text.WordWrap }

                    Item { Layout.preferredHeight: 8 }

                    Text { text: root.t("nearby_header") + "  " + root.nearby.length; font.family: Theme.fontFamily; font.pixelSize: 10; font.bold: true; color: Theme.textMuted }
                    Repeater {
                        model: root.nearby
                        DeviceCard {
                            required property var modelData
                            Layout.fillWidth: true
                            paired: false
                            name: String(modelData.name || "")
                            address: String(modelData.ip || "")
                            online: true
                            detail: String(modelData.ip || "") + " · " + root.t("needs_approval")
                        }
                    }
                    Text {
                        Layout.fillWidth: true
                        text: root.nearby.length === 0 ? (root.serviceOn ? root.t("nearby_empty") : root.t("service_disabled_sub")) : root.t("nearby_footnote")
                        font.family: Theme.fontFamily; font.pixelSize: 10; color: Theme.textDim; wrapMode: Text.WordWrap
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ components
    component Card: Rectangle {
        radius: Theme.radiusMd
        color: Theme.bgSurface
        border.color: Theme.border
        border.width: 1
    }

    component IconButton: Rectangle {
        id: ib
        property string glyph: ""
        property string tip: ""
        property bool highlighted: false
        signal activated()
        width: 32; height: 32
        radius: Theme.radiusSm
        color: ibMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard
        border.color: ib.highlighted ? Theme.accent : Theme.border
        Text { anchors.centerIn: parent; text: ib.glyph; font.family: Theme.iconFont; font.pixelSize: 14; color: ib.highlighted ? Theme.accent : Theme.textMain }
        MouseArea { id: ibMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: ib.activated() }
        ToolTip.visible: ibMouse.containsMouse && ib.tip !== ""
        ToolTip.text: ib.tip
        ToolTip.delay: 500
    }

    component Pill: Rectangle {
        id: pill
        property string label: ""
        property bool selected: false
        signal activated()
        implicitWidth: pillText.implicitWidth + 20
        implicitHeight: 26
        radius: Theme.radiusSm
        color: pill.selected ? Theme.accent : (pillMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard)
        border.color: pill.selected ? Theme.accent : Theme.border
        Text { id: pillText; anchors.centerIn: parent; text: pill.label; font.family: Theme.fontFamily; font.pixelSize: 10; font.bold: true; color: pill.selected ? Theme.bgBase : Theme.textMain }
        MouseArea { id: pillMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: pill.activated() }
    }

    component DeviceCard: Rectangle {
        id: dc
        property bool paired: false
        property string name: ""
        property string address: ""
        property string detail: ""
        property bool own: false
        property bool online: false
        readonly property bool armed: paired && root.armedUnpair === address
        implicitHeight: 54
        radius: Theme.radiusMd
        color: dcMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard
        border.color: (dc.paired && dc.online) ? Theme.borderLight : Theme.border

        MouseArea {
            id: dcMouse
            anchors.fill: parent
            hoverEnabled: true
            acceptedButtons: Qt.LeftButton | Qt.RightButton
            cursorShape: Qt.PointingHandCursor
            onClicked: function(mouse) {
                if (mouse.button === Qt.RightButton) root.run(["--sync-clipboard", dc.address])
                else root.sendFileTo(dc.address)
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 8
            spacing: 10

            Text {
                text: /android|phone|pixel|galaxy|sdk_gphone|samsung|xiaomi/i.test(dc.name) ? "󰏲" : "󰌢"
                font.family: Theme.iconFont
                font.pixelSize: 18
                color: (dc.paired && dc.online) ? Theme.accent : Theme.textMuted
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1
                Text {
                    Layout.fillWidth: true
                    text: dc.name + (dc.paired ? "  · " + (dc.own ? root.t("badge_own") : root.t("badge_paired")) : "")
                    font.family: Theme.fontFamily; font.pixelSize: 12; font.bold: true; color: Theme.textMain; elide: Text.ElideRight
                }
                Text {
                    Layout.fillWidth: true
                    text: dc.armed ? root.t("unpair_armed") : dc.detail
                    font.family: Theme.fontFamily; font.pixelSize: 10; color: dc.armed ? Theme.accentDanger : Theme.textMuted; elide: Text.ElideRight
                }
            }
            Text {
                text: dc.paired ? "󰌾" : "󰌿"
                font.family: Theme.iconFont
                font.pixelSize: 13
                color: dc.paired ? Theme.accent : Theme.textDim
            }
            IconButton { visible: dc.paired; glyph: "󰅍"; tip: root.t("send_clipboard_tooltip"); onActivated: root.run(["--sync-clipboard", dc.address]) }
            IconButton { visible: dc.paired; glyph: "󰅖"; tip: dc.armed ? root.t("unpair_confirm_tooltip") : root.t("unpair_tooltip"); highlighted: dc.armed; onActivated: root.requestUnpair(dc.address) }
        }
    }
}
