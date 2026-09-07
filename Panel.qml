import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "ozdil.omasend"
  ipcTarget: "ozdil.omasend"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  property string localIp: "127.0.0.1"
  property int port: 8844
  property string pin: "----"
  property string sessionKey: ""
  property string activeMode: "LAN"
  property bool wanActive: false
  property bool wanConnecting: false
  property string wanUrl: ""
  property string activeUrl: ""
  property string savePath: "~/Downloads/omasend"
  property string qrPath: ""
  property int totalReceived: 0
  property var recentFiles: []
  property var sharedFiles: []
  property int refreshNonce: 0

  function resolveEnginePath() {
    return Qt.resolvedUrl("omasend-engine").toString().replace(/^file:\/\//, "")
  }

  function refresh() {
    if (!scanProc.running) {
      scanProc.running = true
    }
  }

  function newPin() {
    actionProc.command = [root.resolveEnginePath(), "--new-pin"]
    actionProc.running = true
  }

  function newKey() {
    actionProc.command = [root.resolveEnginePath(), "--new-key"]
    actionProc.running = true
  }

  function toggleWan() {
    actionProc.command = [root.resolveEnginePath(), "--toggle-wan"]
    actionProc.running = true
  }

  function setLanMode() {
    actionProc.command = [root.resolveEnginePath(), "--set-lan"]
    actionProc.running = true
  }

  function setWanMode() {
    actionProc.command = [root.resolveEnginePath(), "--set-wan"]
    actionProc.running = true
  }

  function copyPortalUrl() {
    copyProc.command = ["wl-copy", root.activeUrl ? root.activeUrl : ("http://" + root.localIp + ":" + root.port)]
    copyProc.running = true
  }

  function openFolder() {
    folderProc.command = ["xdg-open", root.savePath]
    folderProc.running = true
  }

  IpcHandler {
    target: "ozdil.omasend"
    function open() { root.open() }
    function close() { root.close() }
    function toggle() { root.toggle() }
    function refresh() { root.refresh() }
  }

  // Persistent background HTTP daemon
  Process {
    id: serverProc
    command: [root.resolveEnginePath(), "--serve"]
    running: true
  }

  Process {
    id: scanProc
    command: [root.resolveEnginePath(), "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var clean = String(text || "").slice(0, 65536)
          var d = JSON.parse(clean)
          root.localIp = String(d.local_ip || "127.0.0.1")
          root.port = Number(d.port) || 8844
          root.pin = String(d.pin || "----")
          root.sessionKey = String(d.session_key || "")
          root.activeMode = String(d.active_mode || "LAN")
          root.wanActive = Boolean(d.wan_active)
          root.wanConnecting = Boolean(d.wan_connecting)
          root.wanUrl = String(d.wan_url || "")
          root.activeUrl = String(d.active_url || "")
          root.savePath = String(d.download_dir || "~/Downloads/omasend")
          root.qrPath = String(d.qr_path || "")
          root.totalReceived = Number(d.total_received) || 0
          root.recentFiles = d.recent_files || []
          root.sharedFiles = d.shared_files || []
          root.refreshNonce++
        } catch(e) {}
      }
    }
  }

  Process {
    id: actionProc
    onExited: function(code) {
      root.refresh()
    }
  }

  Process { id: copyProc }
  Process { id: folderProc }

  Timer {
    interval: root.wanConnecting ? 1000 : 3000
    running: root.opened || root.wanConnecting
    repeat: true
    onTriggered: root.refresh()
  }

  Component.onCompleted: refresh()
  Component.onDestruction: {
    if (serverProc.running) serverProc.running = false
    if (scanProc.running) scanProc.running = false
    if (actionProc.running) actionProc.running = false
    if (copyProc.running) copyProc.running = false
    if (folderProc.running) folderProc.running = false
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    tooltipText: "OmaSend AirBridge (" + (root.activeMode === "WAN" ? "WAN" : "LAN") + " • E2EE)"
    onPressed: function(b) {
      root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    contentWidth: panel.fittedContentWidth(Style.space(430))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(660))

    ScrollView {
      id: scrollArea
      anchors.fill: parent
      clip: true
      ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
      ScrollBar.vertical.policy: panelColumn.implicitHeight > height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff

      Column {
        id: panelColumn
        width: scrollArea.availableWidth
        spacing: Style.space(12)

        // ---------- Hero: Paper Plane icon · title/status ----------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

          Text {
            id: heroIcon
            textFormat: Text.PlainText
            text: ""
            color: root.bar ? root.bar.foreground : Color.foreground
            font.family: root.bar ? root.bar.fontFamily : Style.font.family
            font.pixelSize: Style.font.display
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            RowLayout {
              width: parent.width
              spacing: Style.space(8)

              Text {
                text: "OmaSend"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.title
                font.bold: true
              }

              Item { Layout.fillWidth: true }

              // E2EE Pill Badge
              Rectangle {
                height: Style.space(20)
                implicitWidth: e2eeBadgeText.implicitWidth + Style.space(12)
                radius: Style.space(10)
                color: "transparent"
                border.color: Color.accent
                border.width: 1

                Text {
                  id: e2eeBadgeText
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: " E2EE"
                  color: Color.accent
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }
            }

            Text {
              textFormat: Text.PlainText
              text: (root.wanConnecting ? "DIŞ AĞ TÜNELİ KURULUYOR..." : (root.activeMode === "WAN" ? "KÜRESEL HAVA KÖPRÜSÜ (WAN)" : "YEREL AĞ KÖPRÜSÜ (LAN)")).toUpperCase()
              color: root.wanConnecting ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.1
            }
          }
        }

        // ---------- Network Mode Switcher (LAN vs WAN) ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "AĞ MODU & BAĞLANTI"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          RowLayout {
            width: parent.width
            spacing: Style.space(6)

            Rectangle {
              Layout.fillWidth: true
              height: Style.space(32)
              radius: Style.space(4)
              color: root.activeMode === "LAN" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
              border.color: root.activeMode === "LAN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
              border.width: 1

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: root.setLanMode()
              }

              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: "  Yerel Ağ (LAN)"
                color: root.activeMode === "LAN" ? (root.bar ? root.bar.foreground : Color.foreground) : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: root.activeMode === "LAN"
              }
            }

            Rectangle {
              Layout.fillWidth: true
              height: Style.space(32)
              radius: Style.space(4)
              color: root.activeMode === "WAN" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
              border.color: root.activeMode === "WAN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
              border.width: 1

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  root.setWanMode()
                }
              }

              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: "  Dış Ağ (WAN)" + (root.wanActive ? " ●" : (root.wanConnecting ? " 󰑐" : ""))
                color: root.activeMode === "WAN" ? (root.bar ? root.bar.foreground : Color.foreground) : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: root.activeMode === "WAN"
              }
            }
          }

          // WAN Tunnel Status Card (if WAN mode is selected)
          Rectangle {
            visible: root.activeMode === "WAN"
            width: parent.width
            implicitHeight: wanCol.implicitHeight + Style.space(16)
            radius: Style.space(6)
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            Column {
              id: wanCol
              anchors.fill: parent
              anchors.margins: Style.space(8)
              spacing: Style.space(6)

              RowLayout {
                width: parent.width
                spacing: Style.space(8)

                Text {
                  Layout.fillWidth: true
                  textFormat: Text.PlainText
                  text: root.wanActive ? "● Dış Ağ Tüneli Aktif" : (root.wanConnecting ? "󰑐 Dış Ağ Tüneli Kuruluyor..." : "○ Tünel Kapalı")
                  color: (root.wanActive || root.wanConnecting) ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Button {
                  text: root.wanActive ? "Tüneli Kapat" : (root.wanConnecting ? "İptal Et" : "Tüneli Başlat")
                  onClicked: root.toggleWan()
                }
              }

              Text {
                visible: root.wanConnecting
                width: parent.width
                textFormat: Text.PlainText
                text: "Cloudflare Edge küresel tüneli oluşturuluyor..."
                color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }

              Text {
                visible: root.wanActive
                width: parent.width
                textFormat: Text.PlainText
                text: root.wanUrl
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideMiddle
              }
            }
          }
        }

        // ---------- QR Code Pairing Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(8)

          PanelSectionHeader {
            text: "QR KOD İLE EŞLEŞ"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          // Crisp QR Card
          Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            width: Style.space(154)
            height: Style.space(154)
            radius: Style.space(8)
            color: "#ffffff"
            border.color: root.bar ? root.bar.foreground : Color.foreground
            border.width: 1

            Image {
              anchors.fill: parent
              anchors.margins: Style.space(8)
              source: root.qrPath ? ("file://" + root.qrPath + "?v=" + root.refreshNonce) : ""
              sourceSize.width: Style.space(138)
              sourceSize.height: Style.space(138)
              fillMode: Image.PreserveAspectFit
              cache: false
            }
          }

          // Active URL row with Copy button
          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.space(4)
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(8)

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: root.activeUrl ? root.activeUrl.replace(/#key=.*$/, "") : ("http://" + root.localIp + ":" + root.port)
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                elide: Text.ElideMiddle
              }

              Button {
                text: "Linki Kopyala"
                onClicked: root.copyPortalUrl()
              }
            }
          }

          // Security PIN & E2EE Info Pill
          Rectangle {
            width: parent.width
            height: Style.space(34)
            radius: Style.space(4)
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                text: "GÜVENLİK PIN: " + root.pin
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }

              Item { Layout.fillWidth: true }

              Text {
                textFormat: Text.PlainText
                text: "QR ile Otomatik E2EE"
                color: Color.accent
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }
          }
        }

        // ---------- E2EE Cryptography Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "UÇTAN UCA ŞİFRELEME (AES-256-GCM)"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.space(4)
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(8)

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: "Anahtar: " + (root.sessionKey.length > 16 ? (root.sessionKey.slice(0, 8) + "..." + root.sessionKey.slice(-8)) : "Aktif")
                color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Button {
                text: "Yeni Anahtar"
                onClicked: root.newKey()
              }
            }
          }
        }

        // ---------- Transfer Path & Files ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "KAYIT KLASÖRÜ & DOSYALAR"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.space(4)
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(8)

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: root.savePath
                color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                elide: Text.ElideMiddle
              }

              Button {
                text: "Klasörü Aç"
                onClicked: root.openFolder()
              }
            }
          }
        }

        // ---------- Actions Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          Button {
            Layout.fillWidth: true
            text: "Yeni PIN"
            onClicked: root.newPin()
          }

          Button {
            Layout.fillWidth: true
            text: "Yenile"
            onClicked: root.refresh()
          }
        }
      }
    }
  }
}
