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
  property int port: 53317
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

  // AirBridge P2P & Bluetooth properties
  property string p2pVisibility: "KNOWN"
  property int p2pVisibilityRemainingSecs: 0
  property bool p2pBtAvailable: false
  property var p2pPeers: []
  property var p2pPendingTransfer: null

  function resolveEnginePath() {
    return Qt.resolvedUrl("omasend-engine").toString().replace(/^file:\/\//, "")
  }

  function executeAction(args) {
    if (actionProc.running) {
      actionProc.running = false
    }
    actionProc.command = [root.resolveEnginePath()].concat(args)
    actionProc.running = true
  }

  function refresh() {
    if (!serverProc.running) {
      serverProc.running = true
    }
    if (scanProc.running) {
      scanProc.running = false
    }
    scanProc.running = true
  }

  function setP2pVisibility(mode) {
    root.p2pVisibility = mode
    if (mode === "EVERYONE") {
      root.p2pVisibilityRemainingSecs = 600
    } else {
      root.p2pVisibilityRemainingSecs = 0
    }
    root.executeAction(["--set-visibility", mode])
  }

  function acceptTransfer(token) {
    root.executeAction(["--accept-transfer", token])
  }

  function rejectTransfer(token) {
    root.executeAction(["--reject-transfer", token])
  }

  function syncClipboardTo(ip) {
    root.executeAction(["--sync-clipboard", ip])
  }

  function sendFileTo(ip) {
    root.executeAction(["--send-dialog", ip])
  }

  function newPin() {
    root.executeAction(["--new-pin"])
  }

  function newKey() {
    root.executeAction(["--new-key"])
  }

  function toggleWan() {
    root.wanConnecting = true
    root.executeAction(["--toggle-wan"])
  }

  function setLanMode() {
    root.activeMode = "LAN"
    root.executeAction(["--set-lan"])
  }

  function setWanMode() {
    root.activeMode = "WAN"
    root.executeAction(["--set-wan"])
  }

  function copyPortalUrl() {
    if (copyProc.running) copyProc.running = false
    copyProc.command = ["wl-copy", root.activeUrl ? root.activeUrl : ("http://" + root.localIp + ":" + root.port)]
    copyProc.running = true
  }

  function openFolder() {
    if (folderProc.running) folderProc.running = false
    folderProc.command = ["xdg-open", root.savePath]
    folderProc.running = true
  }

  IpcHandler {
    target: "ozdil.omasend"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.refresh() }
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
    onExited: function(code) {
      scanProc.running = false
    }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        scanProc.running = false
        try {
          var clean = String(text || "").slice(0, 65536)
          var d = JSON.parse(clean)
          root.localIp = String(d.local_ip || "127.0.0.1")
          root.port = Number(d.port) || 53317
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
          root.p2pVisibility = String(d.p2p_visibility || "KNOWN")
          root.p2pVisibilityRemainingSecs = Number(d.p2p_visibility_remaining_secs) || 0
          root.p2pBtAvailable = Boolean(d.p2p_bluetooth_available)
          root.p2pPeers = d.p2p_discovered_peers || []
          root.p2pPendingTransfer = d.p2p_pending_transfer || null
          root.refreshNonce++
        } catch(e) {}
      }
    }
  }

  Process {
    id: actionProc
    onExited: function(code) {
      actionProc.running = false
      root.refresh()
    }
  }

  Process { id: copyProc }
  Process { id: folderProc }

  Timer {
    id: refreshTimer
    interval: root.wanConnecting ? 1000 : 3000
    running: root.opened || root.wanConnecting
    repeat: true
    onTriggered: root.refresh()
  }

  // Background watchdog to restart engine if terminated
  Timer {
    id: watchdogTimer
    interval: 5000
    running: true
    repeat: true
    onTriggered: {
      if (!serverProc.running) {
        serverProc.running = true
      }
      if (root.opened) {
        root.refresh()
      }
    }
  }

  Component.onCompleted: refresh()
  Component.onDestruction: {
    if (serverProc.running) serverProc.running = false
    if (scanProc.running) scanProc.running = false
    if (actionProc.running) actionProc.running = false
    if (copyProc.running) copyProc.running = false
    if (folderProc.running) folderProc.running = false
    if (refreshTimer.running) refreshTimer.running = false
    if (watchdogTimer.running) watchdogTimer.running = false
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    foreground: root.wanActive ? "#f59e0b" : (root.bar ? root.bar.foreground : Color.foreground)
    tooltipText: "OmaSend AirBridge (" + (root.activeMode === "WAN" ? "WAN Active (Tunnel)" : "LAN (Local Only)") + " • E2EE)"
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
                textFormat: Text.PlainText
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
                radius: Style.cornerRadius
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
              text: (root.wanConnecting ? "ESTABLISHING WAN TUNNEL..." : (root.activeMode === "WAN" ? "GLOBAL AIRBRIDGE (WAN)" : "LOCAL NETWORK BRIDGE (LAN)")).toUpperCase()
              color: root.wanConnecting ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.1
            }
          }
        }

        // ---------- Gatekeeper Transfer Request (If Pending) ----------
        Rectangle {
          visible: root.p2pPendingTransfer !== null && root.p2pPendingTransfer.status === "PENDING"
          width: parent.width
          implicitHeight: pendingCol.implicitHeight + Style.space(16)
          radius: Style.cornerRadius
          color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)
          border.color: Color.accent
          border.width: 1

          Column {
            id: pendingCol
            anchors.fill: parent
            anchors.margins: Style.space(10)
            spacing: Style.space(6)

            RowLayout {
              width: parent.width
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                text: "📁"
                color: Color.accent
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.body
              }

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: "INCOMING AIRBRIDGE TRANSFER"
                color: Color.accent
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }

            Text {
              width: parent.width
              wrapMode: Text.Wrap
              textFormat: Text.PlainText
              text: root.p2pPendingTransfer ? ("From: " + root.p2pPendingTransfer.sender_name + " (" + root.p2pPendingTransfer.sender_ip + ")\nFiles: " + (root.p2pPendingTransfer.file_names || []).join(", ") + " (" + ((root.p2pPendingTransfer.total_size_bytes || 0) / 1024 / 1024).toFixed(1) + " MB)") : ""
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.bodySmall
            }

            RowLayout {
              width: parent.width
              spacing: Style.space(8)

              Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: Style.space(28)
                radius: Style.cornerRadius
                color: Color.accent
                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: " ACCEPT"
                  color: "#000000"
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                MouseArea {
                  anchors.fill: parent
                  z: 10
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    if (root.p2pPendingTransfer) root.acceptTransfer(root.p2pPendingTransfer.token)
                  }
                }
              }

              Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: Style.space(28)
                radius: Style.cornerRadius
                color: "transparent"
                border.color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                border.width: 1
                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: " DECLINE"
                  color: root.bar ? root.bar.foreground : Color.foreground
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                MouseArea {
                  anchors.fill: parent
                  z: 10
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    if (root.p2pPendingTransfer) root.rejectTransfer(root.p2pPendingTransfer.token)
                  }
                }
              }
            }
          }
        }

        // ---------- AirBridge P2P & Bluetooth (AirDrop) ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(8)

          RowLayout {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              Layout.fillWidth: true
              text: "AIRDROP & PEER DISCOVERY"
              foreground: root.bar ? root.bar.foreground : Color.foreground
              fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
            }

            // Bluetooth Status Indicator
            Rectangle {
              visible: root.p2pBtAvailable
              height: Style.space(18)
              implicitWidth: btPillText.implicitWidth + Style.space(10)
              radius: Style.cornerRadius
              color: "transparent"
              border.color: Color.accent
              border.width: 1

              Text {
                id: btPillText
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: " BT READY"
                color: Color.accent
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }
          }

          // 3-Tier Visibility Selector
          RowLayout {
            width: parent.width
            spacing: Style.space(6)

            // OFF Button
            Rectangle {
              Layout.fillWidth: true
              Layout.preferredHeight: Style.space(26)
              radius: Style.cornerRadius
              color: root.p2pVisibility === "OFF" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
              border.color: root.p2pVisibility === "OFF" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
              border.width: 1

              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: "OFF"
                color: root.p2pVisibility === "OFF" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: root.p2pVisibility === "OFF"
              }

              MouseArea {
                anchors.fill: parent
                z: 10
                cursorShape: Qt.PointingHandCursor
                onClicked: root.setP2pVisibility("OFF")
              }
            }

            // KNOWN PEERS Button
            Rectangle {
              Layout.fillWidth: true
              Layout.preferredHeight: Style.space(26)
              radius: Style.cornerRadius
              color: root.p2pVisibility === "KNOWN" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
              border.color: root.p2pVisibility === "KNOWN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
              border.width: 1

              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: "KNOWN PEERS"
                color: root.p2pVisibility === "KNOWN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: root.p2pVisibility === "KNOWN"
              }

              MouseArea {
                anchors.fill: parent
                z: 10
                cursorShape: Qt.PointingHandCursor
                onClicked: root.setP2pVisibility("KNOWN")
              }
            }

            // EVERYONE 10M Button
            Rectangle {
              Layout.fillWidth: true
              Layout.preferredHeight: Style.space(26)
              radius: Style.cornerRadius
              color: root.p2pVisibility === "EVERYONE" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
              border.color: root.p2pVisibility === "EVERYONE" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
              border.width: 1

              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: root.p2pVisibility === "EVERYONE" && root.p2pVisibilityRemainingSecs > 0 ? ("EVERYONE (" + Math.floor(root.p2pVisibilityRemainingSecs / 60) + ":" + (root.p2pVisibilityRemainingSecs % 60 < 10 ? "0" : "") + (root.p2pVisibilityRemainingSecs % 60) + ")") : "EVERYONE (10M)"
                color: root.p2pVisibility === "EVERYONE" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: root.p2pVisibility === "EVERYONE"
              }

              MouseArea {
                anchors.fill: parent
                z: 10
                cursorShape: Qt.PointingHandCursor
                onClicked: root.setP2pVisibility("EVERYONE")
              }
            }
          }

          // Discovered Peers List
          Column {
            width: parent.width
            spacing: Style.space(6)

            Text {
              visible: root.p2pPeers.length === 0
              width: parent.width
              textFormat: Text.PlainText
              text: root.p2pVisibility === "OFF" ? "AirBridge visibility is turned off." : "Scanning for nearby Omarchy devices on local network & Bluetooth..."
              color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.5)
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
              font.italic: true
            }

            Repeater {
              model: root.p2pPeers

              Rectangle {
                width: parent.width
                implicitHeight: Style.space(38)
                radius: Style.cornerRadius
                color: "transparent"
                border.color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(8)
                  spacing: Style.space(8)

                  Text {
                    textFormat: Text.PlainText
                    text: modelData.transport === "BT" ? "" : (modelData.transport === "HYBRID" ? "⚡" : "💻")
                    color: modelData.transport === "BT" ? "#3b82f6" : (modelData.transport === "HYBRID" ? "#a855f7" : Color.accent)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.body
                  }

                  Column {
                    Layout.fillWidth: true
                    spacing: 0
                    RowLayout {
                      spacing: Style.space(6)
                      Text {
                        textFormat: Text.PlainText
                        text: modelData.name || "Omarchy Device"
                        color: root.bar ? root.bar.foreground : Color.foreground
                        font.family: root.bar ? root.bar.fontFamily : Style.font.family
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                      }
                      Rectangle {
                        implicitWidth: badgeText.implicitWidth + Style.space(8)
                        implicitHeight: Style.space(16)
                        radius: Style.cornerRadius
                        color: modelData.transport === "BT" ? "#1e3a8a" : (modelData.transport === "HYBRID" ? "#581c87" : "#064e3b")
                        Text {
                          id: badgeText
                          anchors.centerIn: parent
                          textFormat: Text.PlainText
                          text: modelData.transport
                          color: modelData.transport === "BT" ? "#93c5fd" : (modelData.transport === "HYBRID" ? "#d8b4fe" : "#6ee7b7")
                          font.family: root.bar ? root.bar.fontFamily : Style.font.family
                          font.pixelSize: 9
                          font.bold: true
                        }
                      }
                    }
                    Text {
                      textFormat: Text.PlainText
                      text: (modelData.ip.startsWith("bt:") ? "Bluetooth Paired" : modelData.ip) + (modelData.is_trusted ? " • TRUSTED" : "")
                      color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                      font.family: root.bar ? root.bar.fontFamily : Style.font.family
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Rectangle {
                    Layout.preferredWidth: Style.space(64)
                    Layout.preferredHeight: Style.space(24)
                    radius: Style.cornerRadius
                    color: Color.accent

                    Text {
                      anchors.centerIn: parent
                      textFormat: Text.PlainText
                      text: "📁 SEND"
                      color: "#000000"
                      font.family: root.bar ? root.bar.fontFamily : Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }

                    MouseArea {
                      anchors.fill: parent
                      z: 10
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.sendFileTo(modelData.ip)
                    }
                  }

                  Rectangle {
                    visible: !modelData.ip.startsWith("bt:")
                    Layout.preferredWidth: Style.space(86)
                    Layout.preferredHeight: Style.space(24)
                    radius: Style.cornerRadius
                    color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)
                    border.color: Color.accent
                    border.width: 1

                    Text {
                      anchors.centerIn: parent
                      textFormat: Text.PlainText
                      text: "📋 CLIPBOARD"
                      color: Color.accent
                      font.family: root.bar ? root.bar.fontFamily : Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }

                    MouseArea {
                      anchors.fill: parent
                      z: 10
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.syncClipboardTo(modelData.ip)
                    }
                  }
                }
              }
            }
          }
        }

        // ---------- Network Mode & QR Pairing (Side-by-Side) ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(8)

          PanelSectionHeader {
            text: "NETWORK MODE & PAIRING"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          RowLayout {
            width: parent.width
            spacing: Style.space(10)

            // Crisp QR Card (Left, 132x132)
            Rectangle {
              Layout.preferredWidth: Style.space(132)
              Layout.preferredHeight: Style.space(132)
              radius: Style.cornerRadius
              color: "#ffffff"
              border.color: root.bar ? root.bar.foreground : Color.foreground
              border.width: 1

              Image {
                anchors.fill: parent
                anchors.margins: Style.space(6)
                source: root.qrPath ? ("file://" + root.qrPath + "?v=" + root.refreshNonce) : ""
                sourceSize.width: Style.space(120)
                sourceSize.height: Style.space(120)
                fillMode: Image.PreserveAspectFit
                cache: false
              }
            }

            // Network Mode Switcher & WAN Controls (Right)
            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredHeight: Style.space(132)
              spacing: Style.space(6)

              // Local Network (LAN) Button
              Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: Style.space(32)
                radius: Style.cornerRadius
                color: root.activeMode === "LAN" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
                border.color: root.activeMode === "LAN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    text: ""
                    color: root.activeMode === "LAN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.bodySmall
                  }

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: "Local Network (LAN)"
                    color: root.activeMode === "LAN" ? (root.bar ? root.bar.foreground : Color.foreground) : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    font.bold: root.activeMode === "LAN"
                  }

                  Text {
                    visible: root.activeMode === "LAN"
                    textFormat: Text.PlainText
                    text: "●"
                    color: Color.accent
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.caption
                  }
                }

                MouseArea {
                  anchors.fill: parent
                  z: 10
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.setLanMode()
                }
              }

              // Global WAN Button
              Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: Style.space(32)
                radius: Style.cornerRadius
                color: root.activeMode === "WAN" ? Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent) : "transparent"
                border.color: root.activeMode === "WAN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    text: ""
                    color: root.activeMode === "WAN" ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.bodySmall
                  }

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: "Global WAN"
                    color: root.activeMode === "WAN" ? (root.bar ? root.bar.foreground : Color.foreground) : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    font.bold: root.activeMode === "WAN"
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: root.wanActive ? "●" : (root.wanConnecting ? "󰑐" : "")
                    color: Color.accent
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.caption
                  }
                }

                MouseArea {
                  anchors.fill: parent
                  z: 10
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.setWanMode()
                }
              }

              // Network Status / Action Card
              Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: Style.cornerRadius
                color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(8)
                  spacing: Style.space(6)

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.activeMode === "WAN" ?
                          (root.wanActive ? "● Tunnel Active" : (root.wanConnecting ? "󰑐 Connecting..." : "○ Tunnel Offline")) :
                          " Same Wi-Fi Network"
                    color: (root.wanActive || root.wanConnecting) ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    elide: Text.ElideRight
                  }

                  Button {
                    visible: root.activeMode === "WAN"
                    text: root.wanActive ? "Stop" : (root.wanConnecting ? "Cancel" : "Start")
                    onClicked: root.toggleWan()
                  }
                }
              }
            }
          }

          // Active URL row with Copy button
          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.cornerRadius
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
                text: "Copy Link"
                onClicked: root.copyPortalUrl()
              }
            }
          }
        }

        // ---------- Security PIN Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "SECURITY PIN"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.cornerRadius
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(8)

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: "PIN: " + root.pin
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }

              Button {
                text: "New PIN"
                onClicked: root.newPin()
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
            text: "END-TO-END ENCRYPTION (AES-256-GCM)"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.cornerRadius
            color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(8)

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: "Key: " + (root.sessionKey.length > 16 ? (root.sessionKey.slice(0, 8) + "..." + root.sessionKey.slice(-8)) : "Active")
                color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Button {
                text: "New Key"
                onClicked: root.newKey()
              }
            }
          }
        }

        // ---------- Download Directory Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "DOWNLOAD DIRECTORY"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Rectangle {
            width: parent.width
            height: Style.space(36)
            radius: Style.cornerRadius
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
                text: "Open Folder"
                onClicked: root.openFolder()
              }
            }
          }
        }

        // ---------- Footer / Actions Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: "OmaSend AirBridge • Port " + root.port
            color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.5)
            font.family: root.bar ? root.bar.fontFamily : Style.font.family
            font.pixelSize: Style.font.caption
          }

          Button {
            text: "Refresh"
            onClicked: root.refresh()
          }
        }
      }
    }
  }
}
