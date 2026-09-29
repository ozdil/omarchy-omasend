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
  property bool showAboutModal: false

  // Selected peer for cursor navigation
  property int selectedPeerIndex: 0
  property bool cursorActive: false
  property string focusedPeerIp: ""

  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property string fontFamily: (root.bar && root.bar.fontFamily) ? root.bar.fontFamily : ((typeof Style !== "undefined" && Style.font && Style.font.family) ? Style.font.family : "JetBrainsMono Nerd Font, JetBrains Mono, monospace")

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
    if (mode === "OFF") {
      root.p2pPeers = []
    }
    root.executeAction(["--set-visibility", mode])
  }

  function toggleVisibility() {
    if (root.p2pVisibility === "OFF") {
      root.setP2pVisibility("KNOWN")
    } else if (root.p2pVisibility === "KNOWN") {
      root.setP2pVisibility("EVERYONE")
    } else {
      root.setP2pVisibility("OFF")
    }
  }

  function moveCursor(dy) {
    if (!cursorActive) {
      cursorActive = true
      selectedPeerIndex = 0
      return
    }
    var len = root.p2pPeers ? root.p2pPeers.length : 0
    if (len === 0) return
    var next = selectedPeerIndex + dy
    if (next < 0) next = 0
    if (next >= len) next = len - 1
    selectedPeerIndex = next
  }

  function activateSelected() {
    if (root.p2pPendingTransfer) {
      root.acceptTransfer(root.p2pPendingTransfer.token)
      return
    }
    if (root.p2pPeers && root.p2pPeers.length > selectedPeerIndex) {
      var peer = root.p2pPeers[selectedPeerIndex]
      if (peer && peer.ip) {
        root.sendFileTo(peer.ip)
      }
    }
  }

  onOpenedChanged: {
    if (root.opened) {
      selectedPeerIndex = 0
      cursorActive = false
      root.refresh()
    }
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
    if (sendDialogProc.running) sendDialogProc.running = false
    sendDialogProc.command = [root.resolveEnginePath(), "--send-dialog", ip]
    sendDialogProc.running = true
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
    function setVisibility(mode: string): void { root.setP2pVisibility(mode) }
    function sendFile(ip: string): void { root.sendFileTo(ip) }
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

  Process {
    id: sendDialogProc
    onExited: function(code) {
      sendDialogProc.running = false
      root.refresh()
    }
  }

  Process { id: copyProc }
  Process { id: folderProc }
  Process {
    id: playSendSoundProc
    command: ["pw-play", Qt.resolvedUrl("assets/send_whoosh.wav").toString().replace(/^file:\/\//, "")]
  }

  Timer {
    id: refreshTimer
    interval: 3000
    running: root.opened
    repeat: true
    onTriggered: root.refresh()
  }

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
    if (sendDialogProc.running) sendDialogProc.running = false
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
    foreground: root.bar ? root.bar.foreground : Color.foreground
    tooltipText: "OmaSend AirBridge (" + root.p2pVisibility + ")"
    onPressed: function(b) {
      root.toggle()
    }

    // Dosya ikonun üzerine sürüklendiğinde büyüyen ve camlaşan Drop Alanı
    DropArea {
      id: iconDropArea
      anchors.fill: parent
      z: 50

      onEntered: function(drag) {
        if (drag.hasUrls) {
          drag.acceptProposedAction()
        }
      }

      onDropped: function(drop) {
        if (drop.hasUrls && drop.urls.length > 0) {
          drop.acceptProposedAction()
          var firstFile = drop.urls[0].toString().replace(/^file:\/\//, "")

          // Akustik fırlatma sesini başlat
          if (playSendSoundProc.running) playSendSoundProc.running = false
          playSendSoundProc.running = true

          var targetIp = ""
          if (root.p2pPeers && root.p2pPeers.length > 0) {
            targetIp = root.p2pPeers[0].ip
          }
          if (targetIp !== "") {
            root.executeAction(["--send", targetIp, firstFile])
          }
        }
      }
    }

    // İkonun üstünde büyüyen nefes alan akrilik cam halka (Glassmorphic Bubble)
    Rectangle {
      id: glassBubble
      anchors.centerIn: parent
      width: iconDropArea.containsDrag ? 72 : 0
      height: iconDropArea.containsDrag ? 72 : 0
      radius: width / 2
      color: Qt.rgba(0.06, 0.08, 0.14, 0.82)
      border.color: Qt.rgba(0.4, 0.8, 1.0, 0.85)
      border.width: 1.5
      opacity: iconDropArea.containsDrag ? 1.0 : 0.0
      scale: iconDropArea.containsDrag ? 1.0 : 0.4
      z: 60

      Behavior on width { NumberAnimation { duration: 220; easing.type: Easing.OutBack } }
      Behavior on height { NumberAnimation { duration: 220; easing.type: Easing.OutBack } }
      Behavior on opacity { NumberAnimation { duration: 180 } }
      Behavior on scale { NumberAnimation { duration: 220; easing.type: Easing.OutBack } }

      // İç Işık Kırılması
      Rectangle {
        anchors.fill: parent
        anchors.margins: 2
        radius: parent.radius - 2
        color: "transparent"
        border.color: Qt.rgba(1.0, 1.0, 1.0, 0.25)
        border.width: 1
      }

      // Nefes Alan Dış Dalgalanma
      Rectangle {
        anchors.centerIn: parent
        width: parent.width + 12
        height: parent.height + 12
        radius: (parent.width + 12) / 2
        color: "transparent"
        border.color: Color.accent
        border.width: 1
        opacity: 0.4

        SequentialAnimation on opacity {
          running: iconDropArea.containsDrag
          loops: Animation.Infinite
          NumberAnimation { from: 0.2; to: 0.8; duration: 700; easing.type: Easing.InOutQuad }
          NumberAnimation { from: 0.8; to: 0.2; duration: 700; easing.type: Easing.InOutQuad }
        }
      }

      Column {
        anchors.centerIn: parent
        spacing: 2

        Text {
          anchors.horizontalCenter: parent.horizontalCenter
          textFormat: Text.PlainText
          text: ""
          color: Color.accent
          font.family: root.fontFamily
          font.pixelSize: 20
        }

        Text {
          anchors.horizontalCenter: parent.horizontalCenter
          textFormat: Text.PlainText
          text: (root.p2pPeers && root.p2pPeers.length > 0) ? root.p2pPeers[0].name : "BIRAKIN"
          color: "#ffffff"
          font.family: root.fontFamily
          font.pixelSize: 8
          font.bold: true
          elide: Text.ElideRight
          width: 58
          horizontalAlignment: Text.AlignHCenter
        }
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(root.showAboutModal ? Math.max(panelColumn.implicitHeight, aboutCol.implicitHeight + Style.space(40)) : panelColumn.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: {
        if (root.showAboutModal) {
          root.showAboutModal = false
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) { root.moveCursor(dy) }
      onActivateRequested: root.activateSelected()
      onTextKey: function(t) {
        if (t === "r" || t === "R") {
          root.refresh()
        } else if (t === "v" || t === "V") {
          root.toggleVisibility()
        } else if (t === "a" || t === "A") {
          root.showAboutModal = !root.showAboutModal
        } else if (t === "c" || t === "C") {
          root.copyPortalUrl()
        } else if (t === "o" || t === "O") {
          root.openFolder()
        }
      }

      Column {
        id: panelColumn
        anchors.fill: parent
        spacing: Style.space(14)

        // ---------- Hero: OmaSend icon · title · Visibility Toggle ----------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, powerSwitch.implicitHeight)

          Text {
            id: heroIcon
            textFormat: Text.PlainText
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: ""
            color: root.bar ? root.bar.foreground : Color.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
            opacity: root.p2pVisibility !== "OFF" ? 1.0 : 0.5
          }

          ToggleSwitch {
            id: powerSwitch
            checked: root.p2pVisibility !== "OFF"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            onToggled: root.toggleVisibility()

            PanelToolTip {
              visible: powerSwitch.containsMouse
              text: root.p2pVisibility !== "OFF" ? "Disable OmaSend discovery" : "Enable OmaSend discovery"
              fontFamily: root.fontFamily
            }
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: parent.right
            anchors.rightMargin: powerSwitch.width + Style.space(12)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Text {
              text: "OmaSend"
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
              elide: Text.ElideRight
              width: parent.width
            }

            Text {
              textFormat: Text.PlainText
              text: (root.p2pVisibility === "OFF" ? "DISCOVERY OFF" : (root.p2pVisibility === "EVERYONE" ? ("EVERYONE (" + Math.max(1, Math.floor(root.p2pVisibilityRemainingSecs / 60)) + "M)") : "KNOWN PEERS")).toUpperCase()
              color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.2
              elide: Text.ElideRight
              width: parent.width
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
                text: ""
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
              }

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: "INCOMING AIRBRIDGE TRANSFER"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }

            Text {
              width: parent.width
              wrapMode: Text.Wrap
              textFormat: Text.PlainText
              text: root.p2pPendingTransfer ? ("From: " + root.p2pPendingTransfer.sender_name + "\nFiles: " + (root.p2pPendingTransfer.file_names || []).join(", ") + " (" + ((root.p2pPendingTransfer.total_size_bytes || 0) / 1024 / 1024).toFixed(1) + " MB)") : ""
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.fontFamily
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
                  text: "ACCEPT"
                  color: "#000000"
                  font.family: root.fontFamily
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
                  text: "DECLINE"
                  color: root.bar ? root.bar.foreground : Color.foreground
                  font.family: root.fontFamily
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

        // ---------- Section: PAIRED / AVAILABLE DEVICES ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          id: peersSection
          width: parent.width
          spacing: Style.space(10)

          PanelSectionHeader {
            text: "DEVICES"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.fontFamily
          }

          Repeater {
            model: root.p2pVisibility === "OFF" ? [] : root.p2pPeers

            CursorSurface {
              id: peerRow
              required property var modelData
              required property int index
              width: peersSection.width
              implicitHeight: peerRowContent.implicitHeight + Style.spacing.rowPaddingX
              foreground: root.bar ? root.bar.foreground : Color.foreground
              fill: root.hoverFill
              currentFill: root.selectedFill
              current: false
              hasCursor: root.cursorActive && root.selectedPeerIndex === index

              MouseArea {
                id: rowMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onEntered: {
                  root.cursorActive = true
                  root.selectedPeerIndex = index
                }
                onClicked: {
                  root.sendFileTo(modelData.ip)
                }
              }

              Item {
                id: peerRowContent
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(10)
                anchors.rightMargin: Style.space(10)
                implicitHeight: Math.max(devIcon.implicitHeight, devInfo.implicitHeight, actionBtns.implicitHeight)

                Text {
                  id: devIcon
                  textFormat: Text.PlainText
                  text: modelData.transport === "BT" ? "" : (modelData.transport === "HYBRID" ? "󱘖" : "")
                  color: root.bar ? root.bar.foreground : Color.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.heading
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                }

                Column {
                  id: devInfo
                  spacing: Style.space(1)
                  anchors.left: devIcon.right
                  anchors.leftMargin: Style.space(10)
                  anchors.right: actionBtns.left
                  anchors.rightMargin: Style.space(8)
                  anchors.verticalCenter: parent.verticalCenter

                  Text {
                    textFormat: Text.PlainText
                    text: modelData.name || "Omarchy Device"
                    color: root.bar ? root.bar.foreground : Color.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                    width: parent.width
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: modelData.transport === "BT" ? "Bluetooth Paired" : "Ready to Send"
                    color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.5)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                    width: parent.width
                  }
                }

                RowLayout {
                  id: actionBtns
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(6)

                  PanelActionButton {
                    iconText: ""
                    tooltipText: "Send File"
                    foreground: root.bar ? root.bar.foreground : Color.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.sendFileTo(modelData.ip)
                  }

                  PanelActionButton {
                    iconText: ""
                    tooltipText: "Send Clipboard"
                    foreground: root.bar ? root.bar.foreground : Color.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.syncClipboardTo(modelData.ip)
                  }
                }
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: root.p2pVisibility === "OFF" || root.p2pPeers.length === 0
            text: root.p2pVisibility === "OFF" ? "Turn discovery on to scan for devices." : "Scanning for nearby devices..."
            color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.5)
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
            width: parent.width
          }
        }

        // ---------- Footer / Actions Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          PanelActionButton {
            iconText: "󰋽"
            tooltipText: "About OmaSend"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.fontFamily
            onClicked: root.showAboutModal = !root.showAboutModal
          }

          PanelActionButton {
            iconText: ""
            tooltipText: "Open Received Files Folder"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.fontFamily
            onClicked: root.openFolder()
          }

          Item { Layout.fillWidth: true }

          Button {
            text: root.p2pVisibility === "EVERYONE" ? "EVERYONE" : "KNOWN"
            bordered: true
            fontSize: Style.font.caption
            fontFamily: root.fontFamily
            onClicked: root.toggleVisibility()
          }

          Button {
            text: "Refresh"
            bordered: true
            fontSize: Style.font.caption
            fontFamily: root.fontFamily
            onClicked: root.refresh()
          }
        }
      }
    }

    // About & Imprint Modal Overlay
    Rectangle {
      id: aboutOverlay
      anchors.fill: parent
      visible: root.showAboutModal
      color: Qt.rgba(0.05, 0.05, 0.07, 0.96)
      z: 99

      MouseArea {
        anchors.fill: parent
      }

      Column {
        id: aboutCol
        anchors.centerIn: parent
        width: parent.width - Style.space(40)
        spacing: Style.space(12)

        Row {
          width: parent.width
          Item {
            width: parent.width - closeAboutBtn.implicitWidth
            implicitHeight: aboutTitleText.implicitHeight
            Text {
              id: aboutTitleText
              text: "OmaSend"
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }
          }

          Button {
            id: closeAboutBtn
            text: "✕"
            bordered: true
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.caption
            onClicked: root.showAboutModal = false
          }
        }

        Text {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "Version: 1.3.1\nDeveloper: Ozan Ozdil (@ozdil)\nLicense: MIT\nAirBridge P2P, E2EE Secure Local & Network File Transfer System"
          color: root.bar ? root.bar.foreground : Color.foreground
          opacity: 0.7
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          lineHeight: 1.3
        }

        PanelSeparator {
          width: parent.width
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Button {
          width: parent.width
          text: "GitHub / Contact"
          iconText: "󰊤"
          bordered: true
          foreground: root.bar ? root.bar.foreground : Color.foreground
          accent: Color.accent
          fontFamily: root.fontFamily
          fontSize: Style.font.caption
          onClicked: Qt.openUrlExternally("https://github.com/ozdil")
        }

        Button {
          width: parent.width
          text: "Buy Me a Coffee"
          iconText: "󰅖"
          bordered: true
          foreground: "#000000"
          color: "#FFDD00"
          fontFamily: root.fontFamily
          fontSize: Style.font.caption
          onClicked: Qt.openUrlExternally("https://buymeacoffee.com/ozdil")
        }
      }
    }
  }
}
