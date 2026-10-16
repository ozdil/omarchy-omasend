import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Shapes
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "OmaI18n.js" as OmaI18n

Panel {
  id: root
  moduleName: "ozdil.omasend"
  ipcTarget: "ozdil.omasend"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // --- Language (from the session locale) ---
  readonly property string rawSystemLocale: Quickshell.env("LC_ALL")
    || Quickshell.env("LC_MESSAGES")
    || Quickshell.env("LANG")
    || Qt.locale().name
    || "en"
  readonly property string systemLang: OmaI18n.detectLang(root.rawSystemLocale, Qt.locale().name)
  function t(key) { return OmaI18n.tr(root.systemLang, key) }
  function tf(key, a, b) {
    var s = OmaI18n.tr(root.systemLang, key)
    if (a !== undefined) s = s.replace("%1", a)
    if (b !== undefined) s = s.replace("%2", b)
    return s
  }

  // --- Engine state (from `omasend-engine --json`) ---
  property string localIp: "127.0.0.1"
  property int port: 53317
  property string savePath: "~/Downloads/omasend"
  property int totalReceived: 0
  property string visibility: "KNOWN"
  property var discovered: []
  property var pairedDevices: []
  property var pendingTransfer: null
  property var transferProgress: null
  property bool soundEnabled: true
  property string firewallStatus: "OK"
  property string deviceKeyId: ""
  property string hostname: "Omarchy"
  property int refreshNonce: 0

  // --- Pairing card ---
  property bool showPair: false
  property bool pairOwn: true
  property string pairQrPath: ""
  property int pairExpiresAt: 0
  property int nowSecs: 0
  property int pairedCountAtOpen: 0
  property string statusMsg: ""
  property bool statusError: false

  // --- Unpair confirmation (second click within 4 s) ---
  property string armedUnpair: ""
  // Pairing QR found on screen, waiting for the user to confirm (name + device id shown).
  property string scannedPairUri: ""
  property string scannedPairName: ""
  property string scannedPairId: ""
  // Trust for a scanned device is chosen here and is opt-in; the QR's own flag is ignored.
  property bool scannedPairOwn: false

  // --- Drop HUD ---
  property bool dropActive: false
  property bool dropBlasting: false
  property real dropProximity: 0.0
  property real blastProgress: 0.0
  property string blastTargetName: ""
  property int blastedCount: 0

  // --- Keyboard cursor ---
  property int selectedIndex: 0
  property bool cursorActive: false

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property string fontFamily: (root.bar && root.bar.fontFamily)
    ? root.bar.fontFamily
    : ((typeof Style !== "undefined" && Style.font && Style.font.family)
      ? Style.font.family
      : "JetBrainsMono Nerd Font, JetBrains Mono, monospace")

  readonly property string userHome: Quickshell.env("HOME") || ("/home/" + (Quickshell.env("USER") || "user"))
  readonly property string manifestPath: Qt.resolvedUrl("manifest.json").toString().replace(/^file:\/\//, "")
  property string pluginVersion: ""

  readonly property bool serviceOn: root.visibility !== "OFF"

  // Discovered peers that are not QR-paired keys (legacy transport, receiver approves).
  readonly property var nearby: {
    if (!root.serviceOn || !root.discovered) return []
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

  // Keyboard / drop targets: paired devices first, then nearby peers.
  readonly property var targets: {
    var out = []
    for (var i = 0; i < root.pairedDevices.length; i++) {
      var d = root.pairedDevices[i]
      out.push({ kind: "paired", id: d.device_id, name: d.name, address: d.device_id, online: Boolean(d.online), own: Boolean(d.own_device) })
    }
    for (var j = 0; j < root.nearby.length; j++) {
      var p = root.nearby[j]
      out.push({ kind: "nearby", id: p.id, name: p.name, address: p.ip, online: true, own: false })
    }
    return out
  }

  // Default drop target: the single online device of your own.
  readonly property var defaultTarget: {
    var own = []
    for (var i = 0; i < root.targets.length; i++) {
      var t = root.targets[i]
      if (t.kind === "paired" && t.own && t.online) own.push(t)
    }
    if (own.length === 1) return own[0]
    if (root.cursorActive && root.selectedIndex >= 0 && root.selectedIndex < root.targets.length) return root.targets[root.selectedIndex]
    return null
  }

  function shortId(id) {
    var s = String(id || "")
    return s.length > 9 ? s.slice(0, 9) : (s || "----")
  }

  function engine() { return root.userHome + "/.local/bin/omasend-engine" }

  function run(args) {
    if (actionProc.running) actionProc.running = false
    actionProc.command = [root.engine()].concat(args)
    actionProc.running = true
  }

  function refresh() {
    if (!serverProc.running) serverProc.running = true
    if (scanProc.running) scanProc.running = false
    scanProc.running = true
  }

  function forceScan() {
    if (forceScanProc.running) forceScanProc.running = false
    forceScanProc.running = true
  }

  function toggleService() { root.run(["--set-visibility", root.serviceOn ? "OFF" : "KNOWN"]); root.visibility = root.serviceOn ? "OFF" : "KNOWN" }
  function acceptTransfer(token) { root.run(["--accept-transfer", token]) }
  function rejectTransfer(token) { root.run(["--reject-transfer", token]) }
  function cancelTransfer() { root.transferProgress = null; root.run(["--cancel-transfer"]) }
  function toggleSound() { root.soundEnabled = !root.soundEnabled; root.run(["--toggle-sound"]) }
  function syncClipboardTo(address) { root.run(["--sync-clipboard", address]) }

  function sendFileTo(address) {
    if (sendDialogProc.running) sendDialogProc.running = false
    sendDialogProc.command = [root.engine(), "--send-dialog", address]
    sendDialogProc.running = true
  }

  function openFolder() {
    if (folderProc.running) folderProc.running = false
    folderProc.command = ["xdg-open", root.savePath]
    folderProc.running = true
  }

  function copyText(text) {
    if (copyProc.running) copyProc.running = false
    copyProc.command = ["wl-copy", text]
    copyProc.running = true
  }

  function setStatus(msg, isError) {
    root.statusMsg = msg
    root.statusError = Boolean(isError)
    statusClearTimer.restart()
  }

  // --- Pairing ---
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

  function scanScreenForPairing() {
    root.cancelScannedPair()
    root.setStatus(root.t("pair_scanning_screen"), false)
    if (screenScanProc.running) screenScanProc.running = false
    screenScanProc.running = true
  }

  function cancelScannedPair() {
    root.scannedPairUri = ""
    root.scannedPairName = ""
    root.scannedPairId = ""
    root.scannedPairOwn = false
  }

  function confirmScannedPair() {
    if (!root.scannedPairUri) return
    root.setStatus(root.t("pair_connecting"), false)
    if (pairWithProc.running) pairWithProc.running = false
    pairWithProc.output = ""
    pairWithProc.command = [root.engine(), "--pair-with", root.scannedPairUri].concat(root.scannedPairOwn ? ["--own"] : [])
    pairWithProc.running = true
    root.cancelScannedPair()
  }

  function requestUnpair(deviceId) {
    if (root.armedUnpair === deviceId) {
      root.armedUnpair = ""
      root.run(["--unpair", deviceId])
    } else {
      root.armedUnpair = deviceId
      unpairArmTimer.restart()
    }
  }

  function activateTarget(tgt) {
    if (!tgt) return
    root.sendFileTo(tgt.address)
  }

  function moveCursor(dy) {
    if (!root.cursorActive) {
      root.cursorActive = true
      root.selectedIndex = 0
      return
    }
    if (root.targets.length === 0) return
    root.selectedIndex = Math.max(0, Math.min(root.targets.length - 1, root.selectedIndex + dy))
  }

  function activateSelected() {
    if (root.pendingTransfer && root.pendingTransfer.status === "PENDING") {
      root.acceptTransfer(root.pendingTransfer.token)
      return
    }
    if (root.selectedIndex >= 0 && root.selectedIndex < root.targets.length) root.activateTarget(root.targets[root.selectedIndex])
  }

  function handleDroppedData(drop) {
    var files = []
    if (drop.hasUrls && drop.urls.length > 0) {
      for (var i = 0; i < drop.urls.length; i++) {
        var u = drop.urls[i].toString().replace(/^file:\/\//, "")
        try { u = decodeURIComponent(u) } catch (e) {}
        if (u.trim() !== "") files.push(u.trim())
      }
    } else if (drop.hasText && drop.text) {
      var lines = drop.text.split("\n")
      for (var j = 0; j < lines.length; j++) {
        var l = lines[j].replace(/^file:\/\//, "").trim()
        try { l = decodeURIComponent(l) } catch (e) {}
        if (l !== "") files.push(l)
      }
    }
    var tgt = root.defaultTarget
    root.blastedCount = files.length
    root.blastTargetName = tgt ? tgt.name : root.t("drop_choose_target")
    if (tgt && files.length > 0) {
      // One detached transfer for all files (one approval); never killed by other actions.
      Quickshell.execDetached([root.engine(), "--send", tgt.address].concat(files))
    } else if (files.length > 0) {
      root.open()
    }
    root.dropBlasting = true
    blastAnim.restart()
  }

  onOpenedChanged: {
    if (root.opened) {
      root.selectedIndex = 0
      root.cursorActive = false
      root.armedUnpair = ""
      if (panelFlick) panelFlick.contentY = 0
      root.forceScan()
      root.refresh()
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    } else {
      root.showPair = false
    }
  }

  // Pairing finished on the other device: close the card and say so.
  onPairedDevicesChanged: {
    if (root.showPair && root.pairedDevices.length > root.pairedCountAtOpen) {
      var d = root.pairedDevices[root.pairedDevices.length - 1]
      root.showPair = false
      root.setStatus(root.tf("paired_with", d ? d.name : ""), false)
    }
  }

  IpcHandler {
    target: "ozdil.omasend"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.refresh() }
    function pair(): void { root.open(); root.openPairing() }
    function setVisibility(mode: string): void { root.run(["--set-visibility", mode]) }
    function sendFile(target: string): void { root.sendFileTo(target) }
  }

  // --- Processes ---
  Process {
    id: serverProc
    command: [root.engine(), "--serve"]
    running: true
  }

  Process {
    id: forceScanProc
    command: [root.engine(), "--force-scan"]
    onExited: function(code) { forceScanProc.running = false; root.refresh() }
  }

  Process {
    id: scanProc
    command: [root.engine(), "--json"]
    onExited: function(code) { scanProc.running = false }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        scanProc.running = false
        try {
          var d = JSON.parse(String(text || "").slice(0, 262144))
          root.localIp = String(d.local_ip || "127.0.0.1")
          root.port = Number(d.port) || 53317
          root.savePath = String(d.download_dir || "~/Downloads/omasend")
          root.totalReceived = Number(d.total_received) || 0
          root.visibility = (String(d.p2p_visibility || "KNOWN") === "OFF") ? "OFF" : "KNOWN"
          root.discovered = d.p2p_discovered_peers || []
          root.pairedDevices = d.paired_devices || []
          root.pendingTransfer = d.p2p_pending_transfer || null
          root.transferProgress = d.p2p_transfer_progress || null
          if (d.sound_enabled !== undefined) root.soundEnabled = Boolean(d.sound_enabled)
          root.firewallStatus = String(d.firewall_status || "OK")
          root.deviceKeyId = String(d.device_key_id || "")
          root.hostname = String(d.p2p_hostname || "Omarchy")
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
          if (!root.pairQrPath) root.setStatus(root.t("pair_qr_failed"), true)
        } catch (e) {
          root.setStatus(root.t("pair_qr_failed"), true)
        }
      }
    }
  }

  Process {
    id: pairWithProc
    property string output: ""
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: pairWithProc.output = String(text || "").trim() }
    stderr: StdioCollector { waitForEnd: true; onStreamFinished: if (String(text || "").trim() !== "") pairWithProc.output = String(text).trim() }
    onExited: function(code) {
      pairWithProc.running = false
      root.setStatus(pairWithProc.output || (code === 0 ? root.t("paired_ok") : root.t("pair_failed")), code !== 0)
      if (code === 0) root.showPair = false
      root.refresh()
    }
  }

  Process {
    id: pairInspectProc
    property string uri: ""
    property string output: ""
    property string errors: ""
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: pairInspectProc.output = String(text || "").trim() }
    stderr: StdioCollector { waitForEnd: true; onStreamFinished: pairInspectProc.errors = String(text || "").trim() }
    onExited: function(code) {
      pairInspectProc.running = false
      if (code !== 0) {
        root.setStatus(pairInspectProc.errors || root.t("pair_failed"), true)
        return
      }
      try {
        var info = JSON.parse(pairInspectProc.output)
        root.scannedPairName = String(info.name || "?")
        root.scannedPairId = String(info.device_id || "")
        root.scannedPairOwn = false
        root.scannedPairUri = pairInspectProc.uri
        root.setStatus("", false)
      } catch (e) {
        root.setStatus(root.t("pair_failed"), true)
      }
    }
  }

  // Reads a pairing QR shown on this screen (another desktop, a mirrored phone, ...).
  Process {
    id: screenScanProc
    command: ["bash", "-c", "f=$(mktemp --suffix=.png) && /usr/bin/grim \"$f\" 2>/dev/null && (/usr/bin/zbarimg -q --raw \"$f\" 2>/dev/null || true); rm -f \"$f\""]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        screenScanProc.running = false
        var lines = String(text || "").split("\n")
        for (var i = 0; i < lines.length; i++) {
          var l = lines[i].trim()
          if (l.indexOf("omasend://pair?") === 0) {
            // Do not pair yet: show who this is and let the user confirm.
            if (pairInspectProc.running) pairInspectProc.running = false
            pairInspectProc.uri = l
            pairInspectProc.output = ""
            pairInspectProc.errors = ""
            pairInspectProc.command = [root.engine(), "--pair-inspect", l]
            pairInspectProc.running = true
            return
          }
        }
        root.setStatus(root.t("pair_no_qr_on_screen"), true)
      }
    }
  }

  Process {
    id: actionProc
    onExited: function(code) { actionProc.running = false; root.refresh() }
  }

  Process {
    id: sendDialogProc
    onExited: function(code) { sendDialogProc.running = false; root.refresh() }
  }

  Process { id: copyProc }
  Process { id: folderProc }

  FileView {
    id: manifestWatcher
    path: root.manifestPath
    watchChanges: true
    printErrors: false
    onLoaded: {
      try { root.pluginVersion = String(JSON.parse(text()).version || "") } catch (e) {}
    }
    onFileChanged: reload()
  }

  Timer {
    interval: 1000
    running: root.opened
    repeat: true
    onTriggered: {
      root.refresh()
      root.nowSecs = Math.floor(Date.now() / 1000)
      if (root.showPair && root.pairQrPath !== "" && root.nowSecs >= root.pairExpiresAt - 5) root.newPairOffer()
    }
  }

  Timer {
    interval: 5000
    running: true
    repeat: true
    onTriggered: {
      if (!serverProc.running) serverProc.running = true
      if (root.opened) root.refresh()
    }
  }

  Timer { id: statusClearTimer; interval: 6000; onTriggered: root.statusMsg = "" }
  Timer { id: unpairArmTimer; interval: 4000; onTriggered: root.armedUnpair = "" }

  Component.onCompleted: refresh()
  Component.onDestruction: {
    if (serverProc.running) serverProc.running = false
    if (scanProc.running) scanProc.running = false
    if (actionProc.running) actionProc.running = false
    if (sendDialogProc.running) sendDialogProc.running = false
  }

  // =========================================================================
  // BAR BUTTON & DROP SENSOR
  // =========================================================================
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.dropBlasting ? "󰄬" : ""
    active: root.dropActive || root.dropBlasting
    useActiveColor: false
    foreground: (root.dropActive || root.dropBlasting) ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
    tooltipText: "OmaSend · " + root.tf("tooltip_devices", root.onlineCount, root.pairedDevices.length)
    onPressed: function(b) {
      if (b === Qt.RightButton) root.forceScan()
      else root.toggle()
    }

    DropArea {
      id: iconDropArea
      anchors.centerIn: parent
      width: Math.min(320, root.bar ? root.bar.width : 320)
      height: parent.height
      keys: ["text/uri-list", "text/plain", "application/x-kde-urilist"]

      onEntered: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dropHandoffTimer.stop()
          root.dropActive = true
          drag.acceptProposedAction()
          var dist = Math.abs(drag.x - (iconDropArea.width / 2))
          var raw = Math.max(0.35, Math.min(1.0, 1.0 - (dist / (iconDropArea.width / 2))))
          root.dropProximity = 0.5 * (1.0 - Math.cos(raw * Math.PI))
        }
      }
      onPositionChanged: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dropHandoffTimer.stop()
          root.dropActive = true
          drag.acceptProposedAction()
          var dist = Math.abs(drag.x - (iconDropArea.width / 2))
          var raw = Math.max(0.35, Math.min(1.0, 1.0 - (dist / (iconDropArea.width / 2))))
          root.dropProximity = Math.max(root.dropProximity, 0.5 * (1.0 - Math.cos(raw * Math.PI)))
        }
      }
      onExited: dropHandoffTimer.restart()
      onDropped: function(drop) {
        dropHandoffTimer.stop()
        if (drop.hasUrls || drop.hasText) {
          drop.acceptProposedAction()
          root.handleDroppedData(drop)
        }
      }
    }
  }

  Behavior on dropProximity { NumberAnimation { duration: 140; easing.type: Easing.OutCubic } }

  Timer {
    id: dropHandoffTimer
    interval: 160
    onTriggered: {
      if (!iconDropArea.containsDrag && !hudDropArea.containsDrag && !root.dropBlasting) {
        root.dropActive = false
        root.dropProximity = 0.0
      }
    }
  }

  Timer {
    interval: 350
    repeat: true
    running: root.dropActive && !root.dropBlasting
    onTriggered: {
      if (!iconDropArea.containsDrag && !hudDropArea.containsDrag) {
        root.dropActive = false
        root.dropProximity = 0.0
      }
    }
  }

  SequentialAnimation {
    id: blastAnim
    NumberAnimation { target: root; property: "blastProgress"; from: 0.0; to: 1.0; duration: 520; easing.type: Easing.OutCubic }
    ScriptAction {
      script: {
        root.dropBlasting = false
        root.blastProgress = 0.0
        root.dropActive = false
        root.dropProximity = 0.0
      }
    }
  }

  // Drop HUD shown while dragging files over the bar icon.
  PopupCard {
    id: dropHud
    anchorItem: button
    owner: root
    bar: root.bar
    triggerMode: "hover"
    open: (root.dropActive || root.dropBlasting) && !root.opened
    borderColor: (root.dropProximity > 0.72 || root.dropBlasting) ? Color.accent : Color.popups.border
    contentWidth: dropHud.fittedContentWidth(Style.space(276))
    contentHeight: dropHud.fittedContentHeight(Style.space(68))

    DropArea {
      id: hudDropArea
      anchors.fill: parent
      keys: ["text/uri-list", "text/plain", "application/x-kde-urilist"]
      onEntered: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dropHandoffTimer.stop()
          root.dropActive = true
          root.dropProximity = 1.0
          drag.acceptProposedAction()
        }
      }
      onPositionChanged: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dropHandoffTimer.stop()
          root.dropActive = true
          root.dropProximity = 1.0
          drag.acceptProposedAction()
        }
      }
      onExited: dropHandoffTimer.restart()
      onDropped: function(drop) {
        dropHandoffTimer.stop()
        if (drop.hasUrls || drop.hasText) {
          drop.acceptProposedAction()
          root.handleDroppedData(drop)
        }
      }
    }

    RowLayout {
      anchors.fill: parent
      spacing: Style.space(12)

      Item {
        Layout.preferredWidth: Style.space(44)
        Layout.preferredHeight: Style.space(44)
        Layout.alignment: Qt.AlignVCenter

        Shape {
          anchors.fill: parent
          preferredRendererType: Shape.CurveRenderer
          ShapePath {
            strokeWidth: Style.space(3)
            strokeColor: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14)
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap
            PathAngleArc { centerX: Style.space(22); centerY: Style.space(22); radiusX: Style.space(19); radiusY: Style.space(19); startAngle: 0; sweepAngle: 360 }
          }
          ShapePath {
            strokeWidth: Style.space(3)
            strokeColor: Color.accent
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap
            PathAngleArc {
              centerX: Style.space(22); centerY: Style.space(22); radiusX: Style.space(19); radiusY: Style.space(19)
              startAngle: -90
              sweepAngle: 360 * (root.dropBlasting ? 1.0 : Math.min(1.0, 0.25 + root.dropProximity * 0.75))
            }
          }
        }

        Text {
          anchors.centerIn: parent
          textFormat: Text.PlainText
          text: root.dropBlasting ? "󰄬" : ""
          color: Color.accent
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }
      }

      ColumnLayout {
        Layout.fillWidth: true
        Layout.alignment: Qt.AlignVCenter
        spacing: Style.space(2)

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: root.dropBlasting ? root.t("drop_transfer_started") : "OMASEND"
          color: Color.accent
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
          font.letterSpacing: 1.0
          elide: Text.ElideRight
        }
        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: root.dropBlasting ? root.blastTargetName : (root.defaultTarget ? root.defaultTarget.name : root.t("drop_choose_target"))
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
          elide: Text.ElideRight
        }
        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: root.dropBlasting
                ? (root.blastedCount + " " + root.t("sending_files"))
                : (root.defaultTarget && root.defaultTarget.kind === "paired" ? root.t("drop_encrypted_hint") : root.t("drop_here_hint"))
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }
    }
  }

  // =========================================================================
  // MAIN PANEL
  // =========================================================================
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(column.implicitHeight + footer.implicitHeight + Style.space(12), Style.space(600))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) { if (dy !== 0) root.moveCursor(dy) }
      onActivateRequested: root.activateSelected()
      onDeleteRequested: {
        var tg = root.targets[root.selectedIndex]
        if (root.cursorActive && tg && tg.kind === "paired") root.requestUnpair(tg.id)
      }
      onCloseRequested: {
        if (root.showPair) root.showPair = false
        else root.close()
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(key) {
        if (key === "r" || key === "R") root.forceScan()
        else if (key === "o" || key === "O") root.openFolder()
        else if (key === "p" || key === "P") { if (root.showPair) root.showPair = false; else root.openPairing() }
        else if (key === "c" || key === "C") {
          var tg = root.targets[root.selectedIndex]
          if (root.cursorActive && tg) root.syncClipboardTo(tg.address)
        }
      }

      Flickable {
        id: panelFlick
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: footer.top
        anchors.bottomMargin: Style.space(10)
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(12)

          // ---------------------------------------------------------------
          // HERO
          // ---------------------------------------------------------------
          Item {
            width: parent.width
            implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, heroActions.implicitHeight)

            Text {
              id: heroIcon
              textFormat: Text.PlainText
              text: ""
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.display
              opacity: root.serviceOn ? 1.0 : 0.5
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            RowLayout {
              id: heroActions
              spacing: Style.space(8)
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter

              Button {
                iconText: "󰐲"
                tooltipText: root.t("pair_tooltip")
                foreground: root.showPair ? Color.accent : root.foreground
                fontFamily: root.fontFamily
                iconSize: Style.font.subtitle * 1.4
                horizontalPadding: Style.space(5)
                verticalPadding: Style.space(2)
                Layout.alignment: Qt.AlignVCenter
                onClicked: { if (root.showPair) root.showPair = false; else root.openPairing() }
              }

              ToggleSwitch {
                id: powerSwitch
                checked: root.serviceOn
                foreground: root.foreground
                Layout.alignment: Qt.AlignVCenter
                onToggled: root.toggleService()

                PanelToolTip {
                  visible: powerSwitch.containsMouse
                  text: root.serviceOn ? root.t("turn_off_service") : root.t("turn_on_service")
                  fontFamily: root.fontFamily
                }
              }
            }

            Column {
              id: heroLabels
              anchors.left: heroIcon.right
              anchors.leftMargin: Style.space(14)
              anchors.right: parent.right
              anchors.rightMargin: heroActions.width + Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: "OmaSend · " + root.hostname
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
              }
              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.serviceOn ? root.tf("hero_sub_on", root.onlineCount) : root.t("service_disabled_sub")
                color: Qt.darker(root.foreground, 1.4)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.2
                elide: Text.ElideRight
              }
            }
          }

          // ---------------------------------------------------------------
          // INFO GRID
          // ---------------------------------------------------------------
          GridLayout {
            width: parent.width
            columns: 4
            columnSpacing: Style.space(16)
            rowSpacing: Style.spacing.labelGap

            InfoLabel { text: root.t("label_device_id") }
            DetailValue {
              text: root.shortId(root.deviceKeyId)
              copyable: true
              tooltipText: root.deviceKeyId
              onClickedAction: if (root.deviceKeyId) root.copyText(root.deviceKeyId)
            }
            InfoLabel { text: root.t("label_ip_address") }
            DetailValue {
              text: root.localIp
              copyable: true
              tooltipText: root.t("copy_ip_tooltip")
              onClickedAction: root.copyText(root.localIp)
            }
            InfoLabel { text: root.t("label_paired") }
            DetailValue { text: root.onlineCount + "/" + root.pairedDevices.length }
            InfoLabel { text: root.t("label_received") }
            DetailValue {
              text: root.totalReceived + " " + root.t("files_unit")
              copyable: true
              tooltipText: root.t("open_downloads_tooltip")
              onClickedAction: root.openFolder()
            }
          }

          // ---------------------------------------------------------------
          // PAIRING CARD
          // ---------------------------------------------------------------
          BorderSurface {
            visible: root.showPair
            width: parent.width
            implicitHeight: pairCol.implicitHeight + Style.space(20)
            color: Style.normalFillFor(root.foreground, Color.accent)
            borderSpec: Border.controlSpec("normal", root.foreground, Color.accent)
            radius: Style.cornerRadius

            Column {
              id: pairCol
              anchors.centerIn: parent
              width: parent.width - Style.space(20)
              spacing: Style.space(8)

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.t("pair_title")
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.0
              }

              Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                width: Style.space(176)
                height: Style.space(176)
                radius: Style.cornerRadius
                color: "#ffffff"

                Image {
                  anchors.centerIn: parent
                  width: Style.space(164)
                  height: Style.space(164)
                  source: root.pairQrPath ? ("file://" + root.pairQrPath + "?v=" + root.refreshNonce) : ""
                  sourceSize.width: 512
                  sourceSize.height: 512
                  fillMode: Image.PreserveAspectFit
                  smooth: false
                  cache: false
                }
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.t("pair_instructions")
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.tf("pair_expires", Math.max(0, root.pairExpiresAt - root.nowSecs))
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                horizontalAlignment: Text.AlignHCenter
              }

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                ScopePill {
                  label: root.t("pair_own")
                  activeWhen: root.pairOwn
                  onClicked: { if (!root.pairOwn) { root.pairOwn = true; root.newPairOffer() } }
                }
                ScopePill {
                  label: root.t("pair_other")
                  activeWhen: !root.pairOwn
                  onClicked: { if (root.pairOwn) { root.pairOwn = false; root.newPairOffer() } }
                }
                Item { Layout.fillWidth: true }
                PanelActionButton {
                  iconText: "󰐳"
                  tooltipText: root.t("pair_scan_screen_tooltip")
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onClicked: root.scanScreenForPairing()
                }
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.pairOwn ? root.t("pair_own_hint") : root.t("pair_other_hint")
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              // Confirmation for a pairing QR found on screen.
              Text {
                visible: root.scannedPairUri !== ""
                width: parent.width
                textFormat: Text.PlainText
                text: root.tf("pair_scan_confirm", root.scannedPairName, root.scannedPairId)
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              RowLayout {
                visible: root.scannedPairUri !== ""
                width: parent.width
                spacing: Style.space(6)

                ScopePill {
                  label: root.t("pair_own")
                  activeWhen: root.scannedPairOwn
                  onClicked: root.scannedPairOwn = true
                }
                ScopePill {
                  label: root.t("pair_other")
                  activeWhen: !root.scannedPairOwn
                  onClicked: root.scannedPairOwn = false
                }
                Item { Layout.fillWidth: true }
                PanelActionButton {
                  iconText: "󰄬"
                  tooltipText: root.t("pair_scan_confirm_btn")
                  foreground: Color.accent
                  fontFamily: root.fontFamily
                  onClicked: root.confirmScannedPair()
                }
                PanelActionButton {
                  iconText: "󰅖"
                  tooltipText: root.t("reject_btn")
                  foreground: root.urgent
                  hoverColor: root.urgent
                  fontFamily: root.fontFamily
                  onClicked: root.cancelScannedPair()
                }
              }

              Text {
                visible: root.scannedPairUri !== ""
                width: parent.width
                textFormat: Text.PlainText
                text: root.scannedPairOwn ? root.t("pair_own_hint") : root.t("pair_other_hint")
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }
          }

          // Status line for pairing / unpair / errors
          Text {
            visible: root.statusMsg !== ""
            width: parent.width
            textFormat: Text.PlainText
            text: root.statusMsg
            color: root.statusError ? root.urgent : Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          // ---------------------------------------------------------------
          // FIREWALL WARNING
          // ---------------------------------------------------------------
          BorderSurface {
            visible: root.firewallStatus.indexOf("UFW_ACTIVE_CHECK") === 0 || root.firewallStatus.indexOf("UFW_BLOCKED") === 0 || root.firewallStatus.indexOf("NFT_BLOCKED") === 0
            width: parent.width
            implicitHeight: fwRow.implicitHeight + Style.space(12)
            color: Style.normalFillFor(root.foreground, root.urgent)
            borderSpec: Border.controlSpec("normal", root.foreground, root.urgent)
            radius: Style.cornerRadius

            RowLayout {
              id: fwRow
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                text: "󰒃"
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
              }
              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: root.t("firewall_warning_label")
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }
          }

          // ---------------------------------------------------------------
          // INCOMING TRANSFER (needs a decision)
          // ---------------------------------------------------------------
          Column {
            visible: root.pendingTransfer !== null && root.pendingTransfer.status === "PENDING"
            width: parent.width
            spacing: Style.space(8)

            PanelSeparator { foreground: root.foreground }
            PanelSectionHeader {
              text: root.t("incoming_transfer_header")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            CursorSurface {
              width: parent.width
              current: true
              foreground: root.foreground
              implicitHeight: pendingRow.implicitHeight + Style.spacing.rowPaddingX

              RowLayout {
                id: pendingRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(10)
                anchors.rightMargin: Style.space(8)
                spacing: Style.space(8)

                Text {
                  textFormat: Text.PlainText
                  text: "󰇚"
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.title
                  Layout.alignment: Qt.AlignVCenter
                }

                ColumnLayout {
                  Layout.fillWidth: true
                  spacing: Style.space(1)

                  Text {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: root.pendingTransfer ? String(root.pendingTransfer.sender_name || "") : ""
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                  }
                  Text {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: {
                      if (!root.pendingTransfer) return ""
                      var enc = root.pendingTransfer.transport === "quic"
                      return (enc ? "󰌾 " + root.t("encrypted") : "󰌿 " + root.t("not_encrypted"))
                        + " · " + (root.pendingTransfer.file_names || []).join(", ")
                    }
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                  }
                }

                PanelActionButton {
                  iconText: "󰄬"
                  tooltipText: root.t("accept_btn")
                  foreground: Color.accent
                  fontFamily: root.fontFamily
                  onClicked: if (root.pendingTransfer) root.acceptTransfer(root.pendingTransfer.token)
                }
                PanelActionButton {
                  iconText: "󰅖"
                  tooltipText: root.t("reject_btn")
                  foreground: root.urgent
                  hoverColor: root.urgent
                  fontFamily: root.fontFamily
                  onClicked: if (root.pendingTransfer) root.rejectTransfer(root.pendingTransfer.token)
                }
              }
            }
          }

          // ---------------------------------------------------------------
          // ACTIVE TRANSFER
          // ---------------------------------------------------------------
          Column {
            visible: root.transferProgress !== null
            width: parent.width
            spacing: Style.space(8)

            PanelSeparator { foreground: root.foreground }
            PanelSectionHeader {
              text: root.t("active_transfer_header")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            CursorSurface {
              width: parent.width
              current: true
              foreground: root.foreground
              implicitHeight: progressCol.implicitHeight + Style.space(14)

              ColumnLayout {
                id: progressCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(10)
                anchors.rightMargin: Style.space(8)
                spacing: Style.space(6)

                RowLayout {
                  Layout.fillWidth: true
                  spacing: Style.space(8)

                  Text {
                    textFormat: Text.PlainText
                    text: (root.transferProgress && String(root.transferProgress.direction || "").indexOf("send") === 0) ? "" : "󰇚"
                    color: Color.accent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                  }
                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.transferProgress
                          ? (String(root.transferProgress.file_name || "") + " (" + Number(root.transferProgress.percent || 0) + "%)")
                          : ""
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                    elide: Text.ElideRight
                  }
                  PanelActionButton {
                    iconText: "󰅖"
                    tooltipText: root.t("cancel_btn")
                    foreground: root.urgent
                    hoverColor: root.urgent
                    fontFamily: root.fontFamily
                    onClicked: root.cancelTransfer()
                  }
                }

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(4)
                  radius: Style.space(2)
                  color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14)

                  Rectangle {
                    width: parent.width * Math.max(0.02, Math.min(1.0, (root.transferProgress ? Number(root.transferProgress.percent || 0) : 0) / 100.0))
                    height: parent.height
                    radius: parent.radius
                    color: Color.accent
                  }
                }
              }
            }
          }

          // ---------------------------------------------------------------
          // MY DEVICES (QR-paired keys, end-to-end encrypted)
          // ---------------------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          Column {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: root.t("my_devices_header")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              model: root.pairedDevices

              DeviceRow {
                required property var modelData
                required property int index
                width: parent.width
                rowIndex: index
                kind: "paired"
                name: String(modelData.name || "")
                address: String(modelData.device_id || "")
                online: Boolean(modelData.online)
                own: Boolean(modelData.own_device)
                detail: (Boolean(modelData.online) ? (root.t("online") + " · " + String(modelData.ip || "")) : root.t("not_seen"))
                        + " · " + root.shortId(modelData.device_id)
              }
            }

            Text {
              visible: root.pairedDevices.length === 0
              width: parent.width
              textFormat: Text.PlainText
              text: root.t("no_paired_devices")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // ---------------------------------------------------------------
          // NEARBY (not paired: legacy transport, receiver approves)
          // ---------------------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          Column {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: root.t("nearby_header")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              model: root.nearby

              DeviceRow {
                required property var modelData
                required property int index
                width: parent.width
                rowIndex: root.pairedDevices.length + index
                kind: "nearby"
                name: String(modelData.name || "")
                address: String(modelData.ip || "")
                online: true
                own: false
                detail: String(modelData.ip || "") + " · " + root.t("needs_approval")
              }
            }

            Text {
              width: parent.width
              textFormat: Text.PlainText
              text: root.nearby.length === 0
                    ? (root.serviceOn ? root.t("nearby_empty") : root.t("service_disabled_sub"))
                    : root.t("nearby_footnote")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }
        }
      }

      // -----------------------------------------------------------------
      // FOOTER
      // -----------------------------------------------------------------
      Column {
        id: footer
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: Style.space(6)

        PanelSeparator { foreground: root.foreground }

        CursorSurface {
          width: parent.width
          foreground: root.foreground
          implicitHeight: footerRow.implicitHeight + Style.spacing.rowPaddingX

          MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openFolder()
          }

          RowLayout {
            id: footerRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Style.space(10)
            anchors.rightMargin: Style.space(8)
            spacing: Style.space(8)

            Text {
              textFormat: Text.PlainText
              text: "󰉋"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.icon
            }
            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              text: root.t("downloads_footer") + (root.pluginVersion ? ("  ·  v" + root.pluginVersion) : "")
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideRight
            }
            PanelActionButton {
              iconText: root.soundEnabled ? "󰕾" : "󰖁"
              tooltipText: root.soundEnabled ? root.t("sound_on_tooltip") : root.t("sound_off_tooltip")
              foreground: root.soundEnabled ? root.foreground : root.dim
              fontFamily: root.fontFamily
              onClicked: root.toggleSound()
            }
            PanelActionButton {
              iconText: "󰑐"
              tooltipText: root.t("refresh_scan_tooltip")
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.forceScan()
            }
            PanelActionButton {
              iconText: "󰋽"
              tooltipText: root.t("about_tooltip")
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.setStatus(root.t("about_line"), false)
            }
          }
        }
      }
    }
  }

  // =========================================================================
  // COMPONENTS
  // =========================================================================
  component ScopePill: Button {
    required property string label
    property bool activeWhen: false
    text: label
    fontSize: Style.font.caption
    foreground: root.foreground
    fontFamily: root.fontFamily
    horizontalPadding: Style.spacing.controlPaddingX
    verticalPadding: Style.spacing.controlPaddingY
    bordered: true
    active: activeWhen
  }

  component DeviceRow: CursorSurface {
    id: row
    required property int rowIndex
    property string kind: "nearby"
    property string name: ""
    property string address: ""
    property string detail: ""
    property bool online: false
    property bool own: false
    readonly property bool paired: kind === "paired"
    readonly property bool armed: paired && root.armedUnpair === address

    current: paired && online
    hasCursor: root.cursorActive && root.selectedIndex === rowIndex
    foreground: root.foreground
    fill: root.hoverFill
    currentFill: root.selectedFill
    implicitHeight: rowBody.implicitHeight

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton | Qt.RightButton
      cursorShape: Qt.PointingHandCursor
      onEntered: {
        root.cursorActive = true
        root.selectedIndex = row.rowIndex
      }
      onClicked: function(mouse) {
        if (!row.address) return
        if (mouse.button === Qt.RightButton) root.syncClipboardTo(row.address)
        else root.sendFileTo(row.address)
      }
    }

    Item {
      id: rowBody
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(6)
      implicitHeight: Math.max(rowIcon.implicitHeight, rowInfo.implicitHeight, rowActions.implicitHeight) + Style.spacing.rowPaddingX

      Text {
        id: rowIcon
        textFormat: Text.PlainText
        text: /android|phone|pixel|galaxy|sdk_gphone|samsung|xiaomi/i.test(row.name) ? "󰏲" : "󰌢"
        color: (row.paired && row.online) ? root.foreground : Qt.darker(root.foreground, 1.4)
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
      }

      RowLayout {
        id: rowActions
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(2)

        Text {
          textFormat: Text.PlainText
          text: row.paired ? "󰌾" : "󰌿"
          color: row.paired ? Color.accent : Qt.darker(root.foreground, 1.4)
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          Layout.rightMargin: Style.space(4)
        }
        PanelActionButton {
          visible: row.paired
          iconText: "󰅍"
          tooltipText: root.t("send_clipboard_tooltip")
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.syncClipboardTo(row.address)
        }
        PanelActionButton {
          visible: row.paired
          iconText: "󰅖"
          tooltipText: row.armed ? root.t("unpair_confirm_tooltip") : root.t("unpair_tooltip")
          foreground: row.armed ? root.urgent : root.dim
          hoverColor: root.urgent
          bordered: row.armed
          fontFamily: root.fontFamily
          onClicked: root.requestUnpair(row.address)
        }
      }

      Column {
        id: rowInfo
        spacing: Style.space(1)
        anchors.left: rowIcon.right
        anchors.leftMargin: Style.space(10)
        anchors.right: rowActions.left
        anchors.rightMargin: Style.space(6)
        anchors.verticalCenter: parent.verticalCenter

        Text {
          width: parent.width
          textFormat: Text.PlainText
          text: row.name + (row.paired ? (row.own ? "  · " + root.t("badge_own") : "  · " + root.t("badge_paired")) : "")
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }
        Text {
          width: parent.width
          textFormat: Text.PlainText
          text: row.armed ? root.t("unpair_armed") : row.detail
          color: row.armed ? root.urgent : Qt.darker(root.foreground, 1.5)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }
    }
  }

  component DetailValue: InfoValue {
    property bool copyable: false
    property string tooltipText: ""
    signal clickedAction()

    Layout.fillWidth: true
    horizontalAlignment: Text.AlignRight
    elide: Text.ElideRight

    MouseArea {
      id: valueMouse
      anchors.fill: parent
      enabled: parent.copyable && parent.text !== ""
      hoverEnabled: enabled
      cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: parent.clickedAction()
    }

    PanelToolTip {
      visible: valueMouse.enabled && valueMouse.containsMouse && parent.tooltipText !== ""
      text: parent.tooltipText
      fontFamily: root.fontFamily
    }
  }

  component InfoLabel: Text {
    textFormat: Text.PlainText
    color: root.foreground
    opacity: 0.6
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  component InfoValue: Text {
    textFormat: Text.PlainText
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
  }
}
