import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
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

  // AirBridge P2P (Strict OmaID) properties
  property string p2pVisibility: "KNOWN"
  property int p2pVisibilityRemainingSecs: 0
  property var p2pPeers: []
  property var p2pPendingTransfer: null
  property bool showAboutModal: false
  property bool showOmaIdQrModal: false
  property bool showOmaIdPairModal: false

  // 16-Digit OmaID & Profile State
  property string omaId: ""
  property string omaidQrPath: ""
  property bool omaIdRevealed: true
  property bool omaIdCopiedFeedback: false

  // OmaID Pairing & Scan State
  property string pairInputOmaId: ""
  property string pairInputName: ""
  property string pairStatusMsg: ""
  property bool pairStatusError: false

  // Selected peer for cursor navigation
  property int selectedPeerIndex: 0
  property bool cursorActive: false
  property string focusedPeerIp: ""

  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, Color.accent) : "transparent"
  readonly property string fontFamily: (root.bar && root.bar.fontFamily) ? root.bar.fontFamily : ((typeof Style !== "undefined" && Style.font && Style.font.family) ? Style.font.family : "JetBrainsMono Nerd Font, JetBrains Mono, monospace")
  readonly property string peersPath: (Quickshell.env("HOME") || "/home/ozdil") + "/.local/state/omarchy/omasend/discovered_peers.json"
  readonly property string omaidQrFilePath: (Quickshell.env("HOME") || "/home/ozdil") + "/.local/state/omarchy/omasend/omaid_qr.svg"
  readonly property string clipStagingPath: (Quickshell.env("HOME") || "/home/ozdil") + "/.local/state/omarchy/omasend/clip_staging"
  readonly property string manifestPath: Qt.resolvedUrl("manifest.json").toString().replace(/^file:\/\//, "")
  readonly property string manifestFallbackPath: (Quickshell.env("HOME") || "/home/ozdil") + "/.config/omarchy/plugins/ozdil.omasend/manifest.json"

  property string pluginVersion: "1.7.2"
  property string pluginDescription: "AirBridge P2P, E2EE Secure Local & Network File Transfer System"
  property string pluginAuthor: "Ozan Özdil (@ozdil)"
  property string pluginLicense: "MIT"

  function loadManifest(rawJson) {
    try {
      if (!rawJson) return
      var parsed = JSON.parse(rawJson)
      if (parsed.version) root.pluginVersion = parsed.version
      if (parsed.description) root.pluginDescription = parsed.description
      if (parsed.author) root.pluginAuthor = parsed.author
      if (parsed.license) root.pluginLicense = parsed.license
    } catch(e) {}
  }

  function formatOmaId(id, revealed) {
    if (!id || String(id).trim() === "") return "---- ---- ---- ----"
    var clean = String(id).replace(/[^0-9]/g, "")
    if (!revealed) {
      if (clean.length >= 16) {
        return "••••-••••-••••-" + clean.slice(12, 16)
      }
      return "••••-••••-••••-••••"
    }
    if (clean.length === 16) {
      return clean.slice(0, 4) + "-" + clean.slice(4, 8) + "-" + clean.slice(8, 12) + "-" + clean.slice(12, 16)
    }
    return clean
  }

  function formatInputOmaId(val) {
    if (!val) return ""
    var clean = String(val).replace(/[^0-9]/g, "").slice(0, 16)
    var parts = []
    for (var i = 0; i < clean.length; i += 4) {
      parts.push(clean.slice(i, i + 4))
    }
    return parts.join("-")
  }

  function loadDiscoveredPeers(content) {
    try {
      if (!content || String(content).trim() === "") return
      var parsed = JSON.parse(content)
      if (Array.isArray(parsed)) {
        root.p2pPeers = parsed
      }
    } catch(e) {}
  }

  function bindOmaId(targetId, targetName) {
    var clean = String(targetId || "").replace(/[^0-9]/g, "")
    if (clean.length !== 16) {
      root.pairStatusMsg = "Geçersiz OmaID (16 haneli rakam olmalı)"
      root.pairStatusError = true
      return
    }
    root.pairStatusMsg = "Cihaz bağlanıyor..."
    root.pairStatusError = false
    var name = String(targetName || "").trim() || ("OmaID-" + clean.slice(0, 4))
    root.executeAction(["--bind-oma-id", clean, name])
    root.pairStatusMsg = "Cihaz başarıyla bağlandı ve güvenildi!"
    root.pairStatusError = false
    pairTimer.restart()
  }

  function scanFromScreen() {
    root.pairStatusMsg = "Ekran taranıyor..."
    root.pairStatusError = false
    if (screenScanProc.running) screenScanProc.running = false
    screenScanProc.running = true
  }

  function pasteOmaIdFromClipboard() {
    if (pasteProc.running) pasteProc.running = false
    pasteProc.running = true
  }

  function forceScan() {
    if (forceScanProc.running) forceScanProc.running = false
    forceScanProc.running = true
  }

  function resolveEnginePath() {
    var home = Quickshell.env("HOME") || "/home/ozdil"
    return home + "/.local/bin/omasend-engine"
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
    if (omaIdDirectReadProc.running) {
      omaIdDirectReadProc.running = false
    }
    omaIdDirectReadProc.running = true
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
      root.forceScan()
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

  function copyText(text) {
    if (copyProc.running) copyProc.running = false
    copyProc.command = ["wl-copy", text]
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

  Process {
    id: omaIdDirectReadProc
    command: ["cat", (Quickshell.env("HOME") || "/home/ozdil") + "/.local/state/omarchy/omasend/oma_id"]
    running: true
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        omaIdDirectReadProc.running = false
        var val = String(text || "").trim()
        if (val.length >= 16) {
          root.omaId = val
        }
      }
    }
  }

  // Persistent background HTTP daemon
  Process {
    id: serverProc
    command: [root.resolveEnginePath(), "--serve"]
    running: true
  }

  Process {
    id: forceScanProc
    command: [root.resolveEnginePath(), "--force-scan"]
    onExited: function(code) {
      forceScanProc.running = false
      root.refresh()
    }
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
          root.omaidQrPath = String(d.omaid_qr_path || root.omaidQrFilePath)
          root.totalReceived = Number(d.total_received) || 0
          root.recentFiles = d.recent_files || []
          root.sharedFiles = d.shared_files || []
          root.p2pVisibility = String(d.p2p_visibility || "KNOWN")
          root.p2pVisibilityRemainingSecs = Number(d.p2p_visibility_remaining_secs) || 0
          root.p2pPeers = d.p2p_discovered_peers || []
          root.p2pPendingTransfer = d.p2p_pending_transfer || null
          root.omaId = String(d.oma_id || d.p2p_device_id || "")
          root.refreshNonce++
        } catch(e) {}
      }
    }
  }

  Timer {
    id: omaIdCopyTimer
    interval: 1800
    repeat: false
    onTriggered: {
      root.omaIdCopiedFeedback = false
    }
  }

  Timer {
    id: pairTimer
    interval: 1800
    repeat: false
    onTriggered: {
      if (!root.pairStatusError) {
        root.showOmaIdPairModal = false
        root.pairInputOmaId = ""
        root.pairInputName = ""
        root.pairStatusMsg = ""
      }
    }
  }

  Process {
    id: screenScanProc
    command: ["bash", "-c", "rm -f /tmp/oma_qr_scan.png && /usr/bin/grim /tmp/oma_qr_scan.png 2>/dev/null && (/usr/bin/zbarimg -q --raw /tmp/oma_qr_scan.png 2>/dev/null || true) && rm -f /tmp/oma_qr_scan.png"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        screenScanProc.running = false
        var raw = String(text || "").trim()
        if (raw.length > 0) {
          var clean = raw.replace(/[^0-9]/g, "")
          if (clean.length >= 16) {
            root.pairInputOmaId = root.formatInputOmaId(clean.slice(0, 16))
            root.pairStatusMsg = "QR Kod okundu: " + root.pairInputOmaId
            root.pairStatusError = false
          } else {
            root.pairStatusMsg = "QR Kod içeriğinde 16 haneli OmaID bulunamadı"
            root.pairStatusError = true
          }
        } else {
          root.pairStatusMsg = "Ekrandan taranabilir QR kod bulunamadı"
          root.pairStatusError = true
        }
      }
    }
  }

  Process {
    id: pasteProc
    command: ["wl-paste", "--no-newline"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        pasteProc.running = false
        var raw = String(text || "").trim()
        if (raw.length > 0) {
          var clean = raw.replace(/[^0-9]/g, "")
          if (clean.length >= 16) {
            root.pairInputOmaId = root.formatInputOmaId(clean.slice(0, 16))
            root.pairStatusMsg = "Panodan OmaID aktarıldı: " + root.pairInputOmaId
            root.pairStatusError = false
          } else {
            root.pairStatusMsg = "Panodaki metin 16 haneli OmaID formatında değil"
            root.pairStatusError = true
          }
        } else {
          root.pairStatusMsg = "Pano boş"
          root.pairStatusError = true
        }
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

  FileView {
    id: peersWatcher
    path: root.peersPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.loadDiscoveredPeers(text())
    onLoadFailed: {}
    onFileChanged: reload()
  }

  FileView {
    id: manifestWatcher
    path: root.manifestPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.loadManifest(text())
    onLoadFailed: {
      manifestFallbackWatcher.reload()
    }
    onFileChanged: reload()
  }

  FileView {
    id: manifestFallbackWatcher
    path: root.manifestFallbackPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.loadManifest(text())
    onFileChanged: reload()
  }

  Timer {
    id: refreshTimer
    interval: 800
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

  // Transform Watcher for strictly reactive coordinate tracking across bar re-layouts
  TransformWatcher {
    id: buttonWatcher
    a: button && button.QsWindow.window ? button.QsWindow.window.contentItem : null
    b: button
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    active: (dropPortal.active && dropPortal.proximity > 0.01) || dropPortal.isBlasting
    useActiveColor: false
    foreground: ((dropPortal.active && dropPortal.proximity > 0.01) || dropPortal.isBlasting) ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
    tooltipText: "OmaSend AirBridge (" + root.p2pVisibility + ")"
    onPressed: function(b) {
      root.toggle()
    }

    DropArea {
      id: iconDropArea
      anchors.centerIn: parent
      width: Math.min(560, root.bar ? root.bar.width : 560)
      height: parent.height
      keys: ["text/uri-list", "text/plain", "application/x-kde-urilist"]

      onEntered: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dragRetentionTimer.stop()
          dropPortal.active = true
          dropPortal.proximity = Math.max(dropPortal.proximity, 0.02)
          drag.acceptProposedAction()
        }
      }

      onPositionChanged: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dragRetentionTimer.stop()
          dropPortal.active = true
          drag.acceptProposedAction()
          var dx = drag.x - (iconDropArea.width / 2)
          var dist = Math.abs(dx)
          var raw = Math.max(0.0, Math.min(1.0, 1.0 - (dist / (iconDropArea.width / 2))))
          dropPortal.proximity = Math.max(dropPortal.proximity, 0.5 * (1.0 - Math.cos(raw * Math.PI)))
        }
      }

      onExited: {
        dragRetentionTimer.restart()
      }

      onDropped: function(drop) {
        dragRetentionTimer.stop()
        if (drop.hasUrls || drop.hasText) {
          drop.acceptProposedAction()
          dropPortal.triggerDropBlast(drop)
        }
      }
    }
  }

  // Anchored Drop Portal & Fluid Water Droplet Ripple Engine
  PopupWindow {
    id: dropPortal
    anchor {
      id: dropPortalAnchor
      window: button ? button.QsWindow.window : null
      adjustment: PopupAdjustment.Slide
      edges: Edges.Top | Edges.Left
      gravity: Edges.Bottom | Edges.Right
      rect.width: 1
      rect.height: 1

      onAnchoring: {
        if (!button || !root.bar) return
        var target = button
        var popupWidth = dropPortal.implicitWidth
        var popupHeight = dropPortal.implicitHeight
        var localX = target.width / 2 - popupWidth / 2
        var isBottom = (root.bar.position === "bottom" || root.bar.edge === "bottom")
        var localY = isBottom ? -popupHeight : target.height

        var win = target.QsWindow.window
        if (!win) return

        var point = win.contentItem.mapFromItem(target, localX, localY)
        point.x = Math.max(0, Math.min(point.x, win.width - popupWidth))

        dropPortalAnchor.rect.x = Math.round(point.x)
        dropPortalAnchor.rect.y = Math.round(point.y)
      }
    }
    implicitWidth: 600
    implicitHeight: 600
    visible: (dropPortal.active && dropPortal.proximity > 0.01) || dropPortal.isBlasting
    color: "transparent"

    property bool active: false
    property real proximity: 0.0
    property bool isBlasting: false
    property real blastProgress: 0.0

    // Exact button center relative to dropPortal (Fully Reactive with TransformWatcher)
    readonly property real originX: {
      buttonWatcher.transform
      if (!button || !button.QsWindow.window) return dropPortal.width / 2
      var win = button.QsWindow.window
      var btnCenterInWin = win.contentItem.mapFromItem(button, button.width / 2, 0)
      return Math.round(btnCenterInWin.x - dropPortalAnchor.rect.x)
    }
    readonly property real originY: (root.bar && (root.bar.position === "bottom" || root.bar.edge === "bottom")) ? dropPortal.height : 0

    // 350ms Drag Dropout Buffer Timer (Ensures strictly drag-only activation)
    Timer {
      id: dragRetentionTimer
      interval: 350
      repeat: false
      onTriggered: {
        if (!portalDropArea.containsDrag && !iconDropArea.containsDrag && !dropPortal.isBlasting) {
          dropPortal.active = false
          dropPortal.proximity = 0.0
        }
      }
    }

    function triggerDropBlast(drop) {
      var rawUrl = ""
      if (drop.hasUrls && drop.urls.length > 0) {
        rawUrl = drop.urls[0].toString()
      } else if (drop.hasText && drop.text) {
        rawUrl = drop.text
      }
      var firstFile = rawUrl.replace(/^file:\/\//, "")

      // Play send whoosh sound via PipeWire
      if (playSendSoundProc.running) playSendSoundProc.running = false
      playSendSoundProc.running = true

      // Target peer identification
      var targetPeer = (root.p2pPeers && root.selectedPeerIndex >= 0 && root.selectedPeerIndex < root.p2pPeers.length)
                       ? root.p2pPeers[root.selectedPeerIndex]
                       : (root.p2pPeers && root.p2pPeers.length > 0 ? root.p2pPeers[0] : null)
      var targetIp = targetPeer ? targetPeer.ip : ""

      if (targetIp !== "" && firstFile !== "") {
        root.executeAction(["--send", targetIp, firstFile])
      }

      // Trigger Water Droplet Splash & Rebound Shockwave
      dropPortal.isBlasting = true
      blastAnim.restart()
    }

    // Water Droplet Impact & Crown Splash Animation Sequence
    SequentialAnimation {
      id: blastAnim
      running: false
      ParallelAnimation {
        NumberAnimation {
          target: dropPortal
          property: "blastProgress"
          from: 0.0
          to: 1.0
          duration: 460
          easing.type: Easing.OutCubic
        }
        NumberAnimation {
          target: impactCrown
          property: "scale"
          from: 0.0
          to: 1.65
          duration: 220
          easing.type: Easing.OutBack
        }
        NumberAnimation {
          target: flareBeam
          property: "opacity"
          from: 0.0
          to: 1.0
          duration: 120
          easing.type: Easing.OutQuad
        }
      }
      ParallelAnimation {
        NumberAnimation {
          target: impactCrown
          property: "scale"
          to: 1.0
          duration: 240
          easing.type: Easing.OutElastic
        }
        NumberAnimation {
          target: flareBeam
          property: "opacity"
          to: 0.0
          duration: 240
          easing.type: Easing.InQuad
        }
        NumberAnimation {
          target: dropPortal
          property: "proximity"
          to: 0.0
          duration: 240
        }
      }
      ScriptAction {
        script: {
          dropPortal.isBlasting = false
          dropPortal.blastProgress = 0.0
          dropPortal.proximity = 0.0
          dropPortal.active = false
        }
      }
    }

    DropArea {
      id: portalDropArea
      anchors.fill: parent
      keys: ["text/uri-list", "text/plain", "application/x-kde-urilist"]

      onEntered: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dragRetentionTimer.stop()
          dropPortal.active = true
          drag.acceptProposedAction()
        }
      }

      onPositionChanged: function(drag) {
        if (drag.hasUrls || drag.hasText) {
          dragRetentionTimer.stop()
          dropPortal.active = true
          drag.acceptProposedAction()
          var dx = drag.x - dropPortal.originX
          var dy = drag.y - dropPortal.originY
          var dist = Math.sqrt(dx * dx + dy * dy)
          var maxDist = 600.0
          var raw = Math.max(0.0, Math.min(1.0, 1.0 - (dist / maxDist)))
          dropPortal.proximity = 0.5 * (1.0 - Math.cos(raw * Math.PI))
        }
      }

      onExited: {
        dragRetentionTimer.restart()
      }

      onDropped: function(drop) {
        dragRetentionTimer.stop()
        if (drop.hasUrls || drop.hasText) {
          drop.acceptProposedAction()
          dropPortal.triggerDropBlast(drop)
        }
      }
    }

    Item {
      id: auraContainer
      x: Math.round(dropPortal.originX - width / 2)
      y: Math.round(dropPortal.originY - height / 2)
      width: 600
      height: 600
      layer.enabled: true
      opacity: ((dropPortal.active && dropPortal.proximity > 0.01) || dropPortal.isBlasting) ? 1.0 : 0.0
      Behavior on opacity {
        NumberAnimation { duration: 120; easing.type: Easing.OutQuad }
      }

      // Layer 5: Liquid Water Surface Radial Refraction Gradient (Center 80% -> Outer 0%)
      Canvas {
        id: radialGradientCanvas
        anchors.centerIn: parent
        width: 580
        height: 580
        antialiasing: true
        layer.enabled: true
        renderTarget: Canvas.FramebufferObject

        onPaint: {
          var ctx = getContext("2d")
          ctx.reset()
          if (dropPortal.proximity <= 0.005 && !dropPortal.isBlasting) return

          var cx = width / 2
          var cy = height / 2
          var r = (80 + dropPortal.proximity * 440) / 2

          var grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, r)
          grad.addColorStop(0.0, Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.80 * (0.35 + dropPortal.proximity * 0.65)))
          grad.addColorStop(0.28, Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.48 * dropPortal.proximity))
          grad.addColorStop(0.65, Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.16 * dropPortal.proximity))
          grad.addColorStop(1.0, Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.00))

          ctx.fillStyle = grad
          ctx.beginPath()
          ctx.arc(cx, cy, r, 0, 2 * Math.PI, false)
          ctx.fill()
        }

        Connections {
          target: dropPortal
          function onProximityChanged() { radialGradientCanvas.requestPaint() }
          function onIsBlastingChanged() { radialGradientCanvas.requestPaint() }
          function onBlastProgressChanged() { radialGradientCanvas.requestPaint() }
        }
      }

      // Layer 4: Ambient Liquid Pool Glow (80px -> 480px)
      Rectangle {
        id: ambientGlow
        anchors.centerIn: parent
        width: 80 + (dropPortal.proximity * 400) + (dropPortal.isBlasting ? dropPortal.blastProgress * 120 : 0)
        height: width
        radius: width / 2
        layer.enabled: true
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, dropPortal.isBlasting ? 0.35 : (0.04 + dropPortal.proximity * 0.24))
        border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, dropPortal.isBlasting ? 0.75 : (0.08 + dropPortal.proximity * 0.48))
        border.width: 1.0

        Behavior on width { NumberAnimation { duration: 60; easing.type: Easing.OutQuad } }
        Behavior on height { NumberAnimation { duration: 60; easing.type: Easing.OutQuad } }
        Behavior on color { ColorAnimation { duration: 80 } }
      }

      // Wave 4: Outermost Propagating Ripple (Phase Offset: 1200ms)
      Rectangle {
        id: portalWave4
        anchors.centerIn: parent
        width: 260 + dropPortal.proximity * 300
        height: width
        radius: width / 2
        layer.enabled: true
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.01)
        border.color: Color.accent
        border.width: Math.max(0.8, 1.4 * (1.0 - scale * 0.5))

        SequentialAnimation on opacity {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          PauseAnimation { duration: 1200 }
          NumberAnimation { from: 0.0; to: 0.35 + dropPortal.proximity * 0.30; duration: 550; easing.type: Easing.OutQuad }
          NumberAnimation { from: 0.35 + dropPortal.proximity * 0.30; to: 0.0; duration: 1150; easing.type: Easing.InQuad }
        }

        SequentialAnimation on scale {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          PauseAnimation { duration: 1200 }
          NumberAnimation { from: 0.0; to: 1.0; duration: 1700; easing.type: Easing.OutCubic }
        }
      }

      // Wave 3: Outer Propagating Ripple (Phase Offset: 800ms)
      Rectangle {
        id: portalWave3
        anchors.centerIn: parent
        width: 200 + dropPortal.proximity * 280
        height: width
        radius: width / 2
        layer.enabled: true
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.02)
        border.color: Color.accent
        border.width: Math.max(1.0, 1.8 * (1.0 - scale * 0.4))

        SequentialAnimation on opacity {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          PauseAnimation { duration: 800 }
          NumberAnimation { from: 0.0; to: 0.48 + dropPortal.proximity * 0.32; duration: 500; easing.type: Easing.OutQuad }
          NumberAnimation { from: 0.48 + dropPortal.proximity * 0.32; to: 0.0; duration: 1100; easing.type: Easing.InQuad }
        }

        SequentialAnimation on scale {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          PauseAnimation { duration: 800 }
          NumberAnimation { from: 0.0; to: 1.0; duration: 1600; easing.type: Easing.OutCubic }
        }
      }

      // Layer 6: Floating Frosted Glass Capsule (Dynamic Island Peer Badge)
      Item {
        id: floatingDeviceCapsule
        z: 30
        anchors.horizontalCenter: parent.horizontalCenter
        y: (root.bar && (root.bar.position === "bottom" || root.bar.edge === "bottom"))
           ? (parent.height / 2 - 110 - (dropPortal.proximity * 25))
           : (parent.height / 2 + 80 + (dropPortal.proximity * 25))

        width: Math.min(360, capsuleRow.implicitWidth + 28)
        height: 32
        opacity: (dropPortal.active && dropPortal.proximity > 0.03) || dropPortal.isBlasting ? 1.0 : 0.0
        scale: opacity > 0 ? (0.92 + dropPortal.proximity * 0.08) : 0.85

        Behavior on opacity { NumberAnimation { duration: 140; easing.type: Easing.OutCubic } }
        Behavior on scale   { NumberAnimation { duration: 180; easing.type: Easing.OutBack } }
        Behavior on y       { NumberAnimation { duration: 100; easing.type: Easing.OutQuad } }

        // Frosted Dark Glass Surface
        Rectangle {
          anchors.fill: parent
          radius: height / 2
          color: Qt.rgba(0.06, 0.07, 0.10, 0.88)
          border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.50)
          border.width: 1.0

          // Subtle Inner Specular Rim
          Rectangle {
            anchors.fill: parent
            anchors.margins: 1
            radius: parent.radius - 1
            color: "transparent"
            border.color: Qt.rgba(1.0, 1.0, 1.0, 0.10)
            border.width: 1.0
          }
        }

        RowLayout {
          id: capsuleRow
          anchors.centerIn: parent
          spacing: 8

          // Device Icon (JetBrainsMono Nerd Font)
          Text {
            textFormat: Text.PlainText
            text: {
              var peer = (root.p2pPeers && root.p2pPeers.length > root.selectedPeerIndex) ? root.p2pPeers[root.selectedPeerIndex] : null
              var isMobile = peer && peer.is_mobile
              return isMobile ? "󰏲" : "󰌢"
            }
            color: Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.base
            Layout.alignment: Qt.AlignVCenter
          }

          // Target Peer Name
          Text {
            textFormat: Text.PlainText
            text: {
              if (root.p2pPeers && root.p2pPeers.length > 0) {
                var p = (root.selectedPeerIndex >= 0 && root.selectedPeerIndex < root.p2pPeers.length)
                        ? root.p2pPeers[root.selectedPeerIndex]
                        : root.p2pPeers[0]
                return p.name ? p.name.toUpperCase() : "DISCOVERING..."
              }
              return "DISCOVERING PEERS..."
            }
            color: root.bar ? root.bar.foreground : Color.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 0.6
            elide: Text.ElideRight
            Layout.maximumWidth: 200
            Layout.alignment: Qt.AlignVCenter
          }

          // Connection Mode Badge
          Rectangle {
            implicitWidth: modeBadgeText.implicitWidth + 10
            implicitHeight: 18
            radius: 4
            color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.18)
            border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.40)
            border.width: 0.8
            Layout.alignment: Qt.AlignVCenter

            Text {
              id: modeBadgeText
              anchors.centerIn: parent
              textFormat: Text.PlainText
              text: root.activeMode === "LAN" ? "P2P" : root.activeMode
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.micro
              font.bold: true
              font.letterSpacing: 0.5
            }
          }
        }
      }

      // Wave 2: Mid Propagating Ripple (Phase Offset: 400ms)
      Rectangle {
        id: portalWave2
        anchors.centerIn: parent
        width: 130 + dropPortal.proximity * 220
        height: width
        radius: width / 2
        layer.enabled: true
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.03)
        border.color: Color.accent
        border.width: Math.max(1.0, 2.0 * (1.0 - scale * 0.4))

        SequentialAnimation on opacity {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          PauseAnimation { duration: 400 }
          NumberAnimation { from: 0.0; to: 0.58 + dropPortal.proximity * 0.32; duration: 450; easing.type: Easing.OutQuad }
          NumberAnimation { from: 0.58 + dropPortal.proximity * 0.32; to: 0.0; duration: 1050; easing.type: Easing.InQuad }
        }

        SequentialAnimation on scale {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          PauseAnimation { duration: 400 }
          NumberAnimation { from: 0.0; to: 1.0; duration: 1500; easing.type: Easing.OutCubic }
        }
      }

      // Wave 1: Inner Wavefront Birth (Phase Offset: 0ms)
      Rectangle {
        id: portalWave1
        anchors.centerIn: parent
        width: 70 + dropPortal.proximity * 140
        height: width
        radius: width / 2
        layer.enabled: true
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.04)
        border.color: Color.accent
        border.width: Math.max(1.2, 2.4 * (1.0 - scale * 0.35))

        SequentialAnimation on opacity {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          NumberAnimation { from: 0.0; to: 0.75 + dropPortal.proximity * 0.25; duration: 350; easing.type: Easing.OutQuad }
          NumberAnimation { from: 0.75 + dropPortal.proximity * 0.25; to: 0.0; duration: 900; easing.type: Easing.InQuad }
        }

        SequentialAnimation on scale {
          running: dropPortal.active && dropPortal.proximity > 0.02 && !dropPortal.isBlasting
          loops: Animation.Infinite
          NumberAnimation { from: 0.0; to: 1.0; duration: 1250; easing.type: Easing.OutCubic }
        }
      }

      // Anamorphic Optical Flare Halo Streak
      Rectangle {
        id: flareBeam
        anchors.centerIn: parent
        z: 15
        width: 36 + (dropPortal.isBlasting ? dropPortal.blastProgress * 400 : dropPortal.proximity * 340)
        height: 2 + (dropPortal.isBlasting ? 4 : dropPortal.proximity * 2.0)
        radius: 1
        color: Qt.rgba(1.0, 1.0, 1.0, 0.95)
        opacity: dropPortal.isBlasting ? (1.0 - dropPortal.blastProgress) : (dropPortal.proximity * 0.9)
        Behavior on width { NumberAnimation { duration: 60; easing.type: Easing.OutQuad } }
        Behavior on opacity { NumberAnimation { duration: 80 } }
      }

      // High-Energy Splash Shockwave (onDropped: 0 -> 600px with Easing.OutCubic)
      Rectangle {
        id: shockRipple
        anchors.centerIn: parent
        visible: dropPortal.isBlasting
        width: 30 + (dropPortal.blastProgress * 570)
        height: width
        radius: width / 2
        color: "transparent"
        border.color: Qt.rgba(1.0, 1.0, 1.0, (1.0 - dropPortal.blastProgress) * 0.95)
        border.width: Math.max(1.0, 5.0 * (1.0 - dropPortal.blastProgress))
      }

      // Layer 0: Droplet Impact Crown & Target Reticle
      Rectangle {
        id: impactCrown
        anchors.centerIn: parent
        z: 20
        width: 48 + dropPortal.proximity * 18
        height: width
        radius: width / 2
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, dropPortal.isBlasting ? 0.70 : (0.20 + dropPortal.proximity * 0.35))
        border.color: dropPortal.isBlasting ? Qt.rgba(1.0, 1.0, 1.0, 0.95) : Color.accent
        border.width: (dropPortal.active || dropPortal.isBlasting) ? (1.5 + dropPortal.proximity * 1.5) : 1.5
        scale: (1.0 + dropPortal.proximity * 0.35)

        Behavior on width { NumberAnimation { duration: 60; easing.type: Easing.OutQuad } }
        Behavior on height { NumberAnimation { duration: 60; easing.type: Easing.OutQuad } }
        Behavior on scale { NumberAnimation { duration: 60; easing.type: Easing.OutBack } }
        Behavior on color { ColorAnimation { duration: 80 } }

        Column {
          anchors.centerIn: parent
          spacing: 1
          Text {
            anchors.horizontalCenter: parent.horizontalCenter
            textFormat: Text.PlainText
            text: dropPortal.isBlasting ? "" : (dropPortal.proximity > 0.1 ? "󱘖" : "")
            color: dropPortal.isBlasting ? Qt.rgba(1.0, 1.0, 1.0, 0.95) : Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.title + Math.round(dropPortal.proximity * 2)
          }
          Text {
            anchors.horizontalCenter: parent.horizontalCenter
            textFormat: Text.PlainText
            text: dropPortal.isBlasting ? "SENT!" : ((dropPortal.proximity > 0.1) ? "DROP" : "AIRBRIDGE")
            color: dropPortal.isBlasting ? Qt.rgba(1.0, 1.0, 1.0, 0.95) : Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 0.8
            elide: Text.ElideRight
            width: Math.min(84, impactCrown.width - 4)
            horizontalAlignment: Text.AlignHCenter
          }
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
    contentHeight: panel.fittedContentHeight(
      (root.showAboutModal || root.showOmaIdQrModal || root.showOmaIdPairModal) ?
        Math.max(panelColumn.implicitHeight, (root.showOmaIdPairModal ? (pairCol.implicitHeight + Style.space(40)) : (root.showOmaIdQrModal ? (qrCol.implicitHeight + Style.space(40)) : (aboutCol.implicitHeight + Style.space(40))))) :
        panelColumn.implicitHeight
    )

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: {
        if (root.showOmaIdPairModal) {
          root.showOmaIdPairModal = false
          root.pairStatusMsg = ""
        } else if (root.showOmaIdQrModal) {
          root.showOmaIdQrModal = false
        } else if (root.showAboutModal) {
          root.showAboutModal = false
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) {
        if (!root.showAboutModal && !root.showOmaIdQrModal && !root.showOmaIdPairModal) {
          root.moveCursor(dy)
        }
      }
      onActivateRequested: {
        if (!root.showAboutModal && !root.showOmaIdQrModal && !root.showOmaIdPairModal) {
          root.activateSelected()
        }
      }
      onTextKey: function(t) {
        if (root.showAboutModal || root.showOmaIdQrModal || root.showOmaIdPairModal) return
        if (t === "r" || t === "R") {
          root.refresh()
        } else if (t === "v" || t === "V") {
          root.toggleVisibility()
        } else if (t === "s" || t === "S") {
          if (root.p2pPeers && root.p2pPeers.length > root.selectedPeerIndex) {
            var peer = root.p2pPeers[root.selectedPeerIndex]
            if (peer && peer.ip) root.sendFileTo(peer.ip)
          } else if (root.p2pPeers && root.p2pPeers.length > 0) {
            root.sendFileTo(root.p2pPeers[0].ip)
          }
        } else if (t === "p" || t === "P") {
          if (root.p2pPeers && root.p2pPeers.length > root.selectedPeerIndex) {
            var pPeer = root.p2pPeers[root.selectedPeerIndex]
            if (pPeer && pPeer.ip) root.syncClipboardTo(pPeer.ip)
          } else if (root.p2pPeers && root.p2pPeers.length > 0) {
            root.syncClipboardTo(root.p2pPeers[0].ip)
          }
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

        // Hero: OmaSend icon, title & Visibility Toggle
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

        // OmaID Profile & Connection Mode Indicator
        Rectangle {
          width: parent.width
          implicitHeight: omaidCardContent.implicitHeight + Style.space(16)
          radius: Style.cornerRadius
          color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.07)
          border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.28)
          border.width: 1

          // 1px specular highlight inner rim
          Rectangle {
            anchors.fill: parent
            anchors.margins: 1
            radius: Math.max(0, parent.radius - 1)
            color: "transparent"
            border.color: Qt.rgba(1.0, 1.0, 1.0, 0.08)
            border.width: 1
          }

          ColumnLayout {
            id: omaidCardContent
            anchors.fill: parent
            anchors.margins: Style.space(8)
            spacing: Style.space(6)

            // Header Row: [󰌆] OMAID (BU CİHAZ) ... [• P2P / LAN]
            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                text: "󰌆"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                Layout.alignment: Qt.AlignVCenter
              }

              Text {
                text: "OMAID (BU CİHAZ)"
                color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.fontFamily
                font.pixelSize: Style.font.micro
                font.bold: true
                font.letterSpacing: 0.8
                Layout.alignment: Qt.AlignVCenter
              }

              Text {
                visible: root.omaIdCopiedFeedback
                text: "COPIED"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.micro
                font.bold: true
                Layout.alignment: Qt.AlignVCenter
              }

              Item {
                Layout.fillWidth: true
              }

              // Connection Mode Indicator Badge (LAN / WAN / P2P)
              Rectangle {
                implicitWidth: modeRow.implicitWidth + Style.space(8)
                implicitHeight: 20
                radius: 4
                color: {
                  if (root.wanActive) return Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.20)
                  if (root.activeMode === "P2P" || root.p2pVisibility !== "OFF") return Qt.rgba(0.73, 0.60, 0.97, 0.20)
                  return Qt.rgba(0.62, 0.81, 0.42, 0.20)
                }
                border.color: {
                  if (root.wanActive) return Color.accent
                  if (root.activeMode === "P2P" || root.p2pVisibility !== "OFF") return "#bb9af7"
                  return "#9ece6a"
                }
                border.width: 1
                Layout.alignment: Qt.AlignVCenter

                RowLayout {
                  id: modeRow
                  anchors.centerIn: parent
                  spacing: 4

                  Rectangle {
                    width: 6
                    height: 6
                    radius: 3
                    color: {
                      if (root.wanActive) return Color.accent
                      if (root.activeMode === "P2P" || root.p2pVisibility !== "OFF") return "#bb9af7"
                      return "#9ece6a"
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: {
                      if (root.wanActive) return "WAN"
                      if (root.activeMode === "P2P" || root.p2pVisibility !== "OFF") return "P2P"
                      return "LAN"
                    }
                    color: root.bar ? root.bar.foreground : Color.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.micro
                    font.bold: true
                    font.letterSpacing: 0.5
                  }
                }

                PanelToolTip {
                  text: root.wanActive ? "Cloudflare WAN Tunnel Active" : (root.p2pVisibility !== "OFF" ? "AirBridge P2P WebRTC Active" : "LAN Local Network Only")
                  fontFamily: root.fontFamily
                }
              }
            }

            // Body Row: 16-Digit Code and Action Buttons
            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(6)

              Text {
                Layout.fillWidth: true
                text: root.formatOmaId(root.omaId, root.omaIdRevealed)
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.0
                Layout.alignment: Qt.AlignVCenter
                elide: Text.ElideRight
              }

              // Reveal/Mask Button
              Rectangle {
                implicitWidth: 26
                implicitHeight: 26
                radius: 4
                color: revealMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.20) : "transparent"
                Layout.alignment: Qt.AlignVCenter

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: root.omaIdRevealed ? "󰈉" : "󰈈"
                  color: root.omaIdRevealed ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                MouseArea {
                  id: revealMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.omaIdRevealed = !root.omaIdRevealed
                  }
                }

                PanelToolTip {
                  visible: revealMouse.containsMouse
                  text: root.omaIdRevealed ? "Mask OmaID" : "Reveal OmaID"
                  fontFamily: root.fontFamily
                }
              }

              // Copy OmaID Button
              Rectangle {
                implicitWidth: 26
                implicitHeight: 26
                radius: 4
                color: copyOmaIdMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.20) : "transparent"
                Layout.alignment: Qt.AlignVCenter

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "󰅟"
                  color: root.omaIdCopiedFeedback ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                MouseArea {
                  id: copyOmaIdMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    if (root.omaId) {
                      root.copyText(root.omaId)
                      root.omaIdCopiedFeedback = true
                      omaIdCopyTimer.restart()
                    }
                  }
                }

                PanelToolTip {
                  visible: copyOmaIdMouse.containsMouse
                  text: "OmaID Kopyala"
                  fontFamily: root.fontFamily
                }
              }

              // QR Göster Button
              Rectangle {
                implicitWidth: 26
                implicitHeight: 26
                radius: 4
                color: showQrMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.20) : "transparent"
                Layout.alignment: Qt.AlignVCenter

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "󰄲"
                  color: root.showOmaIdQrModal ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                MouseArea {
                  id: showQrMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.showOmaIdQrModal = !root.showOmaIdQrModal
                    root.showOmaIdPairModal = false
                    root.showAboutModal = false
                  }
                }

                PanelToolTip {
                  visible: showQrMouse.containsMouse
                  text: "QR Göster"
                  fontFamily: root.fontFamily
                }
              }

              // Barkod / QR Tara / Bağla Button
              Rectangle {
                implicitWidth: 26
                implicitHeight: 26
                radius: 4
                color: pairMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.20) : "transparent"
                Layout.alignment: Qt.AlignVCenter

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "󰄳"
                  color: root.showOmaIdPairModal ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                MouseArea {
                  id: pairMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.showOmaIdPairModal = !root.showOmaIdPairModal
                    root.showOmaIdQrModal = false
                    root.showAboutModal = false
                    root.pairInputOmaId = ""
                    root.pairInputName = ""
                    root.pairStatusMsg = ""
                  }
                }

                PanelToolTip {
                  visible: pairMouse.containsMouse
                  text: "Barkod / QR Tara / Bağla"
                  fontFamily: root.fontFamily
                }
              }
            }
          }
        }

        // Gatekeeper Transfer Request (If Pending)
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

        // Section: PAIRED / AVAILABLE DEVICES
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

          Flickable {
            id: peersFlickable
            width: parent.width
            implicitHeight: Math.min(peersCol.implicitHeight, Style.space(220))
            contentWidth: width
            contentHeight: peersCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Column {
              id: peersCol
              width: parent.width
              spacing: Style.space(6)

              Repeater {
                model: root.p2pVisibility === "OFF" ? [] : root.p2pPeers

                CursorSurface {
                  id: peerRow
                  required property var modelData
                  required property int index
                  width: peersCol.width
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
                      if (modelData.ip) root.sendFileTo(modelData.ip)
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
                        text: modelData.last_seen_secs === 0 ? "OmaID Eşleşmiş (Çevrimdışı / Beklemede)" : (modelData.transport === "WAN" ? "OmaID Eşleşmiş (WAN Çevrimiçi)" : "OmaID Eşleşmiş (LAN Çevrimiçi)")
                        color: modelData.last_seen_secs === 0 ? Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 2.0) : Color.accent
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
                        iconText: "󰛄"
                        tooltipText: modelData.ip ? "Send File" : "Device Offline"
                        foreground: root.bar ? root.bar.foreground : Color.foreground
                        fontFamily: root.fontFamily
                        opacity: modelData.ip ? 1.0 : 0.4
                        onClicked: {
                          if (modelData.ip) root.sendFileTo(modelData.ip)
                        }
                      }
                    }
                  }
                }
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: root.p2pVisibility === "OFF" || root.p2pPeers.length === 0
            text: root.p2pVisibility === "OFF" ? "Turn discovery on to scan for paired devices." : "Scanning for paired OmaID devices..."
            color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.5)
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
            width: parent.width
          }
        }


        // Footer / Actions Section
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

    // OmaID QR Code Modal Overlay
    Rectangle {
      id: omaIdQrOverlay
      anchors.fill: parent
      visible: root.showOmaIdQrModal
      color: Qt.rgba(0.05, 0.05, 0.07, 0.97)
      z: 99

      MouseArea {
        anchors.fill: parent
      }

      Column {
        id: qrCol
        anchors.centerIn: parent
        width: parent.width - Style.space(40)
        spacing: Style.space(12)

        Row {
          width: parent.width
          Item {
            width: parent.width - closeQrBtn.implicitWidth
            implicitHeight: qrTitleText.implicitHeight
            RowLayout {
              spacing: Style.space(6)
              Text {
                text: "󰄲"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
              }
              Text {
                id: qrTitleText
                text: "OmaID QR Kodu"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
              }
            }
          }

          Button {
            id: closeQrBtn
            text: "✕"
            bordered: true
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.caption
            onClicked: root.showOmaIdQrModal = false
          }
        }

        Text {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "Mobil cihazınızdan veya başka bir Omarchy masaüstünden bu QR kodu okutarak anında güvenli AirBridge eşleşmesi kurun."
          color: root.bar ? root.bar.foreground : Color.foreground
          opacity: 0.75
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          lineHeight: 1.3
        }

        // Acrylic Glass QR Container
        Rectangle {
          anchors.horizontalCenter: parent.horizontalCenter
          width: 190
          height: 190
          radius: 12
          color: "#ffffff"
          border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.5)
          border.width: 2

          Image {
            id: omaQrImg
            anchors.fill: parent
            anchors.margins: 10
            source: "file://" + (root.omaidQrPath || root.omaidQrFilePath)
            sourceSize.width: 170
            sourceSize.height: 170
            fillMode: Image.PreserveAspectFit
            smooth: false
            cache: false
          }
        }

        // Formatted OmaID Text Pill
        Rectangle {
          width: parent.width
          implicitHeight: 36
          radius: Style.cornerRadius
          color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.10)
          border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.35)
          border.width: 1

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Style.space(10)
            anchors.rightMargin: Style.space(10)
            spacing: Style.space(8)

            Text {
              text: "󰌆"
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              text: root.formatOmaId(root.omaId, true)
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.2
              horizontalAlignment: Text.AlignHCenter
            }

            Rectangle {
              implicitWidth: 26
              implicitHeight: 26
              radius: 4
              color: modalCopyOmaIdMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.25) : "transparent"

              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: root.omaIdCopiedFeedback ? "󰄬" : "󰅟"
                color: root.omaIdCopiedFeedback ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              MouseArea {
                id: modalCopyOmaIdMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                  if (root.omaId) {
                    root.copyText(root.omaId)
                    root.omaIdCopiedFeedback = true
                    omaIdCopyTimer.restart()
                  }
                }
              }
            }
          }
        }

        PanelSeparator {
          width: parent.width
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Button {
          width: parent.width
          text: root.omaIdCopiedFeedback ? "OmaID Kopyalandı" : "OmaID Panoya Kopyala"
          iconText: root.omaIdCopiedFeedback ? "󰄬" : "󰅟"
          bordered: true
          accent: Color.accent
          foreground: root.bar ? root.bar.foreground : Color.foreground
          fontFamily: root.fontFamily
          fontSize: Style.font.caption
          onClicked: {
            if (root.omaId) {
              root.copyText(root.omaId)
              root.omaIdCopiedFeedback = true
              omaIdCopyTimer.restart()
            }
          }
        }
      }
    }

    // OmaID Pair & Scan Modal Overlay
    Rectangle {
      id: omaIdPairOverlay
      anchors.fill: parent
      visible: root.showOmaIdPairModal
      color: Qt.rgba(0.05, 0.05, 0.07, 0.97)
      z: 99

      MouseArea {
        anchors.fill: parent
      }

      Column {
        id: pairCol
        anchors.centerIn: parent
        width: parent.width - Style.space(40)
        spacing: Style.space(10)

        Row {
          width: parent.width
          Item {
            width: parent.width - closePairBtn.implicitWidth
            implicitHeight: pairTitleText.implicitHeight
            RowLayout {
              spacing: Style.space(6)
              Text {
                text: "󰄳"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
              }
              Text {
                id: pairTitleText
                text: "OmaID Bağla & QR Tara"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
              }
            }
          }

          Button {
            id: closePairBtn
            text: "✕"
            bordered: true
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.caption
            onClicked: {
              root.showOmaIdPairModal = false
              root.pairStatusMsg = ""
            }
          }
        }

        Text {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "Ekrandaki QR kodunu tarayın, panodaki kodu aktarın veya 16 haneli OmaID'yi girerek güvenli cihaz bağlayın."
          color: root.bar ? root.bar.foreground : Color.foreground
          opacity: 0.75
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          lineHeight: 1.3
        }

        // Quick Action Buttons Row (Ekrandan Tara / Panodan Al)
        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          Rectangle {
            Layout.fillWidth: true
            height: 34
            radius: 6
            color: scanHover.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.18) : Qt.rgba(1.0, 1.0, 1.0, 0.06)
            border.color: scanHover.containsMouse ? Color.accent : Qt.rgba(1.0, 1.0, 1.0, 0.15)
            border.width: 1

            RowLayout {
              anchors.centerIn: parent
              spacing: Style.space(6)
              Text {
                text: "󰄳"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
              Text {
                text: "Ekrandan Tara"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.micro
                font.bold: true
              }
            }

            MouseArea {
              id: scanHover
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: root.scanFromScreen()
            }
          }

          Rectangle {
            Layout.fillWidth: true
            height: 34
            radius: 6
            color: pasteHover.containsMouse ? Qt.rgba(1.0, 1.0, 1.0, 0.12) : Qt.rgba(1.0, 1.0, 1.0, 0.06)
            border.color: pasteHover.containsMouse ? Qt.rgba(1.0, 1.0, 1.0, 0.3) : Qt.rgba(1.0, 1.0, 1.0, 0.15)
            border.width: 1

            RowLayout {
              anchors.centerIn: parent
              spacing: Style.space(6)
              Text {
                text: "󰅍"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
              Text {
                text: "Panodan Al"
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.micro
                font.bold: true
              }
            }

            MouseArea {
              id: pasteHover
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: root.pasteOmaIdFromClipboard()
            }
          }
        }

        // 16-Digit OmaID Input Label & Field
        Column {
          width: parent.width
          spacing: Style.space(4)

          RowLayout {
            width: parent.width
            Text {
              text: "16 HANELİ OMAID"
              color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
              font.family: root.fontFamily
              font.pixelSize: Style.font.micro
              font.bold: true
              font.letterSpacing: 0.8
            }
            Item { Layout.fillWidth: true }
            Text {
              property int cleanLen: root.pairInputOmaId.replace(/[^0-9]/g, "").length
              text: "(" + cleanLen + " / 16)"
              color: cleanLen === 16 ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.6)
              font.family: root.fontFamily
              font.pixelSize: Style.font.micro
              font.bold: true
            }
          }

          Rectangle {
            width: parent.width
            height: 38
            radius: 6
            color: Qt.rgba(1.0, 1.0, 1.0, 0.05)
            border.color: pairOmaIdInput.activeFocus ? Color.accent : (root.pairInputOmaId.replace(/[^0-9]/g, "").length === 16 ? Color.accent : Qt.rgba(1.0, 1.0, 1.0, 0.15))
            border.width: 1

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              spacing: Style.space(6)

              TextInput {
                id: pairOmaIdInput
                Layout.fillWidth: true
                text: root.pairInputOmaId
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.0
                color: root.bar ? root.bar.foreground : Color.foreground
                selectByMouse: true
                cursorVisible: activeFocus
                maximumLength: 19

                onTextChanged: {
                  var formatted = root.formatInputOmaId(text)
                  if (formatted !== text) {
                    var oldPos = cursorPosition
                    root.pairInputOmaId = formatted
                    cursorPosition = Math.min(formatted.length, oldPos + 1)
                  } else {
                    root.pairInputOmaId = text
                  }
                }

                Text {
                  anchors.fill: parent
                  visible: !pairOmaIdInput.text && !pairOmaIdInput.activeFocus
                  text: "0000-0000-0000-0000"
                  color: Qt.rgba(1.0, 1.0, 1.0, 0.25)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1.0
                  verticalAlignment: Text.AlignVCenter
                }
              }

              Text {
                visible: root.pairInputOmaId.replace(/[^0-9]/g, "").length === 16
                text: "󰄬"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }
          }
        }

        // Friendly Device Name Input
        Column {
          width: parent.width
          spacing: Style.space(4)

          Text {
            text: "CİHAZ ADI (İSTEĞE BAĞLI)"
            color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
            font.family: root.fontFamily
            font.pixelSize: Style.font.micro
            font.bold: true
            font.letterSpacing: 0.8
          }

          Rectangle {
            width: parent.width
            height: 38
            radius: 6
            color: Qt.rgba(1.0, 1.0, 1.0, 0.05)
            border.color: pairNameInput.activeFocus ? Color.accent : Qt.rgba(1.0, 1.0, 1.0, 0.15)
            border.width: 1

            TextInput {
              id: pairNameInput
              anchors.fill: parent
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              text: root.pairInputName
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              color: root.bar ? root.bar.foreground : Color.foreground
              selectByMouse: true
              cursorVisible: activeFocus
              verticalAlignment: Text.AlignVCenter
              onTextChanged: root.pairInputName = text

              Text {
                anchors.fill: parent
                visible: !pairNameInput.text && !pairNameInput.activeFocus
                text: "Örn: Telefon, İş Dizüstü"
                color: Qt.rgba(1.0, 1.0, 1.0, 0.25)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                verticalAlignment: Text.AlignVCenter
              }
            }
          }
        }

        // Status Feedback Banner
        Rectangle {
          width: parent.width
          implicitHeight: statusText.implicitHeight + Style.space(8)
          visible: root.pairStatusMsg.length > 0
          radius: 6
          color: root.pairStatusError ? Qt.rgba(0.9, 0.2, 0.2, 0.15) : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.15)
          border.color: root.pairStatusError ? "#f7768e" : Color.accent
          border.width: 1

          Text {
            id: statusText
            anchors.centerIn: parent
            width: parent.width - Style.space(16)
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
            text: root.pairStatusMsg
            color: root.pairStatusError ? "#f7768e" : Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.micro
            font.bold: true
          }
        }

        PanelSeparator {
          width: parent.width
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        // Action Buttons
        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          Rectangle {
            id: pairActionBtn
            Layout.fillWidth: true
            height: 36
            radius: 6
            property bool isReady: root.pairInputOmaId.replace(/[^0-9]/g, "").length === 16
            color: isReady
              ? (pairActionHover.containsMouse ? Qt.darker(Color.accent, 1.15) : Color.accent)
              : Qt.rgba(1.0, 1.0, 1.0, 0.05)
            border.color: isReady ? Color.accent : Qt.rgba(1.0, 1.0, 1.0, 0.12)
            border.width: 1

            RowLayout {
              anchors.centerIn: parent
              spacing: Style.space(6)
              Text {
                text: "󰌆"
                color: pairActionBtn.isReady ? "#000000" : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.8)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }
              Text {
                text: "Cihazı Bağla"
                color: pairActionBtn.isReady ? "#000000" : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.8)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }

            MouseArea {
              id: pairActionHover
              anchors.fill: parent
              enabled: pairActionBtn.isReady
              hoverEnabled: true
              cursorShape: pairActionBtn.isReady ? Qt.PointingHandCursor : Qt.ArrowCursor
              onClicked: root.bindOmaId(root.pairInputOmaId, root.pairInputName)
            }
          }

          Rectangle {
            Layout.preferredWidth: 60
            height: 36
            radius: 6
            color: cancelHover.containsMouse ? Qt.rgba(1.0, 1.0, 1.0, 0.12) : Qt.rgba(1.0, 1.0, 1.0, 0.05)
            border.color: Qt.rgba(1.0, 1.0, 1.0, 0.15)
            border.width: 1

            Text {
              anchors.centerIn: parent
              text: "İptal"
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            MouseArea {
              id: cancelHover
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: {
                root.showOmaIdPairModal = false
                root.pairStatusMsg = ""
              }
            }
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
          text: "Sürüm: " + root.pluginVersion + "\nGeliştirici: " + root.pluginAuthor + "\nLisans: " + root.pluginLicense + "\n" + root.pluginDescription
          color: root.bar ? root.bar.foreground : Color.foreground
          opacity: 0.8
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
