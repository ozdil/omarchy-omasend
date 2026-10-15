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

  // --- Automatic Multi-Language (i18n) Detection from Device Locale ---
  readonly property string rawSystemLocale: Quickshell.env("LC_ALL")
    || Quickshell.env("LC_MESSAGES")
    || Quickshell.env("LANG")
    || Qt.locale().name
    || "en"
  readonly property string systemLang: OmaI18n.detectLang(root.rawSystemLocale, Qt.locale().name)

  function t(key) {
    return OmaI18n.tr(root.systemLang, key)
  }

  // --- Core Engine & Network State ---
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

  // --- Anonim OmaID (Zero-Knowledge Account ID) & Device ID State ---
  property string p2pVisibility: "KNOWN"
  property int p2pVisibilityRemainingSecs: 0
  property var p2pPeers: []
  property var p2pPendingTransfer: null
  property var p2pTransferProgress: null
  property bool soundEnabled: true
  property string firewallStatus: "OK"

  property string omaId: ""
  property string deviceId: ""
  property string hostname: "Omarchy-PC"
  property string omaidQrPath: ""
  property bool omaIdRevealed: true
  property bool omaIdCopiedFeedback: false

  // --- Two-Mode Selector: "own" (Kendi OmaID) vs "foreign" (Yabancı OmaID) ---
  property string targetScope: "own"
  property bool showSyncSection: false
  property bool showQrSection: false
  property bool showAboutSection: false

  property string syncInputOmaId: ""
  property string syncStatusMsg: ""
  property bool syncStatusError: false

  property string directTargetInput: ""
  property string directStatusMsg: ""
  property bool directStatusError: false

  // --- Drop HUD State (Strictly Native Wayland DropArea) ---
  property bool dropActive: false
  property bool dropBlasting: false
  property real dropProximity: 0.0
  property real blastProgress: 0.0
  property string blastTargetName: ""
  property int blastedCount: 0

  // --- Keyboard & Mouse Cursor Model (Official Omarchy Network Panel Standard) ---
  property int selectedPeerIndex: 0
  property bool cursorActive: false
  property string focusSection: "peers"

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
  readonly property string peersPath: root.userHome + "/.local/state/omarchy/omasend/discovered_peers.json"
  readonly property string omaidQrFilePath: root.userHome + "/.local/state/omarchy/omasend/omaid_qr.svg"
  readonly property string manifestPath: Qt.resolvedUrl("manifest.json").toString().replace(/^file:\/\//, "")
  readonly property string manifestFallbackPath: root.userHome + "/.config/omarchy/plugins/ozdil.omasend/manifest.json"

  property string pluginVersion: "1.9.1"
  property string pluginDescription: "Anonim OmaID (Zero-Knowledge Identity) & AirBridge P2P Dosya Aktarım Sistemi"
  property string pluginAuthor: "Ozan Özdil (@ozdil)"
  property string pluginLicense: "MIT"

  // --- Peer Separation: Own Devices (Same OmaID -> Zero-Click) vs Foreign OmaID Devices ---
  readonly property var ownPeers: {
    if (root.p2pVisibility === "OFF" || !root.p2pPeers) return []
    var myClean = String(root.omaId || "").replace(/[^0-9]/g, "")
    var out = []
    for (var i = 0; i < root.p2pPeers.length; i++) {
      var p = root.p2pPeers[i]
      if (!p) continue
      var pClean = String(p.oma_id || "").replace(/[^0-9]/g, "")
      if (pClean.length !== 16) continue
      var sameOwner = Boolean(p.is_same_owner) || (myClean.length === 16 && pClean === myClean)
      if (sameOwner) out.push(p)
    }
    return out
  }

  readonly property var otherPeers: {
    if (root.p2pVisibility === "OFF" || !root.p2pPeers) return []
    var myClean = String(root.omaId || "").replace(/[^0-9]/g, "")
    var out = []
    for (var i = 0; i < root.p2pPeers.length; i++) {
      var p = root.p2pPeers[i]
      if (!p) continue
      var pClean = String(p.oma_id || "").replace(/[^0-9]/g, "")
      if (pClean.length !== 16) continue
      var sameOwner = Boolean(p.is_same_owner) || (myClean.length === 16 && pClean === myClean)
      if (!sameOwner) out.push(p)
    }
    return out
  }

  function loadManifest(rawJson) {
    try {
      if (!rawJson) return
      var parsed = JSON.parse(rawJson)
      if (parsed.version) root.pluginVersion = parsed.version
      if (parsed.description) root.pluginDescription = parsed.description
      if (parsed.author) root.pluginAuthor = parsed.author
      if (parsed.license) root.pluginLicense = parsed.license
    } catch (e) {}
  }

  function formatOmaId(id, revealed) {
    if (!id || String(id).trim() === "") return "---- ---- ---- ----"
    var clean = String(id).replace(/[^0-9]/g, "")
    if (!revealed) {
      if (clean.length >= 16) return "••••-••••-••••-" + clean.slice(12, 16)
      return "••••-••••-••••-••••"
    }
    if (clean.length === 16) {
      return clean.slice(0, 4) + "-" + clean.slice(4, 8) + "-" + clean.slice(8, 12) + "-" + clean.slice(12, 16)
    }
    return clean
  }

  function formatShortDeviceId(devId) {
    if (!devId || String(devId).trim() === "") return "----"
    var clean = String(devId).trim().toUpperCase()
    if (clean.length > 8) return clean.slice(0, 4) + "-" + clean.slice(4, 8)
    return clean
  }

  function formatPeerIdentity(peer) {
    if (!peer) return ""
    var oma = root.formatOmaId(peer.oma_id || "", true)
    var dev = root.formatShortDeviceId(peer.id || "")
    return oma + " / " + dev
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

  function isValidLuhnOmaId(val) {
    var clean = String(val || "").replace(/[^0-9]/g, "")
    if (clean.length !== 16) return false
    var sum = 0
    for (var i = 0; i < 16; i++) {
      var d = parseInt(clean.charAt(15 - i), 10)
      if (isNaN(d)) return false
      if (i % 2 === 1) {
        d *= 2
        if (d > 9) d -= 9
      }
      sum += d
    }
    return (sum % 10) === 0
  }

  function loadDiscoveredPeers(content) {
    try {
      if (!content || String(content).trim() === "") return
      var parsed = JSON.parse(content)
      if (Array.isArray(parsed)) root.p2pPeers = parsed
    } catch (e) {}
  }

  function syncOwnOmaId(candidateId) {
    var clean = String(candidateId || "").replace(/[^0-9]/g, "")
    if (clean.length !== 16) {
      root.syncStatusMsg = root.t("err_omaid_16_digits")
      root.syncStatusError = true
      return
    }
    if (!root.isValidLuhnOmaId(clean)) {
      root.syncStatusMsg = root.t("err_omaid_luhn")
      root.syncStatusError = true
      return
    }
    var formatted = root.formatOmaId(clean, true)
    root.syncStatusMsg = root.t("msg_syncing_id")
    root.syncStatusError = false
    if (setOwnOmaIdProc.running) setOwnOmaIdProc.running = false
    setOwnOmaIdProc.targetFormattedId = formatted
    setOwnOmaIdProc.command = [root.resolveEnginePath(), "--set-oma-id", formatted]
    setOwnOmaIdProc.running = true
  }

  function generateNewOwnOmaId() {
    root.syncStatusMsg = root.t("msg_generating_new_id")
    root.syncStatusError = false
    if (newOwnOmaIdProc.running) newOwnOmaIdProc.running = false
    newOwnOmaIdProc.running = true
  }

  function sendToDirectTarget(targetStr) {
    var trimmed = String(targetStr || "").trim()
    if (trimmed === "") {
      root.directStatusMsg = root.t("msg_enter_foreign_omaid")
      root.directStatusError = true
      return
    }
    var digitsOnly = trimmed.replace(/[^0-9]/g, "")
    if (digitsOnly.length !== 16 || !root.isValidLuhnOmaId(digitsOnly)) {
      root.directStatusMsg = root.t("err_omaid_16_digits")
      root.directStatusError = true
      return
    }
    var formatted = root.formatOmaId(digitsOnly, true)
    root.directStatusMsg = root.t("msg_opening_file_picker") + " (" + formatted + ")..."
    root.directStatusError = false
    root.sendFileTo(formatted)
  }

  function scanFromScreen(forSync) {
    if (forSync) {
      root.syncStatusMsg = root.t("msg_scanning_screen_qr")
      root.syncStatusError = false
    } else {
      root.directStatusMsg = root.t("msg_scanning_screen_qr")
      root.directStatusError = false
    }
    screenScanProc.forSync = Boolean(forSync)
    if (screenScanProc.running) screenScanProc.running = false
    screenScanProc.running = true
  }

  function pasteOmaIdFromClipboard(targetMode) {
    pasteProc.targetMode = targetMode || "direct"
    if (pasteProc.running) pasteProc.running = false
    pasteProc.running = true
  }

  function forceScan() {
    if (forceScanProc.running) forceScanProc.running = false
    forceScanProc.running = true
  }

  function resolveEnginePath() {
    return root.userHome + "/.local/bin/omasend-engine"
  }

  function executeAction(args) {
    if (actionProc.running) actionProc.running = false
    actionProc.command = [root.resolveEnginePath()].concat(args)
    actionProc.running = true
  }

  function refresh() {
    if (!serverProc.running) serverProc.running = true
    if (omaIdDirectReadProc.running) omaIdDirectReadProc.running = false
    omaIdDirectReadProc.running = true
    if (scanProc.running) scanProc.running = false
    scanProc.running = true
  }

  function setP2pVisibility(mode) {
    var m = (mode === "OFF") ? "OFF" : "KNOWN"
    root.p2pVisibility = m
    if (m === "OFF") root.p2pPeers = []
    root.executeAction(["--set-visibility", m])
  }

  function togglePower() {
    if (root.p2pVisibility === "OFF") {
      root.setP2pVisibility("KNOWN")
    } else {
      root.setP2pVisibility("OFF")
    }
  }

  function resolveActiveDropPeer() {
    if (root.ownPeers && root.ownPeers.length > 0) return root.ownPeers[0]
    if (root.p2pPeers && root.selectedPeerIndex >= 0 && root.selectedPeerIndex < root.p2pPeers.length) {
      return root.p2pPeers[root.selectedPeerIndex]
    }
    if (root.p2pPeers && root.p2pPeers.length > 0) return root.p2pPeers[0]
    return null
  }

  function handleDroppedData(drop) {
    var fileList = []
    if (drop.hasUrls && drop.urls.length > 0) {
      for (var i = 0; i < drop.urls.length; i++) {
        var u = drop.urls[i].toString().replace(/^file:\/\//, "")
        try { u = decodeURIComponent(u) } catch (e) {}
        if (u.trim() !== "") fileList.push(u.trim())
      }
    } else if (drop.hasText && drop.text) {
      var lines = drop.text.split("\n")
      for (var j = 0; j < lines.length; j++) {
        var l = lines[j].replace(/^file:\/\//, "").trim()
        try { l = decodeURIComponent(l) } catch (e) {}
        if (l !== "") fileList.push(l)
      }
    }

    root.blastedCount = fileList.length
    if (root.soundEnabled) {
      if (playSendSoundProc.running) playSendSoundProc.running = false
      playSendSoundProc.running = true
    }

    var targetPeer = root.resolveActiveDropPeer()
    var targetAddr = targetPeer ? (targetPeer.ip || targetPeer.oma_id) : ""
    root.blastTargetName = targetPeer ? (targetPeer.name || targetPeer.ip) : root.t("waiting_for_device")

    if (targetAddr !== "" && fileList.length > 0) {
      for (var k = 0; k < fileList.length; k++) {
        root.executeAction(["--send", targetAddr, fileList[k]])
      }
    }

    root.dropBlasting = true
    blastAnim.restart()
  }

  function moveCursor(dy) {
    if (!cursorActive) {
      cursorActive = true
      selectedPeerIndex = 0
      return
    }
    var total = root.ownPeers.length + root.otherPeers.length
    if (total === 0) return
    selectedPeerIndex = Math.max(0, Math.min(total - 1, selectedPeerIndex + dy))
  }

  function activateSelected() {
    if (root.p2pPendingTransfer && root.p2pPendingTransfer.status === "PENDING") {
      root.acceptTransfer(root.p2pPendingTransfer.token)
      return
    }
    var all = root.ownPeers.concat(root.otherPeers)
    if (all.length > selectedPeerIndex && selectedPeerIndex >= 0) {
      var peer = all[selectedPeerIndex]
      if (peer && (peer.ip || peer.oma_id)) {
        root.sendFileTo(peer.ip || peer.oma_id)
      }
    }
  }

  onOpenedChanged: {
    if (root.opened) {
      selectedPeerIndex = 0
      cursorActive = false
      if (panelFlick) panelFlick.contentY = 0
      root.forceScan()
      root.refresh()
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    }
  }

  function acceptTransfer(token) { root.executeAction(["--accept-transfer", token]) }
  function rejectTransfer(token) { root.executeAction(["--reject-transfer", token]) }
  function cancelTransfer() {
    root.p2pTransferProgress = null
    root.executeAction(["--cancel-transfer"])
  }
  function toggleSound() {
    root.soundEnabled = !root.soundEnabled
    root.executeAction(["--toggle-sound"])
  }
  function syncClipboardTo(ipOrOmaId) { root.executeAction(["--sync-clipboard", ipOrOmaId]) }

  function sendFileTo(ipOrOmaId) {
    if (sendDialogProc.running) sendDialogProc.running = false
    sendDialogProc.command = [root.resolveEnginePath(), "--send-dialog", ipOrOmaId]
    sendDialogProc.running = true
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

  // --- Background Processes ---
  Process {
    id: omaIdDirectReadProc
    command: ["cat", root.userHome + "/.local/state/omarchy/omasend/oma_id"]
    running: true
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        omaIdDirectReadProc.running = false
        var val = String(text || "").trim()
        if (val.length >= 16) root.omaId = val
      }
    }
  }

  Process {
    id: setOwnOmaIdProc
    property string targetFormattedId: ""
    onExited: function(code) {
      setOwnOmaIdProc.running = false
      if (code === 0) {
        root.omaId = setOwnOmaIdProc.targetFormattedId
        root.syncStatusMsg = root.t("msg_id_synced") + setOwnOmaIdProc.targetFormattedId
        root.syncStatusError = false
        root.refresh()
        syncCloseTimer.restart()
      } else {
        root.syncStatusMsg = root.t("msg_id_save_failed")
        root.syncStatusError = true
      }
    }
  }

  Process {
    id: newOwnOmaIdProc
    command: [root.resolveEnginePath(), "--new-oma-id"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        newOwnOmaIdProc.running = false
        var val = String(text || "").trim()
        if (val.length >= 16) {
          root.omaId = val
          root.syncInputOmaId = root.formatInputOmaId(val)
          root.syncStatusMsg = root.t("msg_new_id_generated") + root.formatOmaId(val, true)
          root.syncStatusError = false
          root.forceScan()
          root.refresh()
        }
      }
    }
  }

  Timer {
    id: syncCloseTimer
    interval: 1200
    repeat: false
    onTriggered: {
      if (!root.syncStatusError) {
        root.showSyncSection = false
        root.syncStatusMsg = ""
      }
    }
  }

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
    onExited: function(code) { scanProc.running = false }
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
          var rawVis = String(d.p2p_visibility || "KNOWN")
          root.p2pVisibility = (rawVis === "OFF") ? "OFF" : "KNOWN"
          root.p2pVisibilityRemainingSecs = Number(d.p2p_visibility_remaining_secs) || 0
          root.p2pPeers = d.p2p_discovered_peers || []
          root.p2pPendingTransfer = d.p2p_pending_transfer || null
          root.p2pTransferProgress = d.p2p_transfer_progress || null
          if (d.sound_enabled !== undefined) root.soundEnabled = Boolean(d.sound_enabled)
          root.firewallStatus = String(d.firewall_status || "OK")
          root.deviceId = String(d.p2p_device_id || "")
          root.hostname = String(d.p2p_hostname || "Omarchy-PC")
          root.omaId = String(d.oma_id || "")
          root.refreshNonce++
        } catch (e) {}
      }
    }
  }

  Timer {
    id: omaIdCopyTimer
    interval: 1800
    repeat: false
    onTriggered: root.omaIdCopiedFeedback = false
  }

  Process {
    id: screenScanProc
    property bool forSync: false
    command: ["bash", "-c", "rm -f /tmp/oma_qr_scan.png && /usr/bin/grim /tmp/oma_qr_scan.png 2>/dev/null && (/usr/bin/zbarimg -q --raw /tmp/oma_qr_scan.png 2>/dev/null || true) && rm -f /tmp/oma_qr_scan.png"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        screenScanProc.running = false
        var raw = String(text || "").trim()
        var clean = raw.replace(/[^0-9]/g, "")
        if (clean.length >= 16) {
          var formatted = root.formatInputOmaId(clean.slice(0, 16))
          if (screenScanProc.forSync) {
            root.syncInputOmaId = formatted
            root.syncStatusMsg = root.t("msg_qr_read") + formatted
            root.syncStatusError = false
          } else {
            root.directTargetInput = formatted
            root.directStatusMsg = root.t("msg_qr_read") + formatted
            root.directStatusError = false
          }
        } else {
          if (screenScanProc.forSync) {
            root.syncStatusMsg = root.t("msg_qr_not_found")
            root.syncStatusError = true
          } else {
            root.directStatusMsg = root.t("msg_qr_not_found")
            root.directStatusError = true
          }
        }
      }
    }
  }

  Process {
    id: pasteProc
    property string targetMode: "direct"
    command: ["wl-paste", "--no-newline"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        pasteProc.running = false
        var raw = String(text || "").trim()
        if (raw.length === 0) return
        var clean = raw.replace(/[^0-9]/g, "")
        if (pasteProc.targetMode === "sync") {
          if (clean.length >= 16) {
            root.syncInputOmaId = root.formatInputOmaId(clean.slice(0, 16))
            root.syncStatusMsg = root.t("msg_clipboard_pasted")
            root.syncStatusError = false
          } else {
            root.syncStatusMsg = root.t("msg_clipboard_no_omaid")
            root.syncStatusError = true
          }
        } else {
          if (clean.length >= 16) {
            root.directTargetInput = root.formatInputOmaId(clean.slice(0, 16))
            root.directStatusMsg = ""
            root.directStatusError = false
          } else {
            root.directStatusMsg = root.t("msg_clipboard_no_omaid")
            root.directStatusError = true
          }
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
      root.directStatusMsg = ""
      root.refresh()
    }
  }

  Process { id: copyProc }
  Process { id: folderProc }
  Process {
    id: playSendSoundProc
    command: ["pw-play", Qt.resolvedUrl("assets/send.wav").toString().replace(/^file:\/\//, "")]
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
    onLoadFailed: manifestFallbackWatcher.reload()
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
    interval: 1000
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
      if (!serverProc.running) serverProc.running = true
      if (root.opened) root.refresh()
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

  // =========================================================================
  // 1. BAR BUTTON & PROXIMITY WAYLAND DROP SENSOR
  // =========================================================================
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.dropBlasting ? "󰄬" : ""
    active: root.dropActive || root.dropBlasting
    useActiveColor: false
    foreground: (root.dropActive || root.dropBlasting) ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
    tooltipText: "OmaSend (" + root.formatOmaId(root.omaId, true) + " / " + root.formatShortDeviceId(root.deviceId) + ")"
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

      onExited: {
        dropHandoffTimer.restart()
      }

      onDropped: function(drop) {
        dropHandoffTimer.stop()
        if (drop.hasUrls || drop.hasText) {
          drop.acceptProposedAction()
          root.handleDroppedData(drop)
        }
      }
    }
  }

  Behavior on dropProximity {
    NumberAnimation { duration: 140; easing.type: Easing.OutCubic }
  }

  Timer {
    id: dropHandoffTimer
    interval: 160
    repeat: false
    onTriggered: {
      if (!iconDropArea.containsDrag && !hudDropArea.containsDrag && !root.dropBlasting) {
        root.dropActive = false
        root.dropProximity = 0.0
      }
    }
  }

  Timer {
    id: dropSafetyWatchdog
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
    running: false
    NumberAnimation {
      target: root
      property: "blastProgress"
      from: 0.0
      to: 1.0
      duration: 520
      easing.type: Easing.OutCubic
    }
    ScriptAction {
      script: {
        root.dropBlasting = false
        root.blastProgress = 0.0
        root.dropActive = false
        root.dropProximity = 0.0
      }
    }
  }

  // =========================================================================
  // 2. BAR-INTEGRATED MAGNETIC DROP HUD (`PopupCard`)
  // =========================================================================
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

      onExited: {
        dropHandoffTimer.restart()
      }

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
            PathAngleArc {
              centerX: Style.space(22)
              centerY: Style.space(22)
              radiusX: Style.space(19)
              radiusY: Style.space(19)
              startAngle: 0
              sweepAngle: 360
            }
          }

          ShapePath {
            strokeWidth: Style.space(7)
            strokeColor: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.18 * root.dropProximity)
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap
            PathAngleArc {
              centerX: Style.space(22)
              centerY: Style.space(22)
              radiusX: Style.space(19)
              radiusY: Style.space(19)
              startAngle: -90
              sweepAngle: 360 * (root.dropBlasting ? 1.0 : Math.min(1.0, 0.25 + root.dropProximity * 0.75))
            }
          }

          ShapePath {
            strokeWidth: Style.space(3)
            strokeColor: Color.accent
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap
            PathAngleArc {
              centerX: Style.space(22)
              centerY: Style.space(22)
              radiusX: Style.space(19)
              radiusY: Style.space(19)
              startAngle: -90
              sweepAngle: 360 * (root.dropBlasting ? 1.0 : Math.min(1.0, 0.25 + root.dropProximity * 0.75))
            }
          }
        }

        BorderSurface {
          anchors.centerIn: parent
          implicitWidth: Style.space(30)
          implicitHeight: Style.space(30)
          radius: Style.space(15)
          color: Style.selectedFillFor(root.foreground, Color.accent)
          borderSpec: Border.none()

          Text {
            anchors.centerIn: parent
            textFormat: Text.PlainText
            text: root.dropBlasting ? "󰄬" : ""
            color: Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }
        }
      }

      ColumnLayout {
        Layout.fillWidth: true
        Layout.alignment: Qt.AlignVCenter
        spacing: Style.space(2)

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: {
            if (root.dropBlasting) return root.t("drop_transfer_started")
            var p = root.resolveActiveDropPeer()
            return "OMASEND AIRBRIDGE"
          }
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
          text: {
            if (root.dropBlasting && root.blastTargetName !== "") return root.blastTargetName
            var p = root.resolveActiveDropPeer()
            return p ? (p.name + " (" + root.formatShortDeviceId(p.id) + ")") : root.t("waiting_for_device")
          }
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
                : root.t("drop_here_hint")
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }
    }
  }

  // =========================================================================
  // 3. MAIN KEYBOARD PANEL (100% Omarchy Network Panel Style — Ultra Clean)
  // =========================================================================
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(column.implicitHeight + stickyFooter.implicitHeight + Style.space(12), Style.space(580))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) {
        if (dy !== 0) root.moveCursor(dy)
      }
      onActivateRequested: root.activateSelected()
      onCloseRequested: {
        if (root.showSyncSection || root.showQrSection || root.showAboutSection) {
          root.showSyncSection = false
          root.showQrSection = false
          root.showAboutSection = false
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R") root.forceScan()
        else if (t === "o" || t === "O") root.openFolder()
      }

      Flickable {
        id: panelFlick
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: stickyFooter.top
        anchors.bottomMargin: Style.space(10)
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Behavior on contentY {
          NumberAnimation { duration: 220; easing.type: Easing.OutCubic }
        }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(12)

          // -----------------------------------------------------------------
          // 1. HERO HEADER (Exact Omarchy Network Panel Structure)
          // -----------------------------------------------------------------
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
              opacity: root.p2pVisibility !== "OFF" ? 1.0 : 0.5
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
                tooltipText: root.t("show_qr_tooltip")
                foreground: root.showQrSection ? Color.accent : root.foreground
                fontFamily: root.fontFamily
                iconSize: Style.font.subtitle * 1.4
                horizontalPadding: Style.space(5)
                verticalPadding: Style.space(2)
                Layout.alignment: Qt.AlignVCenter
                onClicked: {
                  root.showQrSection = !root.showQrSection
                  root.showSyncSection = false
                  if (root.showQrSection) root.executeAction(["--oma-id-qr"])
                }
              }

              Button {
                iconText: "󰑐"
                tooltipText: root.t("refresh_scan_tooltip")
                foreground: root.foreground
                fontFamily: root.fontFamily
                iconSize: Style.font.subtitle * 1.4
                horizontalPadding: Style.space(5)
                verticalPadding: Style.space(2)
                Layout.alignment: Qt.AlignVCenter
                onClicked: root.forceScan()
              }

              ToggleSwitch {
                id: powerSwitch
                checked: root.p2pVisibility !== "OFF"
                foreground: root.foreground
                Layout.alignment: Qt.AlignVCenter
                onToggled: root.togglePower()

                PanelToolTip {
                  visible: powerSwitch.containsMouse
                  text: root.p2pVisibility !== "OFF" ? root.t("turn_off_service") : root.t("turn_on_service")
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
                text: "OmaSend (" + root.hostname + ")"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.p2pVisibility !== "OFF"
                      ? (root.omaIdCopiedFeedback ? root.t("omaid_copied_sub") : root.t("service_active_sub"))
                      : root.t("service_disabled_sub")
                color: root.omaIdCopiedFeedback ? Color.accent : Qt.darker(root.foreground, 1.4)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.2
                elide: Text.ElideRight
              }
            }
          }

          // -----------------------------------------------------------------
          // 2. 4-COLUMN TELEMETRY & IDENTITY GRID (Exact Omarchy Network Style)
          //    Displays: OmaID | Cihaz ID | Yerel IP | Alınan
          // -----------------------------------------------------------------
          GridLayout {
            width: parent.width
            columns: 4
            columnSpacing: Style.space(16)
            rowSpacing: Style.spacing.labelGap

            InfoLabel { text: "OmaID" }
            DetailValue {
              text: root.formatOmaId(root.omaId, root.omaIdRevealed)
              copyable: true
              tooltipText: root.t("copy_omaid_tooltip")
              onClickedAction: {
                if (root.omaId) {
                  root.copyText(root.omaId)
                  root.omaIdCopiedFeedback = true
                  omaIdCopyTimer.restart()
                }
              }
            }

            InfoLabel { text: root.t("label_device_id") }
            DetailValue {
              text: root.formatShortDeviceId(root.deviceId)
              copyable: true
              tooltipText: root.t("copy_device_id_tooltip")
              onClickedAction: {
                if (root.deviceId) root.copyText(root.deviceId)
              }
            }

            InfoLabel { text: root.t("label_ip_address") }
            DetailValue {
              text: root.localIp + ":" + root.port
              copyable: true
              tooltipText: root.t("copy_ip_tooltip")
              onClickedAction: root.copyText(root.localIp)
            }

            InfoLabel { text: root.t("label_received") }
            DetailValue {
              text: root.totalReceived + " " + root.t("files_unit")
              copyable: true
              tooltipText: root.t("open_downloads_tooltip")
              onClickedAction: root.openFolder()
            }
          }

          // Inline QR Card (Only shown when QR icon in Hero is clicked)
          BorderSurface {
            visible: root.showQrSection
            width: parent.width
            implicitHeight: qrCol.implicitHeight + Style.space(18)
            color: Style.normalFillFor(root.foreground, Color.accent)
            borderSpec: Border.controlSpec("normal", root.foreground, Color.accent)
            radius: Style.cornerRadius

            Column {
              id: qrCol
              anchors.centerIn: parent
              width: parent.width - Style.space(20)
              spacing: Style.space(8)

              Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                width: Style.space(140)
                height: Style.space(140)
                radius: Style.cornerRadius
                color: "#ffffff"

                Image {
                  anchors.centerIn: parent
                  width: Style.space(126)
                  height: Style.space(126)
                  source: root.omaidQrPath ? ("file://" + root.omaidQrPath + "?v=" + root.refreshNonce) : ""
                  fillMode: Image.PreserveAspectFit
                  cache: false
                }
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: "OMAID: " + root.formatOmaId(root.omaId, true) + " / " + root.t("label_device_id").toUpperCase() + ": " + root.formatShortDeviceId(root.deviceId)
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                elide: Text.ElideRight
              }
            }
          }

          // -----------------------------------------------------------------
          // 2B. FIREWALL WARNING BANNER (Visible only when UFW/Nftables blocks 53317)
          // -----------------------------------------------------------------
          BorderSurface {
            visible: root.firewallStatus.indexOf("UFW_ACTIVE_CHECK") === 0 || root.firewallStatus.indexOf("UFW_BLOCKED") === 0 || root.firewallStatus.indexOf("NFT_BLOCKED") === 0
            width: parent.width
            implicitHeight: fwWarnRow.implicitHeight + Style.space(12)
            color: Style.normalFillFor(root.foreground, root.urgent)
            borderSpec: Border.controlSpec("normal", root.foreground, root.urgent)
            radius: Style.cornerRadius

            RowLayout {
              id: fwWarnRow
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

          // -----------------------------------------------------------------
          // 3. INCOMING TRANSFER GATEKEEPER (Only visible when foreign OmaID sends)
          // -----------------------------------------------------------------
          Column {
            visible: root.p2pPendingTransfer !== null && root.p2pPendingTransfer.status === "PENDING"
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
              implicitHeight: pendingRowLayout.implicitHeight + Style.spacing.rowPaddingX

              RowLayout {
                id: pendingRowLayout
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
                    text: root.p2pPendingTransfer ? String(root.p2pPendingTransfer.sender_name || "") : ""
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                  }

                  Text {
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    text: root.p2pPendingTransfer
                          ? (String(root.p2pPendingTransfer.sender_id || "") + " · " + (root.p2pPendingTransfer.file_names || []).join(", "))
                          : ""
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
                  onClicked: if (root.p2pPendingTransfer) root.acceptTransfer(root.p2pPendingTransfer.token)
                }

                PanelActionButton {
                  iconText: "󰅖"
                  tooltipText: root.t("reject_btn")
                  foreground: root.urgent
                  hoverColor: root.urgent
                  fontFamily: root.fontFamily
                  onClicked: if (root.p2pPendingTransfer) root.rejectTransfer(root.p2pPendingTransfer.token)
                }
              }
            }
          }

          // -----------------------------------------------------------------
          // 3B. ACTIVE TRANSFER PROGRESS & CANCEL CARD
          // -----------------------------------------------------------------
          Column {
            visible: root.p2pTransferProgress !== null
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
              implicitHeight: activeTransferCol.implicitHeight + Style.space(14)

              ColumnLayout {
                id: activeTransferCol
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
                    text: (root.p2pTransferProgress && root.p2pTransferProgress.direction === "sending") ? "" : "󰇚"
                    color: Color.accent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                  }

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.p2pTransferProgress
                          ? (String(root.p2pTransferProgress.file_name || "") + " (" + Number(root.p2pTransferProgress.percent || 0) + "%)")
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
                    width: parent.width * Math.max(0.02, Math.min(1.0, (root.p2pTransferProgress ? Number(root.p2pTransferProgress.percent || 0) : 0) / 100.0))
                    height: parent.height
                    radius: parent.radius
                    color: Color.accent
                  }
                }
              }
            }
          }

          // -----------------------------------------------------------------
          // 4. KENDİ CİHAZLARIM (Same OmaID, Different Device ID — Zero-Click)
          //    Exact Omarchy "KNOWN NETWORKS" visual structure
          // -----------------------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          Column {
            width: parent.width
            spacing: Style.space(6)

            Item {
              width: parent.width
              implicitHeight: ownHeader.implicitHeight

              PanelSectionHeader {
                id: ownHeader
                text: root.t("own_devices_header")
                foreground: root.foreground
                fontFamily: root.fontFamily
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
              }

              Text {
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                textFormat: Text.PlainText
                text: root.showSyncSection ? root.t("close_action") : root.t("sync_omaid_action")
                color: root.showSyncSection ? Color.accent : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.showSyncSection = !root.showSyncSection
                    root.syncInputOmaId = root.formatInputOmaId(root.omaId)
                    root.syncStatusMsg = ""
                    if (root.showSyncSection) {
                      Qt.callLater(function() { syncField.forceActiveFocus() })
                    }
                  }
                }
              }
            }

            // Inline "OmaID Eşitle" Input (Only visible when "OmaID Eşitle" clicked)
            Column {
              visible: root.showSyncSection
              width: parent.width
              spacing: Style.space(6)

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                TextField {
                  id: syncField
                  Layout.fillWidth: true
                  foreground: root.foreground
                  placeholderText: root.t("own_omaid_placeholder")
                  text: root.syncInputOmaId
                  maximumLength: 19
                  onTextChanged: {
                    var formatted = root.formatInputOmaId(text)
                    if (formatted !== text) text = formatted
                    root.syncInputOmaId = text
                  }
                  onAccepted: root.syncOwnOmaId(root.syncInputOmaId)
                }

                PanelActionButton {
                  iconText: "󰅍"
                  tooltipText: root.t("paste_clipboard_tooltip")
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onClicked: root.pasteOmaIdFromClipboard("sync")
                }

                PanelActionButton {
                  iconText: "󰑓"
                  tooltipText: root.t("generate_new_omaid_tooltip")
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onClicked: root.generateNewOwnOmaId()
                }

                PanelActionButton {
                  iconText: "󰄬"
                  tooltipText: root.t("save_sync_omaid_tooltip")
                  foreground: Color.accent
                  bordered: true
                  fontFamily: root.fontFamily
                  onClicked: root.syncOwnOmaId(root.syncInputOmaId)
                }
              }

              Text {
                visible: root.syncStatusMsg !== ""
                width: parent.width
                textFormat: Text.PlainText
                text: root.syncStatusMsg
                color: root.syncStatusError ? root.urgent : Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }

            Repeater {
              model: root.ownPeers

              PeerRow {
                required property var modelData
                required property int index
                width: parent.width
                peer: modelData
                rowIndex: index
                isOwnDevice: true
              }
            }

            Text {
              visible: root.ownPeers.length === 0
              width: parent.width
              textFormat: Text.PlainText
              text: root.t("no_own_devices")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // -----------------------------------------------------------------
          // 5. YABANCI OMAID (Foreign OmaID Input + Discovered Foreign Peers)
          //    Exact Omarchy "OTHER NETWORKS" visual structure
          // -----------------------------------------------------------------
          PanelSeparator { foreground: root.foreground }

          Column {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: root.t("foreign_omaid_header")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            RowLayout {
              width: parent.width
              spacing: Style.space(6)

              TextField {
                id: directSendField
                Layout.fillWidth: true
                foreground: root.foreground
                placeholderText: "XXXX-XXXX-XXXX-XXXX"
                text: root.directTargetInput
                maximumLength: 19
                onTextChanged: {
                  var formatted = root.formatInputOmaId(text)
                  if (formatted !== text) text = formatted
                  root.directTargetInput = text
                }
                onAccepted: root.sendToDirectTarget(root.directTargetInput)
              }

              PanelActionButton {
                iconText: "󰅍"
                tooltipText: root.t("paste_clipboard_tooltip")
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.pasteOmaIdFromClipboard("direct")
              }

              PanelActionButton {
                iconText: "󰄳"
                tooltipText: root.t("scan_screen_qr_tooltip")
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.scanFromScreen(false)
              }

              PanelActionButton {
                iconText: ""
                tooltipText: root.t("select_file_send_tooltip")
                foreground: Color.accent
                bordered: true
                fontFamily: root.fontFamily
                onClicked: root.sendToDirectTarget(root.directTargetInput)
              }
            }

            Text {
              visible: root.directStatusMsg !== ""
              width: parent.width
              textFormat: Text.PlainText
              text: root.directStatusMsg
              color: root.directStatusError ? root.urgent : Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            Repeater {
              model: root.otherPeers

              PeerRow {
                required property var modelData
                required property int index
                width: parent.width
                peer: modelData
                rowIndex: root.ownPeers.length + index
                isOwnDevice: false
              }
            }
          }

          // -----------------------------------------------------------------
          // 7. INFO / HAKKINDA BÖLÜMÜ (Auto-scrolls into view when Info clicked)
          // -----------------------------------------------------------------
          BorderSurface {
            id: aboutCard
            visible: root.showAboutSection
            width: parent.width
            implicitHeight: aboutInlineCol.implicitHeight + Style.space(18)
            color: Style.normalFillFor(root.foreground, Color.accent)
            borderSpec: Border.controlSpec("normal", root.foreground, Color.accent)
            radius: Style.cornerRadius

            Column {
              id: aboutInlineCol
              anchors.centerIn: parent
              width: parent.width - Style.space(20)
              spacing: Style.space(6)

              RowLayout {
                width: parent.width
                spacing: Style.space(8)

                Text {
                  textFormat: Text.PlainText
                  text: ""
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }

                Text {
                  Layout.fillWidth: true
                  textFormat: Text.PlainText
                  text: "OmaSend v" + root.pluginVersion + " · " + root.t("about_subtitle")
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                  elide: Text.ElideRight
                }

                PanelActionButton {
                  iconText: "󰅖"
                  tooltipText: root.t("close_action")
                  foreground: root.dim
                  fontFamily: root.fontFamily
                  onClicked: root.showAboutSection = false
                }
              }

              PanelSeparator { foreground: root.foreground }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.t("about_identity_prefix") + " (" + root.formatOmaId(root.omaId, true) + " / " + root.formatShortDeviceId(root.deviceId) + ")"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.t("about_security_line")
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.t("about_author_prefix") + ": " + root.pluginAuthor + " · " + root.t("about_save_prefix") + ": " + root.savePath
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }
            }
          }
        }
      }

      // -----------------------------------------------------------------
      // 8. STICKY FOOTER MENU (Always Fixed at Bottom While Scrolling)
      // -----------------------------------------------------------------
      Column {
        id: stickyFooter
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: Style.space(6)

        PanelSeparator { foreground: root.foreground }

        CursorSurface {
          width: parent.width
          foreground: root.foreground
          implicitHeight: utilityRowLayout.implicitHeight + Style.spacing.rowPaddingX

          MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openFolder()
          }

          RowLayout {
            id: utilityRowLayout
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
              text: root.t("downloads_footer") + " (" + root.totalReceived + " " + root.t("files_unit") + ")"
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
              iconText: "󰉋"
              tooltipText: root.t("open_downloads_tooltip")
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.openFolder()
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
              foreground: root.showAboutSection ? Color.accent : root.foreground
              bordered: root.showAboutSection
              fontFamily: root.fontFamily
              onClicked: {
                root.showAboutSection = !root.showAboutSection
                if (root.showAboutSection) {
                  Qt.callLater(function() {
                    panelFlick.contentY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
                  })
                }
              }
            }
          }
        }
      }
    }
  }

  // =========================================================================
  // 4. REUSABLE COMPONENTS (Exact Omarchy Network Panel Components)
  // =========================================================================
  component ScopePill: Button {
    id: pill
    required property string label
    required property string scopeKey

    text: label
    fontSize: Style.font.bodySmall
    foreground: root.foreground
    fontFamily: root.fontFamily
    horizontalPadding: Style.spacing.controlPaddingX
    verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
    bordered: true
    active: root.targetScope === scopeKey
  }

  component PeerRow: CursorSurface {
    id: row
    required property var peer
    required property int rowIndex
    required property bool isOwnDevice

    current: isOwnDevice
    hasCursor: root.cursorActive && root.selectedPeerIndex === rowIndex
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
        root.selectedPeerIndex = row.rowIndex
      }
      onClicked: function(mouse) {
        if (!row.peer) return
        var target = row.peer.ip || row.peer.oma_id
        if (!target) return
        if (mouse.button === Qt.RightButton) {
          root.syncClipboardTo(target)
        } else {
          root.sendFileTo(target)
        }
      }
    }

    Item {
      id: rowBody
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      implicitHeight: Math.max(peerIcon.implicitHeight, peerInfo.implicitHeight, rightGlyph.implicitHeight) + Style.spacing.rowPaddingX

      Text {
        id: peerIcon
        textFormat: Text.PlainText
        text: (row.peer && row.peer.name && String(row.peer.name).toLowerCase().indexOf("android") !== -1) ? "󰏲" : "󰌢"
        color: row.isOwnDevice ? root.foreground : Qt.darker(root.foreground, 1.4)
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
      }

      Text {
        id: rightGlyph
        textFormat: Text.PlainText
        text: row.isOwnDevice ? "" : "󰌾"
        color: row.isOwnDevice ? root.foreground : Qt.darker(root.foreground, 1.4)
        font.family: root.fontFamily
        font.pixelSize: Style.font.subtitle
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
      }

      Column {
        id: peerInfo
        spacing: Style.space(1)
        anchors.left: peerIcon.right
        anchors.leftMargin: Style.space(10)
        anchors.right: rightGlyph.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter

        Text {
          width: parent.width
          textFormat: Text.PlainText
          text: row.peer ? String(row.peer.name || "") : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }

        Text {
          width: parent.width
          textFormat: Text.PlainText
          text: row.peer
                ? (root.formatPeerIdentity(row.peer) + " · " + root.t("approval_send"))
                : ""
          color: row.isOwnDevice ? root.foreground : Qt.darker(root.foreground, 1.5)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }
    }
  }

  component DetailValue: InfoValue {
    property bool copyable: false
    property string tooltipText: "Kopyala"
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
      visible: valueMouse.enabled && valueMouse.containsMouse
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
