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

  // --- Link with OmaID (needs an engine with --link / --account-id) ---
  property string pairMode: "qr"
  property string accountId: ""
  property bool showAccountId: false
  property bool linkSupported: false

  // --- Pair a browser (needs an engine with --pair-offer-web; detected on first use) ---
  property bool webSupported: true
  property string pairWebUrl: ""
  property bool pairWebInstalled: true

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

  // --- Layout ---
  readonly property int tileColumns: 4
  property bool showNearby: false
  property bool showDetails: false

  // Monochrome: one ink, the theme's foreground, follows every Omarchy theme change.
  // States are told apart by glyph, weight and opacity, never by a second hue.
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color ink: foreground
  readonly property color urgent: foreground
  // 0.85 keeps secondary text at WCAG AA (4.5:1) even on low-contrast light themes
  // such as Rosé Pine Dawn and Catppuccin Latte; hierarchy comes from size and weight.
  readonly property color dim: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.85)
  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, root.ink) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, root.ink) : "transparent"
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
  readonly property var nearbyAll: {
    if (!root.serviceOn || !root.discovered) return []
    var out = []
    for (var i = 0; i < root.discovered.length; i++) {
      var p = root.discovered[i]
      if (p && !p.key_trust) out.push(p)
    }
    return out
  }

  // Unencrypted peers stay folded away until asked for, so they are never a keyboard or drop target by accident.
  readonly property var nearby: root.showNearby ? root.nearbyAll : []

  // One word for the panel's security state: secure, blocked or off.
  readonly property string securityState: {
    if (!root.serviceOn) return "off"
    var fw = root.firewallStatus
    if (fw.indexOf("UFW_ACTIVE_CHECK") === 0 || fw.indexOf("UFW_BLOCKED") === 0 || fw.indexOf("NFT_BLOCKED") === 0) return "blocked"
    return "secure"
  }
  readonly property color securityColor: root.securityState === "secure" ? root.ink
                                       : (root.securityState === "blocked" ? root.urgent : root.dim)

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

  // Source installs (build.sh) put the engine in ~/.local/bin, the package in /usr/bin.
  property string enginePath: root.userHome + "/.local/bin/omasend-engine"
  property bool engineLocated: false
  function engine() { return root.enginePath }

  function run(args) {
    if (actionProc.running) actionProc.running = false
    actionProc.command = [root.engine()].concat(args)
    actionProc.running = true
  }

  function refresh() {
    if (root.engineLocated && !serverProc.running) serverProc.running = true
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
    root.showAccountId = false
    root.newPairOffer()
    if (!accountProc.running) accountProc.running = true
  }

  function omaIdDigits(text) { return String(text || "").replace(/[^0-9]/g, "") }

  // 16 digits with a valid Luhn check digit, same rule as the engine.
  function omaIdValid(text) {
    var d = root.omaIdDigits(text)
    if (d.length !== 16) return false
    var sum = 0
    for (var i = 0; i < 16; i++) {
      var n = Number(d.charAt(15 - i))
      if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9 }
      sum += n
    }
    return sum % 10 === 0
  }

  function formatAccountId(id, masked) {
    var d = root.omaIdDigits(id)
    var groups = []
    for (var i = 0; i < d.length; i += 4) groups.push(masked && i < d.length - 4 ? "••••" : d.slice(i, i + 4))
    return groups.join(" ")
  }

  function linkWithOmaId(text) {
    if (linkProc.running) return
    if (!root.omaIdValid(text)) {
      root.setStatus(root.t("link_invalid"), true)
      return
    }
    root.setStatus(root.t("link_working"), false)
    linkProc.output = ""
    linkProc.command = [root.engine(), "--link", root.omaIdDigits(text), "--json"]
    linkProc.running = true
  }

  function newPairOffer() {
    root.pairQrPath = ""
    if (pairProc.running) pairProc.running = false
    root.pairWebUrl = ""
    var flag = root.pairMode === "web" ? "--pair-offer-web" : "--pair-offer"
    pairProc.command = [root.engine(), flag, "--json"].concat(root.pairOwn ? ["--own"] : [])
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

  function moveCursor(delta) {
    if (!root.cursorActive) {
      root.cursorActive = true
      root.selectedIndex = 0
      return
    }
    if (root.targets.length === 0) return
    root.selectedIndex = Math.max(0, Math.min(root.targets.length - 1, root.selectedIndex + delta))
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
      root.showDetails = false
      if (panelFlick) panelFlick.contentY = 0
      root.forceScan()
      root.refresh()
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    } else {
      root.showPair = false
      root.showAccountId = false
      linkInput.text = ""
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
    id: engineLocator
    running: true
    command: ["sh", "-c", "for p in \"$HOME/.local/bin/omasend-engine\" /usr/bin/omasend-engine; do if [ -x \"$p\" ]; then echo \"$p\"; exit 0; fi; done"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var p = String(text || "").trim()
        if (p) root.enginePath = p
        root.engineLocated = true
        if (!serverProc.running) serverProc.running = true
      }
    }
  }

  Process {
    id: serverProc
    command: [root.engine(), "--serve"]
    running: false
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
          // Older engines answer --pair-offer-web --json with the status JSON (no web_url): hide the browser tab.
          if (root.pairMode === "web" && !d.web_url) {
            root.webSupported = false
            root.pairMode = "qr"
            root.setStatus(root.t("web_pair_unsupported"), true)
            root.newPairOffer()
            return
          }
          root.pairWebUrl = String(d.web_url || "")
          root.pairWebInstalled = d.web_installed !== false
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

  // Older engines answer --account-id --json with the status JSON, which has no account_id: the OmaID tab stays hidden.
  Process {
    id: accountProc
    command: [root.engine(), "--account-id", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        accountProc.running = false
        try {
          var d = JSON.parse(String(text || "").slice(0, 65536))
          var id = String(d.account_id || "")
          root.linkSupported = root.omaIdValid(id)
          root.accountId = root.linkSupported ? root.omaIdDigits(id) : ""
        } catch (e) {
          root.linkSupported = false
        }
        if (!root.linkSupported && root.pairMode === "omaid") root.pairMode = "qr"
      }
    }
  }

  Process {
    id: linkProc
    property string output: ""
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: linkProc.output = String(text || "").slice(0, 65536) }
    onExited: function(code) {
      linkProc.running = false
      var d = null
      try { d = JSON.parse(linkProc.output) } catch (e) {}
      if (d && d.ok) {
        var names = []
        for (var i = 0; i < (d.linked || []).length; i++) names.push(String(d.linked[i].name || ""))
        root.setStatus(root.tf("link_ok", names.join(", ")), false)
        linkInput.text = ""
        root.showPair = false
      } else {
        root.setStatus(d && d.error ? String(d.error) : root.t("link_failed"), true)
      }
      root.refresh()
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
      if (root.engineLocated && !serverProc.running) serverProc.running = true
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
    // The glyph only reserves the button's size; the OmaSend logo below is what is drawn.
    text: root.dropBlasting ? "󰄬" : ""
    active: root.dropActive || root.dropBlasting
    useActiveColor: false
    foreground: root.dropBlasting ? root.ink : "transparent"
    tooltipText: "OmaSend · " + root.tf("tooltip_devices", root.onlineCount, root.pairedDevices.length)
    onPressed: function(b) {
      if (b === Qt.RightButton) root.forceScan()
      else root.toggle()
    }

    OmaLogo {
      anchors.centerIn: parent
      visible: !root.dropBlasting
      size: Math.round(Math.min(parent.width, parent.height) * 0.66)
      color: root.dropActive ? root.ink : (root.bar ? root.bar.foreground : Color.foreground)
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
    borderColor: (root.dropProximity > 0.72 || root.dropBlasting) ? root.ink : Color.popups.border
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
            strokeColor: root.ink
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
          visible: root.dropBlasting
          textFormat: Text.PlainText
          text: "󰄬"
          color: root.ink
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }
        OmaLogo {
          anchors.centerIn: parent
          visible: !root.dropBlasting
          size: Style.space(20)
          color: root.ink
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
          color: root.ink
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
  // Quick Share simplicity, Mullvad-style clarity about what is encrypted:
  // one security line, your devices as tiles, everything else tucked away.
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
      onMoveRequested: function(dx, dy) { root.moveCursor(dx + dy * root.tileColumns) }
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
        else if (key === "n" || key === "N") root.showNearby = !root.showNearby
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

          readonly property real tileWidth: Math.floor((width - Style.space(6) * (root.tileColumns - 1)) / root.tileColumns)

          // ---------------------------------------------------------------
          // HEADER: logo, name, on/off
          // ---------------------------------------------------------------
          Item {
            width: parent.width
            implicitHeight: Math.max(heroLogo.height, heroLabels.implicitHeight, powerSwitch.implicitHeight)

            OmaLogo {
              id: heroLogo
              size: Style.space(30)
              color: root.serviceOn ? root.foreground : root.dim
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            ToggleSwitch {
              id: powerSwitch
              checked: root.serviceOn
              foreground: root.foreground
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              onToggled: root.toggleService()

              PanelToolTip {
                visible: powerSwitch.containsMouse
                text: root.serviceOn ? root.t("turn_off_service") : root.t("turn_on_service")
                fontFamily: root.fontFamily
              }
            }

            Column {
              id: heroLabels
              anchors.left: heroLogo.right
              anchors.leftMargin: Style.space(12)
              anchors.right: powerSwitch.left
              anchors.rightMargin: Style.space(12)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: "OmaSend"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
              }
              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.hostname + " · " + (root.serviceOn ? root.t("visible_to_your_devices") : root.t("hidden_short"))
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }
            }
          }

          // ---------------------------------------------------------------
          // SECURITY STATE (one line, always visible)
          // ---------------------------------------------------------------
          BorderSurface {
            width: parent.width
            implicitHeight: secRow.implicitHeight + Style.space(16)
            color: Style.normalFillFor(root.foreground, root.securityColor)
            borderSpec: Border.controlSpec("normal", root.foreground, root.securityColor)
            radius: Style.cornerRadius

            RowLayout {
              id: secRow
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(12)
              spacing: Style.space(10)

              Text {
                textFormat: Text.PlainText
                text: root.securityState === "secure" ? "󰌾" : (root.securityState === "blocked" ? "󰒃" : "󰌿")
                color: root.securityColor
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                Layout.alignment: Qt.AlignVCenter
              }
              ColumnLayout {
                Layout.fillWidth: true
                spacing: Style.space(1)

                Text {
                  Layout.fillWidth: true
                  textFormat: Text.PlainText
                  text: root.t("security_" + root.securityState + "_title")
                  color: root.securityColor
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1.2
                  elide: Text.ElideRight
                }
                Text {
                  Layout.fillWidth: true
                  textFormat: Text.PlainText
                  text: root.securityState === "secure"
                        ? (root.pairedDevices.length > 0
                           ? root.tf("security_secure_sub", root.onlineCount, root.pairedDevices.length)
                           : root.t("security_secure_sub_empty"))
                        : (root.securityState === "blocked" ? root.t("firewall_warning_label") : root.t("security_off_sub"))
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                }
              }
            }
          }

          // ---------------------------------------------------------------
          // INCOMING TRANSFER (needs a decision)
          // ---------------------------------------------------------------
          BorderSurface {
            id: incomingCard
            readonly property bool encrypted: root.pendingTransfer !== null && root.pendingTransfer.transport === "quic"
            readonly property color tone: encrypted ? root.ink : root.urgent
            visible: root.pendingTransfer !== null && root.pendingTransfer.status === "PENDING"
            width: parent.width
            implicitHeight: inCol.implicitHeight + Style.space(20)
            color: Style.normalFillFor(root.foreground, incomingCard.tone)
            borderSpec: Border.controlSpec("normal", root.foreground, incomingCard.tone)
            radius: Style.cornerRadius

            ColumnLayout {
              id: inCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(12)
              spacing: Style.space(6)

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: root.tf("incoming_wants_to_share", root.pendingTransfer ? String(root.pendingTransfer.sender_name || "") : "")
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
                elide: Text.ElideRight
              }
              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: root.pendingTransfer ? (root.pendingTransfer.file_names || []).join(", ") : ""
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                maximumLineCount: 2
                wrapMode: Text.WrapAnywhere
                elide: Text.ElideRight
              }
              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                text: incomingCard.encrypted ? ("󰌾 " + root.t("incoming_encrypted")) : ("󰌿 " + root.t("incoming_not_encrypted"))
                color: incomingCard.tone
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: !incomingCard.encrypted
                wrapMode: Text.WordWrap
              }
              RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: Style.space(2)
                spacing: Style.space(8)

                Item { Layout.fillWidth: true }
                Button {
                  text: root.t("reject_btn")
                  fontSize: Style.font.bodySmall
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  horizontalPadding: Style.space(14)
                  verticalPadding: Style.spacing.controlPaddingY
                  bordered: true
                  onClicked: if (root.pendingTransfer) root.rejectTransfer(root.pendingTransfer.token)
                }
                Button {
                  text: root.t("accept_btn")
                  fontSize: Style.font.bodySmall
                  foreground: root.ink
                  fontFamily: root.fontFamily
                  horizontalPadding: Style.space(14)
                  verticalPadding: Style.spacing.controlPaddingY
                  bordered: true
                  active: true
                  onClicked: if (root.pendingTransfer) root.acceptTransfer(root.pendingTransfer.token)
                }
              }
            }
          }

          // ---------------------------------------------------------------
          // ACTIVE TRANSFER
          // ---------------------------------------------------------------
          BorderSurface {
            visible: root.transferProgress !== null
            width: parent.width
            implicitHeight: progressCol.implicitHeight + Style.space(18)
            color: Style.normalFillFor(root.foreground, root.ink)
            borderSpec: Border.controlSpec("normal", root.foreground, root.ink)
            radius: Style.cornerRadius

            ColumnLayout {
              id: progressCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(8)
              spacing: Style.space(6)

              RowLayout {
                Layout.fillWidth: true
                spacing: Style.space(8)

                Text {
                  textFormat: Text.PlainText
                  text: (root.transferProgress && String(root.transferProgress.direction || "").indexOf("send") === 0) ? "󰕒" : "󰇚"
                  color: root.ink
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                Text {
                  Layout.fillWidth: true
                  textFormat: Text.PlainText
                  text: root.transferProgress ? String(root.transferProgress.file_name || "") : ""
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                  elide: Text.ElideMiddle
                }
                Text {
                  textFormat: Text.PlainText
                  text: root.transferProgress ? (Number(root.transferProgress.percent || 0) + "%") : ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
                PanelActionButton {
                  iconText: "󰅖"
                  tooltipText: root.t("cancel_btn")
                  foreground: root.dim
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
                  color: root.ink
                }
              }
            }
          }

          // ---------------------------------------------------------------
          // PAIRING CARD
          // ---------------------------------------------------------------
          BorderSurface {
            visible: root.showPair
            width: parent.width
            implicitHeight: pairCol.implicitHeight + Style.space(20)
            color: Style.normalFillFor(root.foreground, root.ink)
            borderSpec: Border.controlSpec("normal", root.foreground, root.ink)
            radius: Style.cornerRadius

            Column {
              id: pairCol
              anchors.centerIn: parent
              width: parent.width - Style.space(20)
              spacing: Style.space(8)

              RowLayout {
                width: parent.width

                Text {
                  Layout.fillWidth: true
                  textFormat: Text.PlainText
                  text: root.t("pair_title")
                  color: root.ink
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1.0
                }
                PanelActionButton {
                  iconText: "󰅖"
                  tooltipText: root.t("close_btn")
                  foreground: root.dim
                  fontFamily: root.fontFamily
                  onClicked: root.showPair = false
                }
              }

              RowLayout {
                visible: root.linkSupported || root.webSupported
                width: parent.width
                spacing: Style.space(6)

                ScopePill {
                  label: root.t("pair_mode_qr")
                  activeWhen: root.pairMode === "qr"
                  onClicked: { if (root.pairMode !== "qr") { var wasWeb = root.pairMode === "web"; root.pairMode = "qr"; if (wasWeb || !root.pairQrPath) root.newPairOffer() } }
                }
                ScopePill {
                  visible: root.webSupported
                  label: root.t("pair_mode_web")
                  activeWhen: root.pairMode === "web"
                  onClicked: { if (root.pairMode !== "web") { root.pairMode = "web"; root.newPairOffer() } }
                }
                ScopePill {
                  visible: root.linkSupported
                  label: root.t("pair_mode_omaid")
                  activeWhen: root.pairMode === "omaid"
                  onClicked: root.pairMode = "omaid"
                }
                Item { Layout.fillWidth: true }
              }

              Column {
                visible: root.pairMode === "qr" || root.pairMode === "web"
                width: parent.width
                spacing: Style.space(8)

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
                  text: root.pairMode === "web" ? root.t("web_pair_instructions") : root.t("pair_instructions")
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
                  visible: root.pairMode === "web" && root.pairWebUrl !== ""
                  width: parent.width
                  spacing: Style.space(4)

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.pairWebUrl
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                  }
                  PanelActionButton {
                    iconText: "󰆏"
                    tooltipText: root.t("web_link_copy_tooltip")
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: { root.copyText(root.pairWebUrl); root.setStatus(root.t("web_link_copied"), false) }
                  }
                }

                Text {
                  visible: root.pairMode === "web" && !root.pairWebInstalled
                  width: parent.width
                  textFormat: Text.PlainText
                  text: root.t("web_not_installed")
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  wrapMode: Text.WordWrap
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
                    visible: root.pairMode === "qr"
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
              }

              // Link your own devices by typing the account OmaID (SPAKE2; the number itself is never sent).
              Column {
                visible: root.pairMode === "omaid"
                width: parent.width
                spacing: Style.space(8)

                Text {
                  width: parent.width
                  textFormat: Text.PlainText
                  text: root.t("account_number_label")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1.0
                }

                RowLayout {
                  width: parent.width
                  spacing: Style.space(4)

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.accountId === "" ? "…" : root.formatAccountId(root.accountId, !root.showAccountId)
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    font.bold: true
                    font.letterSpacing: 1.0
                    elide: Text.ElideRight
                  }
                  PanelActionButton {
                    iconText: root.showAccountId ? "󰈉" : "󰈈"
                    tooltipText: root.showAccountId ? root.t("account_hide_tooltip") : root.t("account_show_tooltip")
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.showAccountId = !root.showAccountId
                  }
                  PanelActionButton {
                    iconText: "󰆏"
                    tooltipText: root.t("account_copy_tooltip")
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: if (root.accountId) { root.copyText(root.accountId); root.setStatus(root.t("account_copied"), false) }
                  }
                }

                Text {
                  width: parent.width
                  textFormat: Text.PlainText
                  text: root.t("link_instructions")
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                }

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)

                  BorderSurface {
                    Layout.fillWidth: true
                    implicitHeight: linkInput.implicitHeight + Style.space(12)
                    color: "transparent"
                    borderSpec: Border.controlSpec("normal", root.foreground, linkInput.activeFocus ? root.ink : root.foreground)
                    radius: Style.cornerRadius

                    TextInput {
                      id: linkInput
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.leftMargin: Style.space(8)
                      anchors.rightMargin: Style.space(8)
                      color: root.foreground
                      selectionColor: root.ink
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.letterSpacing: 1.0
                      maximumLength: 24
                      inputMethodHints: Qt.ImhDigitsOnly
                      validator: RegularExpressionValidator { regularExpression: /[0-9 -]*/ }
                      clip: true
                      enabled: !linkProc.running
                      onAccepted: root.linkWithOmaId(text)
                      Keys.onEscapePressed: keyCatcher.forceActiveFocus()

                      Text {
                        anchors.fill: parent
                        visible: linkInput.text === "" && !linkInput.activeFocus
                        textFormat: Text.PlainText
                        text: "0000 0000 0000 0000"
                        color: root.dim
                        font: linkInput.font
                      }
                    }
                  }
                  Button {
                    text: linkProc.running ? root.t("link_working") : root.t("link_btn")
                    fontSize: Style.font.bodySmall
                    foreground: root.ink
                    fontFamily: root.fontFamily
                    horizontalPadding: Style.space(12)
                    verticalPadding: Style.spacing.controlPaddingY
                    bordered: true
                    active: root.omaIdValid(linkInput.text) && !linkProc.running
                    onClicked: root.linkWithOmaId(linkInput.text)
                  }
                }

                Text {
                  width: parent.width
                  textFormat: Text.PlainText
                  text: root.t("link_hint")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                }
              }

              // Confirmation for a pairing QR found on screen.
              Text {
                visible: root.scannedPairUri !== ""
                width: parent.width
                textFormat: Text.PlainText
                text: root.tf("pair_scan_confirm", root.scannedPairName, root.scannedPairId)
                color: root.ink
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
                  foreground: root.ink
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
            text: (root.statusError ? "󰀦 " : "") + root.statusMsg
            color: root.ink
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: root.statusError
            wrapMode: Text.WordWrap
          }

          // ---------------------------------------------------------------
          // SEND TO: paired devices as tiles, plus "Add device"
          // ---------------------------------------------------------------
          Column {
            width: parent.width
            spacing: Style.space(8)

            PanelSectionHeader {
              text: root.t("send_to_header")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Flow {
              width: parent.width
              spacing: Style.space(6)

              Repeater {
                model: root.pairedDevices

                DeviceTile {
                  required property var modelData
                  required property int index
                  width: column.tileWidth
                  rowIndex: index
                  kind: "paired"
                  name: String(modelData.name || "")
                  address: String(modelData.device_id || "")
                  online: Boolean(modelData.online)
                  own: Boolean(modelData.own_device)
                  detail: String(modelData.ip || "") + " · " + root.shortId(modelData.device_id)
                }
              }

              AddTile { width: column.tileWidth }
            }

            Text {
              width: parent.width
              textFormat: Text.PlainText
              text: root.pairedDevices.length === 0
                    ? root.t("send_empty_hint")
                    : (root.defaultTarget ? root.tf("send_hint_default", root.defaultTarget.name) : root.t("send_hint"))
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // ---------------------------------------------------------------
          // NEARBY (not paired, not encrypted): collapsed by default
          // ---------------------------------------------------------------
          Column {
            visible: root.serviceOn && root.nearbyAll.length > 0
            width: parent.width
            spacing: Style.space(8)

            Disclosure {
              width: parent.width
              label: root.tf("nearby_unencrypted_header", root.nearbyAll.length)
              expanded: root.showNearby
              tone: root.urgent
              onToggled: root.showNearby = !root.showNearby
            }

            Flow {
              visible: root.showNearby
              width: parent.width
              spacing: Style.space(6)

              Repeater {
                model: root.nearby

                DeviceTile {
                  required property var modelData
                  required property int index
                  width: column.tileWidth
                  rowIndex: root.pairedDevices.length + index
                  kind: "nearby"
                  name: String(modelData.name || "")
                  address: String(modelData.ip || "")
                  online: true
                  own: false
                  detail: String(modelData.ip || "")
                }
              }
            }

            Text {
              visible: root.showNearby
              width: parent.width
              textFormat: Text.PlainText
              text: root.t("nearby_footnote")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // ---------------------------------------------------------------
          // DETAILS (device key, address, counters): collapsed by default
          // ---------------------------------------------------------------
          Column {
            width: parent.width
            spacing: Style.space(8)

            Disclosure {
              width: parent.width
              label: root.t("details_header")
              expanded: root.showDetails
              tone: root.foreground
              onToggled: root.showDetails = !root.showDetails
            }

            GridLayout {
              visible: root.showDetails
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
  // OmaSend mark from the brand guide (assets/omasend-symbolic.svg): the send arrow breaking out of the Omarchy frame (option B).
  // One color, so it follows the bar theme.
  component OmaLogo: Item {
    id: logo
    property color color: root.foreground
    property real size: Style.space(16)
    width: size
    height: size
    implicitWidth: size
    implicitHeight: size

    Shape {
      width: 300
      height: 300
      scale: logo.size / 300
      transformOrigin: Item.TopLeft
      preferredRendererType: Shape.CurveRenderer

      ShapePath {
        fillColor: logo.color
        strokeColor: "transparent"
        strokeWidth: 0
        PathSvg { path: "M0 0h180v20h-180zM200 0h100v20h-100zM0 20h20v20h-20zM140 20h20v20h-20zM240 20h60v20h-60zM0 40h20v20h-20zM40 40h120v20h-120zM220 40h40v20h-40zM280 40h20v20h-20zM0 60h20v20h-20zM40 60h20v20h-20zM200 60h40v20h-40zM280 60h20v20h-20zM0 80h20v20h-20zM40 80h20v20h-20zM180 80h40v20h-40zM0 100h20v20h-20zM40 100h20v20h-20zM160 100h40v20h-40zM240 100h20v20h-20zM280 100h20v20h-20zM0 120h20v20h-20zM40 120h20v20h-20zM160 120h20v20h-20zM240 120h20v20h-20zM280 120h20v20h-20zM0 140h60v20h-60zM240 140h20v20h-20zM280 140h20v20h-20zM0 160h20v20h-20zM40 160h20v20h-20zM240 160h20v20h-20zM280 160h20v20h-20zM0 180h20v20h-20zM40 180h20v20h-20zM240 180h20v20h-20zM280 180h20v20h-20zM0 200h20v20h-20zM40 200h20v20h-20zM240 200h20v20h-20zM280 200h20v20h-20zM0 220h20v20h-20zM40 220h20v20h-20zM240 220h20v20h-20zM280 220h20v20h-20zM0 240h20v20h-20zM40 240h220v20h-220zM280 240h20v20h-20zM0 260h20v20h-20zM140 260h20v20h-20zM280 260h20v20h-20zM0 280h160v20h-160zM180 280h120v20h-120z" }
      }
    }
  }

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

  // Collapsible section header ("Nearby", "Details").
  component Disclosure: Item {
    id: disc
    property string label: ""
    property bool expanded: false
    property color tone: root.foreground
    signal toggled()
    implicitHeight: discRow.implicitHeight + Style.space(4)

    MouseArea {
      anchors.fill: parent
      cursorShape: Qt.PointingHandCursor
      onClicked: disc.toggled()
    }

    RowLayout {
      id: discRow
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(6)

      Text {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        text: disc.label
        color: Qt.rgba(disc.tone.r, disc.tone.g, disc.tone.b, 0.75)
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1.0
        elide: Text.ElideRight
      }
      Text {
        textFormat: Text.PlainText
        text: disc.expanded ? "󰅀" : "󰅂"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }
    }
  }

  // One device, Quick Share style: click to pick files, right-click sends the clipboard.
  component DeviceTile: Item {
    id: tile
    required property int rowIndex
    property string kind: "nearby"
    property string name: ""
    property string address: ""
    property string detail: ""
    property bool online: false
    property bool own: false
    readonly property bool paired: kind === "paired"
    readonly property bool armed: paired && root.armedUnpair === address
    readonly property bool hasCursor: root.cursorActive && root.selectedIndex === rowIndex
    readonly property bool hot: tileHover.hovered || hasCursor

    implicitHeight: tileCol.implicitHeight + Style.space(14)

    Rectangle {
      anchors.fill: parent
      radius: Style.cornerRadius
      color: tile.hasCursor ? root.selectedFill : (tileHover.hovered ? root.hoverFill : "transparent")
    }

    HoverHandler {
      id: tileHover
      cursorShape: Qt.PointingHandCursor
      onHoveredChanged: if (hovered) { root.cursorActive = true; root.selectedIndex = tile.rowIndex }
    }

    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.LeftButton | Qt.RightButton
      onClicked: function(mouse) {
        if (!tile.address) return
        if (mouse.button === Qt.RightButton) root.syncClipboardTo(tile.address)
        else root.sendFileTo(tile.address)
      }
    }

    PanelToolTip {
      visible: tileHover.hovered && tile.detail !== ""
      text: tile.detail
      fontFamily: root.fontFamily
    }

    Column {
      id: tileCol
      anchors.top: parent.top
      anchors.topMargin: Style.space(8)
      anchors.horizontalCenter: parent.horizontalCenter
      width: parent.width - Style.space(8)
      spacing: Style.space(4)

      Item {
        anchors.horizontalCenter: parent.horizontalCenter
        width: Style.space(44)
        height: Style.space(44)

        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, tile.online ? 0.10 : 0.04)
          border.width: Math.max(1, Style.space(1.5))
          border.color: tile.armed ? root.urgent
                       : (tile.paired && tile.online ? root.ink
                       : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.18))
        }
        Text {
          anchors.centerIn: parent
          textFormat: Text.PlainText
          text: /android|phone|pixel|galaxy|sdk_gphone|samsung|xiaomi/i.test(tile.name) ? "󰏲" : "󰌢"
          color: tile.online ? root.foreground : root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.title
        }
      }

      Text {
        width: parent.width
        textFormat: Text.PlainText
        text: tile.name
        color: tile.online ? root.foreground : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        font.bold: tile.paired && tile.online
        horizontalAlignment: Text.AlignHCenter
        elide: Text.ElideRight
      }
      Text {
        width: parent.width
        textFormat: Text.PlainText
        text: tile.armed ? root.t("tile_unpair_armed")
              : (tile.paired ? ("󰌾 " + (tile.online ? (tile.own ? root.t("badge_own_short") : root.t("online")) : root.t("not_seen")))
                             : ("󰌿 " + root.t("not_encrypted")))
        color: tile.armed ? root.urgent : (tile.paired ? (tile.online ? root.ink : root.dim) : root.urgent)
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        horizontalAlignment: Text.AlignHCenter
        elide: Text.ElideRight
      }
    }

    // Per-device actions appear on hover only.
    PanelActionButton {
      visible: tile.paired && (tile.hot || tile.armed)
      anchors.top: parent.top
      anchors.left: parent.left
      iconText: "󰅍"
      tooltipText: root.t("send_clipboard_tooltip")
      foreground: root.dim
      fontFamily: root.fontFamily
      onClicked: root.syncClipboardTo(tile.address)
    }
    PanelActionButton {
      visible: tile.paired && (tile.hot || tile.armed)
      anchors.top: parent.top
      anchors.right: parent.right
      iconText: "󰅖"
      tooltipText: tile.armed ? root.t("unpair_confirm_tooltip") : root.t("unpair_tooltip")
      foreground: tile.armed ? root.urgent : root.dim
      hoverColor: root.urgent
      bordered: tile.armed
      fontFamily: root.fontFamily
      onClicked: root.requestUnpair(tile.address)
    }
  }

  // "Add device": opens the QR pairing card.
  component AddTile: Item {
    id: addTile
    implicitHeight: addCol.implicitHeight + Style.space(14)

    Rectangle {
      anchors.fill: parent
      radius: Style.cornerRadius
      color: addHover.hovered || root.showPair ? root.hoverFill : "transparent"
    }

    HoverHandler { id: addHover; cursorShape: Qt.PointingHandCursor }

    MouseArea {
      anchors.fill: parent
      onClicked: { if (root.showPair) root.showPair = false; else root.openPairing() }
    }

    Column {
      id: addCol
      anchors.top: parent.top
      anchors.topMargin: Style.space(8)
      anchors.horizontalCenter: parent.horizontalCenter
      width: parent.width - Style.space(8)
      spacing: Style.space(4)

      Item {
        anchors.horizontalCenter: parent.horizontalCenter
        width: Style.space(44)
        height: Style.space(44)

        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: "transparent"
          border.width: Math.max(1, Style.space(1.5))
          border.color: root.showPair ? root.ink : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.28)
        }
        Text {
          anchors.centerIn: parent
          textFormat: Text.PlainText
          text: "󰐕"
          color: root.showPair ? root.ink : root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.title
        }
      }

      Text {
        width: parent.width
        textFormat: Text.PlainText
        text: root.t("add_device")
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        horizontalAlignment: Text.AlignHCenter
        elide: Text.ElideRight
      }
      Text {
        width: parent.width
        textFormat: Text.PlainText
        text: "󰐲 " + root.t("add_device_sub")
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        horizontalAlignment: Text.AlignHCenter
        elide: Text.ElideRight
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
