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
  property string savePath: "~/Downloads/omasend"
  property string qrPath: ""
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

  function copyPortalUrl() {
    copyProc.command = ["wl-copy", "http://" + root.localIp + ":" + root.port + "/?pin=" + root.pin]
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
          root.savePath = String(d.download_dir || "~/Downloads/omasend")
          root.qrPath = String(d.qr_path || "")
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
    tooltipText: "OmaSend AirBridge"
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
    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(620))

    ScrollView {
      id: scrollArea
      anchors.fill: parent
      clip: true
      ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
      ScrollBar.vertical.policy: panelColumn.implicitHeight > height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff

      Column {
        id: panelColumn
        width: scrollArea.availableWidth
        spacing: Style.space(14)

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

            Text {
              text: "OmaSend"
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.title
              font.bold: true
              elide: Text.ElideRight
              width: parent.width
            }

            Text {
              textFormat: Text.PlainText
              text: ("AIRBRIDGE TRANSFER • " + root.localIp).toUpperCase()
              color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.2
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
            text: "CONNECT VIA QR"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          // Crisp QR Card
          Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            width: Style.space(150)
            height: Style.space(150)
            radius: Style.space(8)
            color: "#ffffff"
            border.color: root.bar ? root.bar.foreground : Color.foreground
            border.width: 1

            Image {
              anchors.fill: parent
              anchors.margins: Style.space(8)
              source: root.qrPath ? ("file://" + root.qrPath + "?v=" + root.refreshNonce) : ""
              sourceSize.width: Style.space(134)
              sourceSize.height: Style.space(134)
              fillMode: Image.PreserveAspectFit
              cache: false
            }
          }

          // Portal URL row
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
                text: "http://" + root.localIp + ":" + root.port
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                elide: Text.ElideMiddle
              }

              Button {
                text: "Copy URL"
                onClicked: root.copyPortalUrl()
              }
            }
          }

          // Security PIN Pill
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
                text: "SECURITY PIN: " + root.pin
                color: root.bar ? root.bar.foreground : Color.foreground
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }

              Item { Layout.fillWidth: true }

              Text {
                textFormat: Text.PlainText
                text: "Auto-authorized via QR"
                color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
              }
            }
          }
        }

        // ---------- Transfer Path Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "INCOMING DOWNLOADS"
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
                text: "Open Folder"
                onClicked: root.openFolder()
              }
            }
          }
        }

        // ---------- Actions Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "ACTIONS"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            Button {
              Layout.fillWidth: true
              text: "New PIN"
              onClicked: root.newPin()
            }

            Button {
              Layout.fillWidth: true
              text: "Refresh"
              onClicked: root.refresh()
            }
          }
        }
      }
    }
  }
}
