import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "ozdil.omasend"
  ipcTarget: "ozdil.omasend"

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰐳 omasend"
    slotSize: Style.bar.statusSlot
    tooltipText: "omasend: Wireless AirBridge & Clipboard Sharing"
    onPressed: root.toggle()
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    width: 440
    contentHeight: panel.fittedContentHeight(mainCol.implicitHeight)

    Column {
      id: mainCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(12)

      Text {
        text: "🚀 omasend Hava Köprüsü"
        font.pixelSize: Style.font.title
        font.bold: true
        color: root.bar ? root.bar.foreground : "#ffffff"
      }

      Text {
        text: "QR kod ile iPhone/Android ve bilgisayarınız arasında sıfır kurulumla çift yönlü dosya ve pano (clipboard) aktarın."
        font.pixelSize: Style.font.body
        color: "#94a3b8"
        wrapMode: Text.WordWrap
        width: parent.width
      }

      RowLayout {
        width: parent.width
        spacing: 8

        Button {
          Layout.fillWidth: true
          text: "📱 Dosya Al / Gönder"
          onClicked: {
            root.close()
            if (root.bar) root.bar.run("omarchy-launch-floating-terminal-with-presentation $HOME/.config/omarchy/plugins/omasend/omasend-dashboard")
          }
        }

        Button {
          Layout.fillWidth: true
          text: "📋 Panoyu Telefona Paylaş"
          onClicked: {
            root.close()
            if (root.bar) root.bar.run("omarchy-launch-floating-terminal-with-presentation bash -c '$HOME/.config/omarchy/plugins/omasend/omasend-dashboard <<< 3'")
          }
        }
      }
    }
  }
}
