import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import "theme"

Rectangle {
    id: root
    color: Theme.bgBase

    property string localIp: "127.0.0.1"
    property int port: 53317
    property string pin: "----"
    property string sessionKey: ""
    property string activeMode: "LAN"
    property string visibility: "KNOWN"
    property int visibilityRemainingSecs: 0
    property string qrPath: ""
    property var peers: []
    property var recentFiles: []
    property bool isRefreshing: false

    function resolveEnginePath() {
        return Qt.resolvedUrl("../omasend-engine").toString().replace(/^file:\/\//, "")
    }

    function refreshStatus() {
        if (!statusProc.running) {
            isRefreshing = true;
            statusProc.running = true;
        }
    }

    Timer {
        interval: 3000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: root.refreshStatus()
    }

    Process {
        id: statusProc
        command: [root.resolveEnginePath(), "status", "--json"]
        stdout: StdioCollector {
            onDataChanged: {
                root.isRefreshing = false;
                if (!data || data.trim().length === 0) return;
                try {
                    var s = JSON.parse(data);
                    if (s.local_ip) root.localIp = s.local_ip;
                    if (s.port) root.port = s.port;
                    if (s.pin) root.pin = s.pin;
                    if (s.session_key) root.sessionKey = s.session_key;
                    if (s.active_mode) root.activeMode = s.active_mode;
                    if (s.p2p_visibility) root.visibility = s.p2p_visibility;
                    if (s.p2p_visibility_remaining_secs !== undefined) root.visibilityRemainingSecs = s.p2p_visibility_remaining_secs;
                    if (s.p2p_peers) root.peers = s.p2p_peers;
                    if (s.recent_files) root.recentFiles = s.recent_files;
                } catch(e) {}
            }
        }
    }

    Process {
        id: actionProc
        onExited: {
            root.refreshStatus();
        }
    }

    function runEngineAction(args) {
        if (actionProc.running) actionProc.running = false;
        actionProc.command = [root.resolveEnginePath()].concat(args);
        actionProc.running = true;
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 16

        // Top Navigation & Zero-Trust Bar
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            // App Identity
            Rectangle {
                width: 38
                height: 38
                radius: Theme.radiusMd
                color: Theme.bgCard
                border.color: Theme.border

                Text {
                    anchors.centerIn: parent
                    text: Theme.iconAirBridge
                    font.family: Theme.iconFont
                    font.pixelSize: 18
                    color: Theme.accent
                }
            }

            ColumnLayout {
                spacing: 2
                Text {
                    text: "OmaSend AirBridge"
                    font.family: Theme.fontFamily
                    font.pixelSize: 16
                    font.bold: true
                    color: Theme.textMain
                }
                Text {
                    text: "Zero-Trust LAN/BT Wireless Transfer & Cryptographic Verification"
                    font.family: Theme.fontFamily
                    font.pixelSize: 11
                    color: Theme.textMuted
                }
            }

            Item { Layout.fillWidth: true }

            // Cryptographic Integrity Badge
            Rectangle {
                height: 28
                implicitWidth: integrityRow.implicitWidth + 16
                radius: Theme.radiusSm
                color: Theme.bgCard
                border.color: Theme.borderLight

                RowLayout {
                    id: integrityRow
                    anchors.centerIn: parent
                    spacing: 6

                    Text {
                        text: Theme.iconShield
                        font.family: Theme.iconFont
                        font.pixelSize: 12
                        color: Theme.accentSuccess
                    }
                    Text {
                        text: "SHA-256 + MD5 INTEGRITY"
                        font.family: Theme.fontFamily
                        font.pixelSize: 10
                        font.bold: true
                        color: Theme.accentSuccess
                    }
                }
            }

            // Visibility Mode Pill
            Rectangle {
                height: 28
                implicitWidth: visRow.implicitWidth + 16
                radius: Theme.radiusSm
                color: Theme.bgCard
                border.color: Theme.border

                RowLayout {
                    id: visRow
                    anchors.centerIn: parent
                    spacing: 6

                    Text {
                        text: Theme.iconRadar
                        font.family: Theme.iconFont
                        font.pixelSize: 12
                        color: root.visibility === "OFF" ? Theme.textDim : Theme.accent
                    }
                    Text {
                        text: "MODE: " + root.visibility + (root.visibilityRemainingSecs > 0 ? " (" + root.visibilityRemainingSecs + "s)" : "")
                        font.family: Theme.fontFamily
                        font.pixelSize: 10
                        font.bold: true
                        color: Theme.textMain
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        var nextMode = root.visibility === "KNOWN" ? "EVERYONE" : (root.visibility === "EVERYONE" ? "OFF" : "KNOWN");
                        root.runEngineAction(["visibility", nextMode.toLowerCase()]);
                    }
                }
            }

            // Refresh Button
            Rectangle {
                width: 28
                height: 28
                radius: Theme.radiusSm
                color: refreshMouse.containsMouse ? Theme.bgCardHover : Theme.bgCard
                border.color: Theme.border

                Text {
                    anchors.centerIn: parent
                    text: Theme.iconRefresh
                    font.family: Theme.iconFont
                    font.pixelSize: 12
                    color: root.isRefreshing ? Theme.accent : Theme.textMuted
                    rotation: root.isRefreshing ? 180 : 0
                    Behavior on rotation { NumberAnimation { duration: 400 } }
                }

                MouseArea {
                    id: refreshMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.refreshStatus()
                }
            }
        }

        // Horizontal Divider
        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: Theme.border
        }

        // Two-Column Work Area
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 16

            // Left Column: Discovered Radar Devices
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 55
                radius: Theme.radiusMd
                color: Theme.bgCard
                border.color: Theme.border

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 12

                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                            text: "NEARBY AIRBRIDGE RADAR"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMuted
                        }
                        Item { Layout.fillWidth: true }
                        Text {
                            text: root.peers.length + " PEER(S) DETECTED"
                            font.family: Theme.fontFamily
                            font.pixelSize: 10
                            color: Theme.accent
                        }
                    }

                    // Peer List
                    ListView {
                        id: peerList
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 8
                        model: root.peers

                        delegate: Rectangle {
                            width: peerList.width
                            height: 64
                            radius: Theme.radiusSm
                            color: pMouse.containsMouse ? Theme.bgCardHover : Theme.bgSurface
                            border.color: Theme.border

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 12

                                Rectangle {
                                    width: 36
                                    height: 36
                                    radius: Theme.radiusSm
                                    color: Theme.bgBase
                                    border.color: Theme.border

                                    Text {
                                        anchors.centerIn: parent
                                        text: (modelData.transport === "BT" || (modelData.name && modelData.name.toLowerCase().indexOf("phone") !== -1)) ? Theme.iconMobile : Theme.iconDesktop
                                        font.family: Theme.iconFont
                                        font.pixelSize: 16
                                        color: modelData.is_trusted ? Theme.accentSuccess : Theme.accent
                                    }
                                }

                                ColumnLayout {
                                    spacing: 2
                                    Layout.fillWidth: true

                                    RowLayout {
                                        spacing: 6
                                        Text {
                                            text: modelData.name || "Unknown Device"
                                            font.family: Theme.fontFamily
                                            font.pixelSize: 13
                                            font.bold: true
                                            color: Theme.textMain
                                            elide: Text.ElideRight
                                        }
                                        if (modelData.is_trusted) {
                                            Text {
                                                text: "[TRUSTED]"
                                                font.family: Theme.fontFamily
                                                font.pixelSize: 9
                                                font.bold: true
                                                color: Theme.accentSuccess
                                            }
                                        }
                                    }

                                    Text {
                                        text: modelData.ip + " | Transport: " + (modelData.transport || "LAN")
                                        font.family: Theme.monoFont
                                        font.pixelSize: 10
                                        color: Theme.textMuted
                                    }
                                }

                                // Send File Button
                                Rectangle {
                                    height: 30
                                    implicitWidth: sendBtnRow.implicitWidth + 16
                                    radius: Theme.radiusSm
                                    color: Theme.bgDark
                                    border.color: Theme.accent

                                    RowLayout {
                                        id: sendBtnRow
                                        anchors.centerIn: parent
                                        spacing: 6

                                        Text {
                                            text: Theme.iconSend
                                            font.family: Theme.iconFont
                                            font.pixelSize: 11
                                            color: Theme.accent
                                        }
                                        Text {
                                            text: "SEND"
                                            font.family: Theme.fontFamily
                                            font.pixelSize: 10
                                            font.bold: true
                                            color: Theme.accent
                                        }
                                    }

                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: {
                                            root.runEngineAction(["send-prompt", modelData.ip]);
                                        }
                                    }
                                }
                            }

                            MouseArea {
                                id: pMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                z: -1
                            }
                        }

                        // Empty State
                        Item {
                            anchors.centerIn: parent
                            visible: root.peers.length === 0

                            ColumnLayout {
                                anchors.centerIn: parent
                                spacing: 8

                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: Theme.iconRadar
                                    font.family: Theme.iconFont
                                    font.pixelSize: 32
                                    color: Theme.textDim
                                }
                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "Listening for AirBridge Beacons..."
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 12
                                    color: Theme.textMuted
                                }
                                Text {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "Open OmaSend on your Android device or another Omarchy PC"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 10
                                    color: Theme.textDim
                                }
                            }
                        }
                    }
                }
            }

            // Right Column: QR Share & Activity Log
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 45
                spacing: 16

                // Web & QR Quick Share Box
                Rectangle {
                    Layout.fillWidth: true
                    height: 220
                    radius: Theme.radiusMd
                    color: Theme.bgCard
                    border.color: Theme.border

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 10

                        Text {
                            text: "WEB & QR INSTANT SHARE"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMuted
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 16

                            // Server Coordinates
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 6

                                Text {
                                    text: "Endpoint: http://" + root.localIp + ":" + root.port
                                    font.family: Theme.monoFont
                                    font.pixelSize: 11
                                    color: Theme.textMain
                                }

                                RowLayout {
                                    spacing: 8
                                    Text {
                                        text: "Zero-Trust PIN:"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: Theme.textMuted
                                    }
                                    Rectangle {
                                        height: 24
                                        implicitWidth: 70
                                        radius: Theme.radiusSm
                                        color: Theme.bgDark
                                        border.color: Theme.borderLight

                                        Text {
                                            anchors.centerIn: parent
                                            text: root.pin
                                            font.family: Theme.monoFont
                                            font.pixelSize: 12
                                            font.bold: true
                                            color: Theme.accent
                                        }
                                    }
                                }

                                Text {
                                    text: "Any browser on local Wi-Fi can upload or download securely."
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 10
                                    color: Theme.textDim
                                    wrapMode: Text.WordWrap
                                    Layout.fillWidth: true
                                }
                            }
                        }

                        Item { Layout.fillHeight: true }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Rectangle {
                                Layout.fillWidth: true
                                height: 32
                                radius: Theme.radiusSm
                                color: Theme.bgSurface
                                border.color: Theme.border

                                RowLayout {
                                    anchors.centerIn: parent
                                    spacing: 6
                                    Text {
                                        text: Theme.iconQr
                                        font.family: Theme.iconFont
                                        font.pixelSize: 12
                                        color: Theme.textMain
                                    }
                                    Text {
                                        text: "Show QR Code"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: Theme.textMain
                                    }
                                }

                                MouseArea {
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.runEngineAction(["qr"])
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                height: 32
                                radius: Theme.radiusSm
                                color: Theme.bgSurface
                                border.color: Theme.border

                                RowLayout {
                                    anchors.centerIn: parent
                                    spacing: 6
                                    Text {
                                        text: Theme.iconFolder
                                        font.family: Theme.iconFont
                                        font.pixelSize: 12
                                        color: Theme.textMain
                                    }
                                    Text {
                                        text: "Open Downloads"
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: Theme.textMain
                                    }
                                }

                                MouseArea {
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.runEngineAction(["open-downloads"])
                                }
                            }
                        }
                    }
                }

                // Recent Transfers & Integrity Log
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    radius: Theme.radiusMd
                    color: Theme.bgCard
                    border.color: Theme.border

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 10

                        Text {
                            text: "RECENT TRANSFERS & INTEGRITY"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMuted
                        }

                        ListView {
                            id: recentList
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            spacing: 6
                            model: root.recentFiles

                            delegate: Rectangle {
                                width: recentList.width
                                height: 36
                                radius: Theme.radiusSm
                                color: Theme.bgSurface
                                border.color: Theme.border

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    spacing: 8

                                    Text {
                                        text: Theme.iconCheck
                                        font.family: Theme.iconFont
                                        font.pixelSize: 11
                                        color: Theme.accentSuccess
                                    }

                                    Text {
                                        text: (modelData.name || modelData)
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: Theme.textMain
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    Text {
                                        text: "VERIFIED"
                                        font.family: Theme.monoFont
                                        font.pixelSize: 9
                                        color: Theme.accentSuccess
                                    }
                                }
                            }

                            Item {
                                anchors.centerIn: parent
                                visible: root.recentFiles.length === 0
                                Text {
                                    anchors.centerIn: parent
                                    text: "No recent transfer activity"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    color: Theme.textDim
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
