import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io

TextEdit {
    id: control

    property string placeholderText: ""
    property color placeholderTextColor: "#666666"
    property int maxLength: 300
    property int maxPasteBytes: 4096
    property string pasteNotice: ""
    property bool multiline: false

    signal accepted()

    function insertCleanText(raw) {
        if (readOnly)
            return ;

        var clean = String(raw || "").replace(/\u0000/g, "");
        if (!multiline)
            clean = clean.replace(/[\r\n\t\v\f]/g, " ");

        var start = Math.min(selectionStart, selectionEnd);
        var end = Math.max(selectionStart, selectionEnd);
        var room = maxLength > 0 ? Math.max(0, maxLength - (length - (end - start))) : clean.length;
        if (clean.length > room)
            clean = clean.substring(0, room);

        if (clean.length === 0 && start === end)
            return ;

        if (end > start)
            remove(start, end);

        if (clean.length > 0) {
            insert(start, clean);
            cursorPosition = start + clean.length;
        }
        // TextEdit only has textEdited() from Qt 6.9 on; declaring it ourselves would be an
        // invalid override there, so emit it only where it exists.
        if (typeof control.textEdited === "function")
            control.textEdited();
    }

    function startBoundedPaste() {
        if (readOnly || pasteProcess.running)
            return ;

        control.pasteNotice = "";
        pasteProcess.collectedBytes = 0;
        pasteProcess.collectedText = "";
        pasteProcess.overflowed = false;
        pasteProcess.command = ["timeout", "--signal=KILL", "1", "wl-paste", "--no-newline", "--type", "text/plain;charset=utf-8"];
        pasteProcess.running = true;
    }

    wrapMode: multiline ? TextEdit.Wrap : TextEdit.NoWrap
    textFormat: TextEdit.PlainText
    selectByMouse: true
    clip: true
    Keys.onPressed: (event) => {
        if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            if (!control.multiline) {
                event.accepted = true;
                control.accepted();
                return ;
            }
        }
        if (!control.multiline && (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab)) {
            // Single-line field: let Tab move focus instead of inserting a tab character.
            event.accepted = true;
            var next = control.nextItemInFocusChain(event.key === Qt.Key_Tab);
            if (next)
                next.forceActiveFocus();
            return ;
        }
        if (event.matches(StandardKey.Paste) || (event.modifiers & Qt.ControlModifier && (event.key === Qt.Key_V || event.key === Qt.Key_Insert)) || (event.modifiers & Qt.ShiftModifier && event.key === Qt.Key_Insert)) {
            event.accepted = true;
            control.startBoundedPaste();
            return ;
        }
    }
    onTextChanged: {
        control.pasteNotice = "";
        if (maxLength > 0 && text.length > maxLength) {
            var pos = cursorPosition;
            text = text.slice(0, maxLength);
            cursorPosition = Math.min(pos, maxLength);
        }
    }

    Process {
        id: pasteProcess

        property int collectedBytes: 0
        property string collectedText: ""
        property bool overflowed: false

        onExited: (exitCode) => {
            if (overflowed || exitCode === 124 || exitCode === 137) {
                control.pasteNotice = "Clipboard content exceeded byte limit or timed out.";
                return ;
            }
            if (exitCode !== 0 || collectedText.length === 0)
                return ;

            control.insertCleanText(collectedText);
        }

        stdout: SplitParser {
            splitMarker: ""
            onRead: (chunk) => {
                if (pasteProcess.overflowed) {
                    pasteProcess.running = false;
                    return ;
                }
                // Count UTF-8 bytes, not UTF-16 code units, so the limit matches its name.
                // A chunk can end in half a surrogate pair; then count the worst case.
                var chunkBytes;
                try {
                    chunkBytes = unescape(encodeURIComponent(chunk)).length;
                } catch (e) {
                    chunkBytes = chunk.length * 3;
                }
                pasteProcess.collectedBytes += chunkBytes;
                if (pasteProcess.collectedBytes > control.maxPasteBytes) {
                    pasteProcess.overflowed = true;
                    pasteProcess.running = false;
                    return ;
                }
                pasteProcess.collectedText += chunk;
            }
        }

    }

    MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.MiddleButton
        onPressed: (mouse) => {
            mouse.accepted = true;
        }
    }

    Text {
        anchors.fill: parent
        anchors.leftMargin: control.leftPadding
        anchors.rightMargin: control.rightPadding
        anchors.topMargin: control.topPadding
        anchors.bottomMargin: control.bottomPadding
        text: control.placeholderText
        font: control.font
        color: control.placeholderTextColor
        visible: control.text.length === 0 && !control.activeFocus
        verticalAlignment: control.multiline ? Text.AlignTop : control.verticalAlignment
        elide: Text.ElideRight
        textFormat: Text.PlainText
    }

}
