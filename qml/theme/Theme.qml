pragma Singleton
import QtQuick
import Quickshell
import Quickshell.Io

QtObject {
    id: root

    // Active Omarchy Theme Information
    property string themeName: "monotone"
    property bool isDarkTheme: true

    // Dynamic Color Palette (reactive live bindings)
    property color bgDark: "#0a0a0a"
    property color bgBase: "#111111"
    property color bgSurface: "#1a1a1a"
    property color bgCard: "#222222"
    property color bgCardHover: "#2c2c2c"
    property color border: "#333333"
    property color borderLight: "#444444"

    property color textMain: "#e5e5e5"
    property color textMuted: "#888888"
    property color textDim: "#555555"

    property color accent: "#b8b8b8"
    property color accentHover: "#cccccc"
    property color accentSuccess: "#a6a6a6"
    property color accentWarning: "#8c8c8c"
    property color accentDanger: "#666666"

    // UI Radii and Spacing
    readonly property int radiusSm: 4
    readonly property int radiusMd: 8
    readonly property int radiusLg: 12

    // Mandatory Typography Standard
    readonly property string fontFamily: "JetBrainsMono Nerd Font, JetBrains Mono, monospace"
    readonly property string monoFont: "JetBrainsMono Nerd Font, JetBrains Mono, monospace"
    readonly property string iconFont: "Font Awesome 7 Free Solid, Font Awesome 7 Free, JetBrainsMono Nerd Font, monospace"

    // Themeable Monochrome Icons (Unicode Font Glyph Standard - Zero Emoji Policy)
    readonly property string iconAirBridge: "\uf1eb"
    readonly property string iconRadar: "\uf1e0"
    readonly property string iconSend: "\uf1d8"
    readonly property string iconReceive: "\uf019"
    readonly property string iconUpload: "\uf093"
    readonly property string iconQr: "\uf029"
    readonly property string iconCheck: "\uf00c"
    readonly property string iconTimes: "\uf00d"
    readonly property string iconRefresh: "\uf021"
    readonly property string iconCopy: "\uf0c5"
    readonly property string iconFile: "\uf15b"
    readonly property string iconShield: "\uf132"
    readonly property string iconDesktop: "\uf108"
    readonly property string iconMobile: "\uf10b"
    readonly property string iconFolder: "\uf07b"
    readonly property string iconSearch: "\uf002"
    readonly property string iconLock: "\uf023"
    readonly property string iconKey: "\uf084"
    readonly property string iconSliders: "\uf1de"
    readonly property string iconTerminal: "\uf120"
    readonly property string iconInfo: "\uf05a"

    // Filesystem Theme Watcher
    readonly property string homeDir: Quickshell.env("HOME")
    readonly property string omarchyCurrentThemePath: homeDir + "/.local/state/omarchy/current/theme/colors.toml"

    property string lastLoadedRaw: ""

    function loadColors(raw) {
        if (!raw || raw.trim().length === 0 || raw === lastLoadedRaw) return;
        lastLoadedRaw = raw;

        var dict = {};
        var lines = String(raw).split("\n");
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line || line.charAt(0) === '#') continue;
            var match = line.match(/^([A-Za-z0-9_-]+)\s*=\s*["']?([^"'\r\n]+?)["']?\s*(?:#.*)?$/);
            if (match) {
                dict[match[1].toLowerCase()] = match[2].trim();
            }
        }

        var mode = dict["mode"] || "dark";
        root.isDarkTheme = (mode !== "light");

        var base = dict["background"] || dict["bg"] || (root.isDarkTheme ? "#111111" : "#f4f4f4");
        var fg = dict["foreground"] || dict["fg"] || (root.isDarkTheme ? "#e5e5e5" : "#1a1a1a");
        var acc = dict["accent"] || dict["color4"] || (root.isDarkTheme ? "#b8b8b8" : "#333333");
        var sel = dict["selection"] || dict["selection_background"] || "";
        var mut = dict["muted"] || dict["color8"] || "";

        root.bgBase = base;

        if (root.isDarkTheme) {
            root.bgDark = dict["dark_background"] || dict["darker_background"] || dict["color0"] || Qt.darker(base, 1.3);
            root.bgSurface = dict["lighter_background"] || (sel ? sel : Qt.lighter(base, 1.3));
            root.bgCard = (sel && sel !== base) ? sel : Qt.lighter(base, 1.5);
            root.bgCardHover = Qt.lighter(root.bgCard, 1.2);
            root.border = mut ? mut : Qt.rgba(fg.r, fg.g, fg.b, 0.18);
            root.borderLight = acc ? Qt.rgba(acc.r, acc.g, acc.b, 0.35) : Qt.rgba(fg.r, fg.g, fg.b, 0.25);
            root.textMain = dict["bright_foreground"] || fg;
            root.textMuted = dict["light_foreground"] || mut || Qt.rgba(fg.r, fg.g, fg.b, 0.65);
            root.textDim = dict["dark_foreground"] || dict["color8"] || Qt.rgba(fg.r, fg.g, fg.b, 0.4);
        } else {
            root.bgDark = dict["dark_background"] || Qt.darker(base, 1.08);
            root.bgSurface = dict["lighter_background"] || Qt.lighter(base, 1.03);
            root.bgCard = (sel && sel !== base) ? sel : Qt.darker(base, 1.05);
            root.bgCardHover = Qt.darker(root.bgCard, 1.06);
            root.border = mut ? mut : Qt.rgba(fg.r, fg.g, fg.b, 0.18);
            root.borderLight = acc ? Qt.rgba(acc.r, acc.g, acc.b, 0.35) : Qt.rgba(fg.r, fg.g, fg.b, 0.25);
            root.textMain = dict["bright_foreground"] || fg;
            root.textMuted = dict["light_foreground"] || mut || Qt.rgba(fg.r, fg.g, fg.b, 0.65);
            root.textDim = dict["dark_foreground"] || dict["color8"] || Qt.rgba(fg.r, fg.g, fg.b, 0.4);
        }

        root.accent = acc;
        root.accentHover = Qt.lighter(acc, 1.15);
        root.accentSuccess = dict["bright_green"] || dict["green"] || dict["color2"] || "#a6a6a6";
        root.accentWarning = dict["bright_yellow"] || dict["yellow"] || dict["color3"] || "#8c8c8c";
        root.accentDanger = dict["bright_red"] || dict["red"] || dict["color1"] || "#666666";
    }

    Component.onCompleted: {
        themeWatcher.running = true;
    }

    Process {
        id: themeWatcher
        command: ["/bin/cat", root.omarchyCurrentThemePath]
        stdout: StdioCollector {
            onDataChanged: {
                if (data && data.length > 0) {
                    root.loadColors(data);
                }
            }
        }
    }
}
