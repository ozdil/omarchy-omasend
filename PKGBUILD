# Maintainer: Ozan Özdil <ozan@pm.me>
pkgname=omarchy-omasend
pkgver=2.0.9
pkgrel=1
pkgdesc="Local file and clipboard sharing between Omarchy and Android: QR pairing, end-to-end encrypted QUIC between paired devices"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-omasend"
license=('MIT')
# quickshell runs the panel; wl-clipboard is needed for clipboard sync. QR codes are rendered
# by the engine itself (no qrencode).
depends=('glibc' 'gcc-libs' 'libnotify' 'quickshell' 'wl-clipboard')
optdepends=(
    'zenity: for native file chooser dialog'
    'libwebp: for clipboard image WebP thumbnail compression'
    'grim: to scan a pairing QR code shown on screen'
    'zbar: to scan a pairing QR code shown on screen'
    'cloudflared: for the optional WAN tunnel'
)
makedepends=('cargo' 'rust')
# Browser client (optional, not built here): the engine serves it at /web/ from
# /usr/share/omasend/web if that directory exists (built omasend-web dist/). Users of build.sh
# get it in ~/.local/share/omarchy/omasend/web instead.

build() {
    cd "${startdir}"
    cargo build --release --locked
}

package() {
    cd "${startdir}"
    # One copy: the panel and the omasend-status/-dashboard scripts fall back to /usr/bin.
    install -Dm755 "target/release/omasend-engine" "${pkgdir}/usr/bin/omasend-engine"
    install -Dm755 "omasend-status" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-status"
    install -Dm755 "omasend-dashboard" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-dashboard"
    install -Dm755 "omasend-theme-icon" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-theme-icon"
    install -Dm644 "omasend.desktop" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend.desktop"
    install -Dm644 "assets/omasend-symbolic.svg" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/assets/omasend-symbolic.svg"
    install -Dm644 "manifest.json" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/manifest.json"
    install -Dm644 "Panel.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/Panel.qml"
    install -Dm644 "OmaI18n.js" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/OmaI18n.js"
    install -Dm644 "qml/MainWindow.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/MainWindow.qml"
    install -Dm644 "qml/shell.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/shell.qml"
    install -Dm644 "qml/theme/Theme.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/theme/Theme.qml"
    install -Dm644 "qml/theme/qmldir" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/theme/qmldir"
    ln -s ../OmaI18n.js "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/OmaI18n.js"
    for f in assets/*.wav; do
        install -Dm644 "${f}" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/${f}"
    done
    install -Dm644 "omasend.desktop" "${pkgdir}/usr/share/applications/omasend.desktop"
    install -Dm644 "assets/omasend.svg" "${pkgdir}/usr/share/icons/hicolor/scalable/apps/omasend.svg"
    install -Dm644 "assets/omasend-symbolic.svg" "${pkgdir}/usr/share/icons/hicolor/symbolic/apps/omasend-symbolic.svg"
    install -Dm644 "README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
