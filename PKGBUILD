# Maintainer: Ozan Özdil <ozan@pm.me>
pkgname=omarchy-omasend
pkgver=1.9.1
pkgrel=1
pkgdesc="Anonymous Numbered Identity (Zero-Log OmaID), Zero-Click AirBridge, and cross-device sharing plugin for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-omasend"
license=('MIT')
depends=('glibc' 'gcc-libs' 'curl' 'jq' 'libnotify')
optdepends=(
    'wl-clipboard: for Wayland clipboard sync'
    'qrencode: for QR code generation'
    'zenity: for native file chooser dialog'
    'libwebp: for clipboard image WebP thumbnail compression'
)
makedepends=('cargo' 'rust')

build() {
    cd "${startdir}"
    cargo build --release --locked
}

package() {
    cd "${startdir}"
    install -Dm755 "target/release/omasend-engine" "${pkgdir}/usr/bin/omasend-engine"
    install -Dm755 "target/release/omasend-engine" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-engine"
    install -Dm755 "target/release/omasend-engine" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/bin/omasend-engine"
    install -Dm755 "omasend-status" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-status"
    install -Dm755 "omasend-dashboard" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-dashboard"
    install -Dm644 "manifest.json" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/manifest.json"
    install -Dm644 "Panel.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/Panel.qml"
    install -Dm644 "OmaI18n.js" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/OmaI18n.js"
    install -Dm644 "qml/MainWindow.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/MainWindow.qml"
    install -Dm644 "qml/shell.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/shell.qml"
    install -Dm644 "qml/theme/Theme.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/qml/theme/Theme.qml"
    install -Dm644 "assets/receive.wav" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/assets/receive.wav"
    install -Dm644 "assets/send.wav" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/assets/send.wav"
    install -Dm644 "omasend.desktop" "${pkgdir}/usr/share/applications/omasend.desktop"
    install -Dm644 "README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
