# Maintainer: Ozan Özdil <ozan@pm.me>
pkgname=omarchy-omasend
pkgver=1.1.0
pkgrel=1
pkgdesc="Wireless AirBridge, QR file transfer, and cross-device sharing plugin for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-omasend"
license=('MIT')
depends=('glibc' 'gcc-libs')
optdepends=('wl-clipboard: for Wayland clipboard sync')
makedepends=('cargo' 'rust')

build() {
    cd "${startdir}"
    cargo build --release --locked
}

package() {
    cd "${startdir}"
    install -Dm755 "target/release/omasend-engine" "${pkgdir}/usr/bin/omasend-engine"
    install -Dm755 "target/release/omasend-engine" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-engine"
    install -Dm755 "omasend-status" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-status"
    install -Dm755 "omasend-dashboard" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/omasend-dashboard"
    install -Dm644 "manifest.json" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/manifest.json"
    install -Dm644 "Panel.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omasend/Panel.qml"
    install -Dm644 "README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
