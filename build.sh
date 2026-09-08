#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "Building omasend-engine from source..."
cargo build --release --locked
install -m 755 target/release/omasend-engine ./omasend-engine

echo "omasend-engine successfully compiled and placed at ${DIR}/omasend-engine"

if command -v ufw >/dev/null 2>&1; then
    sudo -n ufw allow in proto tcp to any port 53317 >/dev/null 2>&1 || true
    sudo -n ufw allow in proto udp to any port 53317 >/dev/null 2>&1 || true
fi

if command -v omarchy-restart-shell >/dev/null 2>&1; then
    echo "Reloading Omarchy shell..."
    omarchy-restart-shell >/dev/null 2>&1 || true
fi

echo "OmaSend is ready."
