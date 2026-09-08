#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "🦀 Building omasend-engine from source..."
cargo build --release --locked
cp target/release/omasend-engine ./omasend-engine
chmod 755 ./omasend-engine

echo "✅ omasend-engine successfully compiled and placed at ${DIR}/omasend-engine"

if command -v omarchy-restart-shell >/dev/null 2>&1; then
    echo "🔄 Reloading Omarchy shell..."
    omarchy-restart-shell >/dev/null 2>&1 || true
fi

echo "🚀 OmaSend is now fully operational!"
