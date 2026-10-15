#!/usr/bin/env bash
# Builds libomasend_core.so for Android and regenerates the Kotlin (UniFFI) bindings.
#
#   core/build-android.sh [path/to/omasend-android]
#
# Needs: rustup targets aarch64-linux-android armv7-linux-androideabi x86_64-linux-android,
#        cargo-ndk (cargo install cargo-ndk), Android NDK (ANDROID_NDK_HOME or ~/Android/Sdk/ndk/*).
set -euo pipefail

CORE_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${1:-$CORE_DIR/../../../mobile/omasend-android}"
APP_DIR="$(cd "$APP_DIR" && pwd)"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  ANDROID_NDK_HOME="$(ls -d "$HOME"/Android/Sdk/ndk/* 2>/dev/null | sort -V | tail -1)"
  export ANDROID_NDK_HOME
fi
[[ -d "$ANDROID_NDK_HOME" ]] || { echo "Android NDK not found (set ANDROID_NDK_HOME)" >&2; exit 1; }

cd "$CORE_DIR"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 26 \
  -o "$APP_DIR/app/src/main/jniLibs" build --release --lib

# Bindings are generated from an unstripped host build (release builds strip UniFFI metadata).
cargo build --lib
cargo run --features bindgen --bin uniffi-bindgen -- generate \
  --library target/debug/libomasend_core.so --language kotlin \
  --out-dir "$APP_DIR/app/src/main/java" --no-format

echo "OK: $(ls "$APP_DIR"/app/src/main/jniLibs/*/libomasend_core.so | wc -l) ABIs + bindings in $APP_DIR"
