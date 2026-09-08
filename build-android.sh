#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$SCRIPT_DIR/android"

if [ ! -d "$ANDROID_DIR" ]; then
    echo "Error: android directory not found at $ANDROID_DIR" >&2
    exit 1
fi

echo "Building OmaSend for Android..."
cd "$ANDROID_DIR"

MODE="${1:-debug}"

if [ "$MODE" = "bundle" ] || [ "$MODE" = "release" ]; then
    ./gradlew bundleRelease
    AAB_SRC="$ANDROID_DIR/app/build/outputs/bundle/release/app-release.aab"
    AAB_DEST="$SCRIPT_DIR/omasend-release.aab"
    if [ -f "$AAB_SRC" ]; then
        cp "$AAB_SRC" "$AAB_DEST"
        echo "Release bundle created: $AAB_DEST"
    else
        echo "Error: Release bundle output not found at $AAB_SRC" >&2
        exit 1
    fi
else
    ./gradlew assembleDebug
    APK_SRC="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
    APK_DEST="$SCRIPT_DIR/omasend-debug.apk"
    if [ -f "$APK_SRC" ]; then
        cp "$APK_SRC" "$APK_DEST"
        echo "Build successful: $APK_DEST"
    else
        echo "Error: APK output not found at $APK_SRC" >&2
        exit 1
    fi
fi
