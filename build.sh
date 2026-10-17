#!/bin/bash -p
set -euo pipefail

# Immediate rejection of loader injection
if [ -n "${LD_PRELOAD:-}" ] || [ -n "${LD_LIBRARY_PATH:-}" ]; then
    echo "Security Error: Prohibited loader control variable detected" >&2
    exit 1
fi

# Re-exec through fixed trusted shell under sanitized environment (/usr/bin/env -i)
if [ "${OMASEND_SECURE_ENV:-0}" != "1" ]; then
    exec /usr/bin/env -i \
        PATH="/usr/bin:/bin:${HOME}/.local/bin:${HOME}/.cargo/bin" \
        HOME="${HOME}" \
        USER="${USER:-$(/usr/bin/id -un 2>/dev/null || echo "user")}" \
        LANG="${LANG:-C.UTF-8}" \
        LC_ALL="${LC_ALL:-C.UTF-8}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(/usr/bin/id -u)}" \
        WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-1}" \
        HYPRLAND_INSTANCE_SIGNATURE="${HYPRLAND_INSTANCE_SIGNATURE:-}" \
        OMASEND_SECURE_ENV=1 \
        /bin/bash -p "$0" "$@"
fi

# Reject unexpected build and loader controls before building
for var in LD_PRELOAD LD_LIBRARY_PATH RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_HOME BASH_ENV ENV; do
    if [ -n "${!var+x}" ]; then
        echo "Security Error: Prohibited build/loader control variable detected: ${var}" >&2
        exit 1
    fi
done

DIR="$(cd "$(/usr/bin/dirname "$(/usr/bin/realpath "${BASH_SOURCE[0]}")")" && /usr/bin/pwd)"
cd "$DIR"

CARGO_BIN=""
if [[ -x /usr/bin/cargo ]]; then
    CARGO_BIN="/usr/bin/cargo"
elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    CARGO_BIN="${HOME}/.cargo/bin/cargo"
else
    echo "Error: cargo binary not found" >&2
    exit 1
fi

echo "Building omasend-engine from source..."
TMP_BUILD_DIR="$(/usr/bin/mktemp -d -t omasend-build.XXXXXX)"
cleanup() {
    /usr/bin/rm -rf "${TMP_BUILD_DIR}"
}
trap cleanup EXIT

"${CARGO_BIN}" build --release --locked --target-dir "${TMP_BUILD_DIR}"
/usr/bin/install -m 755 "${TMP_BUILD_DIR}/release/omasend-engine" "${DIR}/omasend-engine"

# Bind source tree identity and installed binary SHA-256
SOURCE_HASH=""
if [[ -d "${DIR}/src" && -f "${DIR}/Cargo.toml" && -f "${DIR}/Cargo.lock" ]]; then
    SOURCE_HASH="$(/usr/bin/find "${DIR}/src" "${DIR}/Cargo.toml" "${DIR}/Cargo.lock" -type f 2>/dev/null | /usr/bin/sort | /usr/bin/xargs /usr/bin/sha256sum 2>/dev/null | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
fi

if [[ -z "${SOURCE_HASH}" ]]; then
    echo "Security Error: Unable to compute source identity" >&2
    exit 1
fi

BIN_HASH="$(/usr/bin/sha256sum "${DIR}/omasend-engine" 2>/dev/null | /usr/bin/awk '{print $1}')"
if [[ -z "${BIN_HASH}" ]]; then
    echo "Security Error: Unable to compute engine binary digest" >&2
    exit 1
fi

echo "${SOURCE_HASH} ${BIN_HASH}" > "${DIR}/.engine-provenance"


echo "omasend-engine successfully compiled and placed at ${DIR}/omasend-engine"

PLUGIN_TARGET_DIR="${HOME}/.config/omarchy/plugins/ozdil.omasend"
if [[ -d "${PLUGIN_TARGET_DIR}" && "${DIR}" != "${PLUGIN_TARGET_DIR}" ]]; then
    echo "Syncing updated plugin files to ${PLUGIN_TARGET_DIR}..."
    /usr/bin/cp -f "${DIR}/Panel.qml" "${PLUGIN_TARGET_DIR}/Panel.qml"
    if [[ -f "${DIR}/OmaI18n.js" ]]; then
        /usr/bin/cp -f "${DIR}/OmaI18n.js" "${PLUGIN_TARGET_DIR}/OmaI18n.js"
    fi
    /usr/bin/cp -f "${DIR}/manifest.json" "${PLUGIN_TARGET_DIR}/manifest.json"
    /usr/bin/cp -f "${DIR}/.engine-provenance" "${PLUGIN_TARGET_DIR}/.engine-provenance"
    /usr/bin/install -m 755 "${DIR}/omasend-engine" "${PLUGIN_TARGET_DIR}/omasend-engine"
    if [[ -d "${DIR}/assets" ]]; then
        /usr/bin/mkdir -p "${PLUGIN_TARGET_DIR}/assets"
        /usr/bin/cp -rf "${DIR}/assets/"* "${PLUGIN_TARGET_DIR}/assets/"
    fi
    # Standalone window (omasend-dashboard); qml/OmaI18n.js is a symlink to ../OmaI18n.js.
    if [[ -d "${DIR}/qml" ]]; then
        /usr/bin/rm -rf "${PLUGIN_TARGET_DIR}/qml"
        /usr/bin/cp -R "${DIR}/qml" "${PLUGIN_TARGET_DIR}/qml"
    fi
    for f in omasend-dashboard omasend-status omasend-theme-icon; do
        [[ -f "${DIR}/${f}" ]] && /usr/bin/install -m 755 "${DIR}/${f}" "${PLUGIN_TARGET_DIR}/${f}"
    done
    /usr/bin/cp -f "${DIR}/omasend.desktop" "${PLUGIN_TARGET_DIR}/omasend.desktop"

    # Launcher icon follows the theme: recolor now and on every theme change.
    HOOK_DIR="${HOME}/.config/omarchy/hooks/theme-set.d"
    /usr/bin/mkdir -p "${HOOK_DIR}"
    /usr/bin/printf '%s\n' '#!/bin/bash' \
        'icon="${HOME}/.config/omarchy/plugins/ozdil.omasend/omasend-theme-icon"' \
        '[[ -x "${icon}" ]] && "${icon}" || true' > "${HOOK_DIR}/omasend-icon"
    "${PLUGIN_TARGET_DIR}/omasend-theme-icon" || true
fi

# Sync engine binary to ~/.local/bin/omasend-engine (used by Panel.qml)
LOCAL_BIN_DIR="${HOME}/.local/bin"
LOCAL_BIN_ENGINE="${LOCAL_BIN_DIR}/omasend-engine"
/usr/bin/mkdir -p "${LOCAL_BIN_DIR}"
if [[ ! -L "${LOCAL_BIN_ENGINE}" ]]; then
    /usr/bin/install -m 755 "${DIR}/omasend-engine" "${LOCAL_BIN_ENGINE}"
fi

STATE_DIR="${HOME}/.local/state/omarchy/omasend"
/usr/bin/mkdir -p -m 700 "${STATE_DIR}"
if [[ ! -L "${STATE_DIR}/install_manifest.json" ]]; then
    /usr/bin/cat > "${STATE_DIR}/.tmp_install_manifest.json" <<EOF
{
  "plugin": "ozdil.omasend",
  "files": {
    "${LOCAL_BIN_ENGINE}": "${BIN_HASH}"
  }
}
EOF
    /usr/bin/chmod 600 "${STATE_DIR}/.tmp_install_manifest.json"
    /usr/bin/mv -f "${STATE_DIR}/.tmp_install_manifest.json" "${STATE_DIR}/install_manifest.json"
fi

# Terminate any previous instance so new binary is invoked
/usr/bin/pkill -u "$UID" -f "omasend-engine --serve" >/dev/null 2>&1 || true

if [[ -x /usr/bin/omarchy-restart-shell ]]; then
    echo "Reloading Omarchy shell..."
    /usr/bin/omarchy-restart-shell >/dev/null 2>&1 || true
fi

echo "OmaSend is ready."

