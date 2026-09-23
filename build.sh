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

# Bind source provenance stamp
if [[ -f "${DIR}/Cargo.lock" && -f "${DIR}/Cargo.toml" ]]; then
    /usr/bin/sha256sum "${DIR}/Cargo.lock" "${DIR}/Cargo.toml" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}' > "${DIR}/.engine-provenance" 2>/dev/null || true
fi

echo "omasend-engine successfully compiled and placed at ${DIR}/omasend-engine"

if [[ -x /usr/bin/omarchy-restart-shell ]]; then
    echo "Reloading Omarchy shell..."
    /usr/bin/omarchy-restart-shell >/dev/null 2>&1 || true
fi

echo "OmaSend is ready."

