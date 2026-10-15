#!/bin/bash -p
set -euo pipefail

if [ -n "${LD_PRELOAD:-}" ] || [ -n "${LD_LIBRARY_PATH:-}" ]; then
    echo "Security Error: Prohibited loader control variable detected" >&2
    exit 1
fi

if [ "${OMASEND_SECURE_ENV:-0}" != "1" ]; then
    exec /usr/bin/env -i \
        PATH="/usr/bin:/bin:${HOME}/.local/bin" \
        HOME="${HOME}" \
        USER="${USER:-$(/usr/bin/id -un 2>/dev/null || echo "user")}" \
        LANG="C.UTF-8" \
        LC_ALL="C.UTF-8" \
        OMASEND_SECURE_ENV=1 \
        /bin/bash -p "$0" "$@"
fi

MANIFEST_FILE="${HOME}/.local/state/omarchy/omasend/install_manifest.json"

if [[ ! -f "${MANIFEST_FILE}" || -L "${MANIFEST_FILE}" ]]; then
    echo "No verified install manifest found at ${MANIFEST_FILE}; skipping file removal."
    exit 0
fi

# Terminate running daemon in user space
/usr/bin/pkill -u "$UID" -f "omasend-engine --serve" >/dev/null 2>&1 || true

while IFS=$'\t' read -r file_path expected_hash; do
    [[ -n "${file_path}" && -n "${expected_hash}" ]] || continue
    if [[ -L "${file_path}" ]]; then
        echo "Skipping symlink: ${file_path}"
        continue
    fi
    if [[ -f "${file_path}" ]]; then
        actual_hash="$(/usr/bin/sha256sum "${file_path}" 2>/dev/null | /usr/bin/awk '{print $1}')"
        if [[ "${actual_hash}" == "${expected_hash}" ]]; then
            /usr/bin/rm -f "${file_path}"
            echo "Removed verified file: ${file_path}"
        else
            echo "Preserving modified user file: ${file_path}"
        fi
    fi
done < <(/usr/bin/jq -r '.files | to_entries[] | "\(.key)\t\(.value)"' "${MANIFEST_FILE}" 2>/dev/null || true)

/usr/bin/rm -f "${MANIFEST_FILE}"
echo "OmaSend uninstall completed safely."
