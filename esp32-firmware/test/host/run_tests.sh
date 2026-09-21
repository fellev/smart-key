#!/usr/bin/env bash
# Build and run the SmartKey protocol unit tests natively (no hardware needed).
#
#   ./test/host/run_tests.sh
#
# Uses the mbedTLS sources that ship with ESP-IDF so the host build tests exactly
# the same crypto library version as the firmware.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${HERE}/build"

# Locate mbedTLS: prefer $IDF_PATH, then the usual local installs.
#
# NOTE: this project targets ESP-IDF 5.5.x (mbedTLS 3.x). ESP-IDF 6.x ships
# mbedTLS 4.x, whose vendored copy cannot be built out of tree — see the
# "ESP-IDF version" section in ../../README.md before attempting an upgrade.
if [[ -n "${MBEDTLS_DIR:-}" ]]; then
    :
elif [[ -n "${IDF_PATH:-}" && -d "${IDF_PATH}/components/mbedtls/mbedtls" ]]; then
    MBEDTLS_DIR="${IDF_PATH}/components/mbedtls/mbedtls"
else
    for candidate in "${HOME}"/esp/v*/esp-idf "${HOME}"/esp/esp-idf; do
        if [[ -d "${candidate}/components/mbedtls/mbedtls" ]]; then
            MBEDTLS_DIR="${candidate}/components/mbedtls/mbedtls"
        fi
    done
fi

if [[ -z "${MBEDTLS_DIR:-}" ]]; then
    echo "error: could not find mbedTLS sources. Set MBEDTLS_DIR or IDF_PATH." >&2
    exit 1
fi

echo "Using mbedTLS: ${MBEDTLS_DIR}"

# Keep the C vectors in sync with shared-protocols/test-vectors/*.json.
python3 "${HERE}/sync_vectors.py"

cmake -S "${HERE}" -B "${BUILD_DIR}" -DMBEDTLS_DIR="${MBEDTLS_DIR}" -DCMAKE_BUILD_TYPE=Debug
cmake --build "${BUILD_DIR}" --target test_smartkey_proto -j "$(nproc)"
"${BUILD_DIR}/test_smartkey_proto"
