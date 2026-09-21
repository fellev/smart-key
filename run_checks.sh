#!/usr/bin/env bash
# Run every SmartKey check that does not need hardware.
#
#   ./run_checks.sh
#
# 1. reference crypto self test (RFC 5869 / 7748 / 4231)
# 2. regenerate the golden vectors and fail if they changed unexpectedly
# 3. cross-language constant consistency (C vs Kotlin vs JSON schema)
# 4. firmware protocol unit tests, built natively against ESP-IDF's mbedTLS
# 5. Android unit tests (skipped when no JDK is installed)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
status=0

step() {
    echo
    echo "=============================================================="
    echo "  $1"
    echo "=============================================================="
}

step "1/5  reference crypto self test"
python3 "${ROOT}/shared-protocols/tools/selftest.py" || status=1

step "2/5  regenerate the shared test vectors"
python3 "${ROOT}/shared-protocols/tools/gen_test_vectors.py" || status=1

step "3/5  cross-language constant consistency"
python3 "${ROOT}/shared-protocols/tools/check_consistency.py" || status=1

step "4/5  firmware protocol unit tests"
if [[ -d "${ROOT}/esp32-firmware/test/host" ]]; then
    "${ROOT}/esp32-firmware/test/host/run_tests.sh" 2>&1 | tail -n 20 || status=1
fi

step "5/5  Android unit tests"
# Pick up a JDK that is installed but not on PATH (e.g. a local Temurin
# tarball), so these tests are not silently skipped.
if [[ -z "${JAVA_HOME:-}" ]]; then
    for candidate in "${HOME}/tools/jdk-17" /usr/lib/jvm/java-17-openjdk-amd64; do
        if [[ -x "${candidate}/bin/java" ]]; then
            export JAVA_HOME="${candidate}"
            break
        fi
    done
fi
if [[ -n "${JAVA_HOME:-}" ]] || command -v java >/dev/null 2>&1; then
    (cd "${ROOT}/android-app" && ./gradlew --quiet testDebugUnitTest) || status=1
    echo "Android unit tests passed."
else
    echo "SKIPPED: no JDK found. Run the tests from Android Studio, or install one:"
    echo "  sudo apt install openjdk-17-jdk"
    echo "  # or without root, into ~/tools/jdk-17 (picked up automatically):"
    echo "  curl -L 'https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse' \\"
    echo "    | tar xz -C \"\${HOME}/tools\" && mv \"\${HOME}\"/tools/jdk-17* \"\${HOME}/tools/jdk-17\""
fi

echo
if [[ ${status} -eq 0 ]]; then
    echo "All checks passed."
else
    echo "Some checks FAILED."
fi
exit ${status}
