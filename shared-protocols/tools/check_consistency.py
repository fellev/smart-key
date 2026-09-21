#!/usr/bin/env python3
"""Check that the firmware, the Android app and the schema agree on SKP1.

    python3 shared-protocols/tools/check_consistency.py

The three implementations each hard-code the protocol constants (a C header, a
Kotlin object and a JSON schema). This script re-reads all three and fails if
they ever drift apart, which is the cheapest possible guard against a silent
wire-format mismatch between the door unit and the phone.
"""

from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.path.normpath(os.path.join(HERE, ".."))
ROOT = os.path.normpath(os.path.join(SHARED, ".."))

C_HEADER = os.path.join(
    ROOT, "esp32-firmware/components/smartkey_proto/include/smartkey_proto.h"
)
C_BLE = os.path.join(ROOT, "esp32-firmware/components/smartkey_ble/smartkey_ble.c")
KT_FILE = os.path.join(
    ROOT,
    "android-app/app/src/main/java/com/example/smart_key/protocol/SmartKeyProtocol.kt",
)
KCONFIG = os.path.join(ROOT, "esp32-firmware/main/Kconfig.projbuild")
SCHEMA = os.path.join(SHARED, "schema/smartkey-protocol.json")

failures = []
checks = 0


def check(name, c_value, kt_value, schema_value):
    """Compare one constant across the three sources."""
    global checks
    checks += 1
    if c_value == kt_value == schema_value:
        print(f"ok    {name:<26} = {schema_value}")
    else:
        failures.append(name)
        print(f"FAIL  {name}: C={c_value!r} Kotlin={kt_value!r} schema={schema_value!r}")


def check_pair(name, actual, expected):
    """Compare a value that exists in only two places (Kconfig and the schema)."""
    global checks
    checks += 1
    if actual == expected:
        print(f"ok    {name:<34} = {expected}")
    else:
        failures.append(name)
        print(f"FAIL  {name}: Kconfig={actual!r} schema={expected!r}")


def check_true(name, condition):
    """Assert an invariant that has no single numeric value."""
    global checks
    checks += 1
    if condition:
        print(f"ok    {name}")
    else:
        failures.append(name)
        print(f"FAIL  {name}")


def parse_kconfig_defaults(path):
    """Collect the 'default <value>' of each 'config NAME' block."""
    out = {}
    current = None
    config_re = re.compile(r"^\s*config\s+(\w+)\s*$")
    default_re = re.compile(r"^\s*default\s+(-?\d+)\s*$")
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            match = config_re.match(line)
            if match:
                current = match.group(1)
                continue
            if current is not None:
                match = default_re.match(line)
                if match:
                    out[current] = int(match.group(1))
                    current = None
    return out


def parse_c_defines(path):
    """Collect '#define NAME value' pairs with integer values."""
    out = {}
    pattern = re.compile(r"^#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|\d+)\b")
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            match = pattern.match(line.strip())
            if match:
                out[match.group(1)] = int(match.group(2), 0)
    return out


def parse_c_enums(path):
    """Collect 'SKP_NAME = value,' entries inside enums."""
    out = {}
    pattern = re.compile(r"^\s*(SKP_\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,")
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            match = pattern.match(line)
            if match:
                out[match.group(1)] = int(match.group(2), 0)
    return out


def parse_kotlin_consts(path, scope=None):
    """Collect 'const val NAME = value' pairs with integer values.

    Some names appear in more than one nested object (RATE_LIMITED lives in both
    ErrorCode and UnlockResult), so @p scope restricts the search to the body of
    a single `object Scope { ... }` block.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    if scope is not None:
        start = text.find(f"object {scope} {{")
        if start < 0:
            raise KeyError(f"object {scope} not found in {path}")
        depth = 0
        end = start
        for index in range(text.index("{", start), len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        text = text[start:end]

    pattern = re.compile(
        r"const\s+val\s+(\w+)\s*(?::\s*\w+\s*)?=\s*(0x[0-9A-Fa-f]+|\d+)\b"
    )
    return {m.group(1): int(m.group(2), 0) for m in pattern.finditer(text)}


def parse_kotlin_uuids(path):
    """Collect the GATT UUID constants from the Kotlin side."""
    out = {}
    pattern = re.compile(r'val\s+(\w+_UUID):\s*UUID\s*=\s*UUID\.fromString\("([^"]+)"\)')
    with open(path, encoding="utf-8") as fh:
        for match in pattern.finditer(fh.read()):
            out[match.group(1)] = match.group(2)
    return out


def parse_c_uuids(path):
    """Decode the NimBLE BLE_UUID128_INIT literals (little endian octets)."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    pattern = re.compile(r"UUID_(\w+)\s*=\s*\n?\s*BLE_UUID128_INIT\(([^)]*)\)")
    for match in pattern.finditer(text):
        octets = [int(b, 0) for b in (x.strip() for x in match.group(2).split(",")) if b]
        if len(octets) != 16:
            continue
        hexed = bytes(reversed(octets)).hex()
        out[match.group(1)] = "-".join(
            [hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32]]
        )
    return out


def main():
    for path in (C_HEADER, C_BLE, KT_FILE, KCONFIG, SCHEMA):
        if not os.path.isfile(path):
            print(f"error: missing {path}", file=sys.stderr)
            return 2

    c = {**parse_c_defines(C_HEADER), **parse_c_enums(C_HEADER)}
    kt = parse_kotlin_consts(KT_FILE)
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)

    print("=== sizes and framing ===")
    check("version", c["SKP_VERSION"], kt["VERSION"], schema["version"])
    check("headerSize", c["SKP_HEADER_SIZE"], kt["HEADER_SIZE"],
          schema["frame"]["headerSize"])
    check("maxPayload", c["SKP_MAX_PAYLOAD"], kt["MAX_PAYLOAD"],
          schema["frame"]["maxPayload"])
    for name, c_key, kt_key in (
        ("idSize", "SKP_ID_SIZE", "ID_SIZE"),
        ("keySize", "SKP_KEY_SIZE", "KEY_SIZE"),
        ("nonceSize", "SKP_NONCE_SIZE", "NONCE_SIZE"),
        ("tagSize", "SKP_TAG_SIZE", "TAG_SIZE"),
        ("sessionIdSize", "SKP_SESSION_ID_SIZE", "SESSION_ID_SIZE"),
        ("pseudonymSize", "SKP_PSEUDONYM_SIZE", "PSEUDONYM_SIZE"),
    ):
        check(name, c[c_key], kt[kt_key], schema["crypto"][name])

    print("\n=== advertising ===")
    check("manufacturerId", c["SKP_ADV_COMPANY_ID"], kt["MANUFACTURER_ID"],
          schema["ble"]["manufacturerId"])
    check("advMagic", c["SKP_ADV_MAGIC"], kt["ADV_MAGIC"], schema["ble"]["advMagic"])
    # The C payload includes the 2 byte company id; Android prepends it itself.
    check("advPayloadLength", c["SKP_ADV_PAYLOAD_SIZE"], kt["ADV_DATA_SIZE"] + 2,
          schema["ble"]["advPayloadLength"])
    for name, c_key, kt_key in (
        ("SCREEN_ON", "SKP_ADV_FLAG_SCREEN_ON", "FLAG_SCREEN_ON"),
        ("UNLOCKED", "SKP_ADV_FLAG_UNLOCKED", "FLAG_UNLOCKED"),
        ("PAIRING_MODE", "SKP_ADV_FLAG_PAIRING_MODE", "FLAG_PAIRING_MODE"),
        ("PAIRING_BEACON", "SKP_ADV_FLAG_PAIRING_BEACON", "FLAG_PAIRING_BEACON"),
    ):
        check(f"flag {name}", c[c_key], kt[kt_key], schema["advFlags"][name])

    print("\n=== door beacon (protocol-spec.md §2.4) ===")
    check("doorMagic", c["SKP_DOOR_MAGIC"], kt["DOOR_MAGIC"], schema["ble"]["doorMagic"])
    # As above: the C payload includes the company id, Android prepends it.
    check("doorPayloadLength", c["SKP_DOOR_PAYLOAD_SIZE"], kt["DOOR_DATA_SIZE"] + 2,
          schema["ble"]["doorPayloadLength"])
    check("doorIdLength", c["SKP_DOOR_ID_SIZE"], kt["DOOR_ID_SIZE"],
          schema["ble"]["doorIdLength"])
    for name, c_key, kt_key in (
        ("PAIRING", "SKP_DOOR_FLAG_PAIRING", "DOOR_FLAG_PAIRING"),
        ("ENROLLED", "SKP_DOOR_FLAG_ENROLLED", "DOOR_FLAG_ENROLLED"),
    ):
        check(f"door flag {name}", c[c_key], kt[kt_key], schema["doorFlags"][name])

    print("\n=== frame types ===")
    kt_types = parse_kotlin_consts(KT_FILE, scope="FrameType")
    for name, value in schema["frameTypes"].items():
        check(f"type {name}", c[f"SKP_FRAME_{name}"], kt_types[name], value)

    print("\n=== payload sizes ===")
    for name, value in schema["payloadSizes"].items():
        if value == 0:
            continue  # empty frames have no size constant
        check(f"size {name}", c[f"SKP_{name}_SIZE"], kt[f"{name}_SIZE"], value)

    print("\n=== error codes ===")
    kt_errors = parse_kotlin_consts(KT_FILE, scope="ErrorCode")
    for name, value in schema["errorCodes"].items():
        check(f"error {name}", c[f"SKP_ERR_{name}"], kt_errors[name], value)

    print("\n=== result codes ===")
    kt_unlock = parse_kotlin_consts(KT_FILE, scope="UnlockResult")
    for name, value in schema["unlockResults"].items():
        check(f"unlock {name}", c[f"SKP_UNLOCK_{name}"], kt_unlock[name], value)

    kt_pair = parse_kotlin_consts(KT_FILE, scope="PairResult")
    for name, value in schema["pairResults"].items():
        check(f"pair {name}", c[f"SKP_PAIR_{name}"], kt_pair[name], value)

    print("\n=== proximity / timing defaults (Kconfig vs schema) ===")
    kconfig = parse_kconfig_defaults(KCONFIG)
    for name, option in (
        ("nearDbm", "SMARTKEY_PROXIMITY_NEAR_DBM"),
        ("farDbm", "SMARTKEY_PROXIMITY_FAR_DBM"),
        ("window", "SMARTKEY_PROXIMITY_WINDOW"),
        ("minSamples", "SMARTKEY_PROXIMITY_MIN_SAMPLES"),
        ("pollMs", "SMARTKEY_PROXIMITY_POLL_MS"),
    ):
        value = schema["proximity"][name]
        check_pair(f"proximity {name}", kconfig.get(option), value)

    for name, option in (
        ("rssiEnterDbm", "SMARTKEY_RSSI_ENTER_DBM"),
        ("rssiExitDbm", "SMARTKEY_RSSI_EXIT_DBM"),
        ("rssiExitSamples", "SMARTKEY_RSSI_EXIT_SAMPLES"),
        ("sessionTtlSeconds", "SMARTKEY_SESSION_TTL_S"),
        ("handshakeTimeoutMs", "SMARTKEY_HANDSHAKE_TIMEOUT_MS"),
        ("pairingWindowSeconds", "SMARTKEY_PAIRING_WINDOW_S"),
        ("unlockMinIntervalMs", "SMARTKEY_UNLOCK_MIN_INTERVAL_MS"),
    ):
        check_pair(f"timing {name}", kconfig.get(option), schema["timing"][name])

    # The three distances must stay ordered, or the LED logic is incoherent.
    near = schema["proximity"]["nearDbm"]
    far = schema["proximity"]["farDbm"]
    enter = schema["timing"]["rssiEnterDbm"]
    disconnect = schema["timing"]["rssiExitDbm"]
    check_true("near > far (hysteresis band is positive)", near > far)
    check_true("connect threshold is looser than the LED threshold", enter < near)
    check_true("disconnect is the loosest of all", disconnect < far)

    # The phone beacon and the door beacon share a manufacturer id and differ
    # only by the magic byte. If these ever collide, each parser would accept
    # the other's advertisements and the door would try to range itself.
    check_true(
        "phone and door beacons have distinct magic bytes",
        schema["ble"]["advMagic"] != schema["ble"]["doorMagic"],
    )
    # The door beacon must stay far slower than the phone beacon, or it would
    # compete for the radio with the scanning that actually has to be fast.
    check_true(
        "door beacon is slower than the phone beacon",
        schema["ble"]["doorBeaconIntervalMs"] > schema["ble"]["advertisingIntervalMs"],
    )
    door_interval = kconfig.get("SMARTKEY_DOOR_BEACON_INTERVAL_MS")
    check_pair(
        "ble doorBeaconIntervalMs", door_interval, schema["ble"]["doorBeaconIntervalMs"]
    )

    for name, option in (
        ("departDbm", "SMARTKEY_REARM_DEPART_DBM"),
        ("absentMs", "SMARTKEY_REARM_ABSENT_MS"),
        ("maxHoldMs", "SMARTKEY_REARM_MAX_HOLD_MS"),
    ):
        check_pair(f"rearm {name}", kconfig.get(option), schema["rearm"][name])

    # Departure must be unambiguous: if the phone could be judged "gone" while
    # still close enough to hold a session, the door would re-arm and relight
    # while the user is still standing in front of it.
    depart = schema["rearm"]["departDbm"]
    check_true("post-unlock departure is looser than the LED far threshold",
               depart < far)
    check_true("post-unlock departure is not stricter than the disconnect level",
               depart >= disconnect)
    # The absolute cap must outlast the absence rule, otherwise the cap would
    # always fire first and departure detection would be dead code.
    check_true("re-arm cap outlasts the absence timeout",
               schema["rearm"]["maxHoldMs"] > schema["rearm"]["absentMs"])

    print("\n=== GATT UUIDs ===")
    c_uuids = parse_c_uuids(C_BLE)
    kt_uuids = parse_kotlin_uuids(KT_FILE)
    for name, c_name, kt_name in (
        ("service", "SERVICE", "SERVICE_UUID"),
        ("control", "CONTROL", "CONTROL_UUID"),
        ("status", "STATUS", "STATUS_UUID"),
        ("pairing", "PAIRING", "PAIRING_UUID"),
    ):
        expected = (
            schema["ble"]["service"] if name == "service"
            else schema["ble"]["characteristics"][name]
        )
        check(f"uuid {name}", c_uuids.get(c_name), kt_uuids.get(kt_name), expected)

    print(f"\n{checks} constants compared, {len(failures)} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
