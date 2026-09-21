# SmartKey door unit firmware

ESP-IDF application for the **ESP32-C5** (BLE 5 + 802.15.4 in one chip, which is
why this variant was chosen: no external radio is needed for Zigbee).

## Layout

```
main/                       application: state machine, console, Kconfig
components/
  smartkey_proto/           SKP1 frame codec + crypto (portable, host testable)
  smartkey_store/           NVS credential storage
  smartkey_io/              LED and debounced button
  smartkey_ble/             NimBLE scanner, GATT client, pairing responder
  smartkey_zigbee/          Zigbee On/Off client (stubbed when disabled)
test/host/                  native unit tests against the shared golden vectors
```

The protocol itself is specified in [`../shared-protocols/`](../shared-protocols/).

## Build

```bash
. ~/esp/v5.5.1/esp-idf/export.sh
idf.py set-target esp32c5
idf.py build flash monitor
```

### ESP-IDF version

**Requires ESP-IDF 5.5.x.** The requirement is pinned to `>=5.5.0,<6.0.0` in
`main/idf_component.yml`, and the upper bound is deliberate.

ESP-IDF 6.x bundles **mbedTLS 4.x**, which deletes the legacy crypto APIs:
`mbedtls/md.h`, `mbedtls/ecdh.h` and `mbedtls/ecp.h` are gone and everything
moves behind PSA Crypto (TF-PSA-Crypto). `smartkey_crypto.c` uses all three.

An upgrade was attempted and reverted. Porting the firmware to PSA is
straightforward — `psa_mac_compute()` for HMAC, `psa_raw_key_agreement()` with
`PSA_ALG_ECDH` + `PSA_ECC_FAMILY_MONTGOMERY` for X25519 — and it *compiled and
linked cleanly for the ESP32-C5*. It was reverted because of the **host tests**:

* Espressif's vendored mbedTLS 4 is not self-contained. `bignum.c` includes
  `<mbedtls/bignum.h>`, which exists only in `components/mbedtls/port/include`
  as an `#include_next` shim that also pulls in `sdkconfig.h`. Both are
  artefacts of the IDF component build, so `add_subdirectory()` on that tree
  cannot work.
* Without a host build there is no way to run the **golden vectors** in
  `shared-protocols/test-vectors/`, and those vectors are the only thing that
  proves the firmware and the Android app still derive identical keys.

Shipping a crypto rewrite that has never been checked against the vectors would
risk a silent interop break with every paired phone, so the change was backed
out rather than merged unverified.

**To retry the upgrade**, make the host tests work first, in this order:

1. Point `MBEDTLS_DIR` at an *upstream* mbedTLS 4.x checkout (with submodules)
   rather than the IDF copy, and confirm `run_tests.sh` builds.
2. Re-apply the PSA port to `smartkey_crypto.c`, keeping the 3.x path behind
   `#if MBEDTLS_VERSION_MAJOR >= 4` so 5.5 still builds.
3. Confirm **all** golden vectors pass on the PSA path — especially
   `skc_pseudonym`, the handshake tags and the pairing derivation.
4. Only then bump the bound in `main/idf_component.yml`.

Two smaller v6 changes are already in place and are harmless on 5.5:
`smartkey_io` depends on `esp_driver_gpio` rather than the old monolithic
`driver` component, which 6.x no longer re-exports.

## Unit tests (no hardware)

`smartkey_proto` deliberately has no ESP-IDF dependency, so it compiles on the
development machine against the mbedTLS that ships with ESP-IDF:

```bash
./test/host/run_tests.sh
```

119 checks compare every frame encoding, sub key, tag, pseudonym and the X25519
pairing exchange against `../shared-protocols/test-vectors/`, which the Android
tests also use, plus the proximity filter that gates the LED. If either side
drifts from the spec, these tests fail.

After changing the protocol, refresh the generated header:

```bash
python3 ../shared-protocols/tools/gen_test_vectors.py
python3 test/host/sync_vectors.py
```

## Configuration

`idf.py menuconfig` → **SmartKey door unit**:

| Option | Default | Notes |
|--------|---------|-------|
| `SMARTKEY_LED_GPIO` | 8 | Permission LED; `..._ACTIVE_LOW` for boards that sink the LED |
| `SMARTKEY_BUTTON_GPIO` | 9 | Button to ground, internal pull-up |
| `SMARTKEY_RSSI_ENTER_DBM` | -70 | Start the *connection* above this (~2–3 m) |
| `SMARTKEY_RSSI_EXIT_DBM` | -85 | Drop the connection entirely below this |
| `SMARTKEY_PROXIMITY_NEAR_DBM` | -60 | **LED on** above this filtered level (~1 m) |
| `SMARTKEY_PROXIMITY_FAR_DBM` | -72 | LED off below this; the gap is hysteresis |
| `SMARTKEY_PROXIMITY_WINDOW` | 5 | Samples in the median filter |
| `SMARTKEY_PROXIMITY_MIN_SAMPLES` | 3 | Required before the LED may light |
| `SMARTKEY_PROXIMITY_POLL_MS` | 250 | How fast the LED follows the user |
| `SMARTKEY_SESSION_TTL_S` | 10 | Keep-alive window |
| `SMARTKEY_MAX_USERS` | 8 | Credential slots |
| `SMARTKEY_PAIRING_CODE` | *(empty)* | Empty = random code per window, printed on the console |
| `SMARTKEY_REQUIRE_PHONE_UNLOCKED` | n | Ignore phones whose keyguard is locked |
| `SMARTKEY_ZIGBEE_ENABLED` | y | Turn off to test presence without a coordinator |
| `SMARTKEY_ZIGBEE_USE_TOGGLE` | n | Send Toggle instead of On |

## Timing

The latency critical path — advertisement match, connect, handshake, LED — runs
entirely inside the NimBLE host task, and GATT handles are cached per peer so
reconnects skip discovery. The measured budget is in
[`../shared-protocols/protocol-spec.md`](../shared-protocols/protocol-spec.md) §8;
the firmware logs the actual time with every grant:

```
I (12345) sk_ble: access granted to 'Felix phone' in 214 ms (rssi -54 dBm)
```

## The LED means "you are at the door"

Authentication and proximity are two separate conditions. The LED (and the
button) require **both**:

| state | meaning | LED | button |
|-------|---------|-----|--------|
| `LINGERING` | authorised, but not close enough | off | refused |
| `GRANTED` | authorised **and** measured next to the board | on | works |

Distance comes from the **median** of the last 5 RSSI samples, not a single
reading — raw BLE RSSI swings 15–20 dB packet to packet, so one sample would
both false-trigger from across a room and flicker. Samples are collected from
advertisements during the approach as well as from the live connection, so the
filter is already primed when the handshake finishes and the LED is immediate.

### Calibrating your installation

Walls, mounting height and phone model all shift the numbers, so measure rather
than guess:

```
smartkey> rssi 30
  time     raw        filtered   verdict
    0.0s   -78 dBm    -80 dBm    far  (led off)
    ...
   12.0s   -57 dBm    -58 dBm    NEAR (led on)
```

Stand where the LED *should* come on, read the filtered column, then set
`SMARTKEY_PROXIMITY_NEAR_DBM` a few dB below it and `..._FAR_DBM` about 12 dB
below that. `status` shows the currently compiled gate.

## The door goes idle once it has been opened

`CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK`, **default on**.

A successful unlock drops the session, closes the link and turns the LED off.
"One approach, one opening" — the LED stops inviting presses once the door is
already open. A *failed* unlock keeps the session, because the user still needs
the LED and the button to retry a relay that did not fire.

### Why a plain disconnect would not work

The phone that just opened the door is still in the user's hand, 30 cm from the
reader, still advertising. Simply going idle is undone almost immediately — the
scanner sees the same phone, reconnects and relights the LED within a few hundred
milliseconds. A fixed cooldown has the identical defect a few seconds later.

So re-arming is **departure based**. After an unlock that phone is ignored until:

| rule | default | meaning |
|---|---|---|
| it is seen further away | `REARM_DEPART_DBM` = −75 dBm | the user stepped away |
| it stops being seen | `REARM_ABSENT_MS` = 3000 ms | walked through the door |
| the cap expires | `REARM_MAX_HOLD_MS` = 60000 ms | safety valve |

The cap is not optional in practice: a phone left on a desk beside the reader is
permanently close and permanently visible, so neither of the first two rules
would ever fire and that user would be locked out indefinitely.

The hold is keyed on the BLE address, so a colleague arriving with you is
unaffected, and it is cleared on pairing, revocation and factory reset.

`status` shows the configured thresholds and whether a hold is currently active.

## Door beacon (optional recovery path)

`CONFIG_SMARTKEY_DOOR_BEACON_ENABLE`, **default off**.

The normal flow needs the Android `PresenceService` to stay alive. That is not
guaranteed — vendor battery managers (Samsung's "Deep Sleeping" list especially)
stop foreground services anyway, and when they do presence dies *silently*: the
user finds out while standing at a door that will not light up.

With the beacon enabled the door advertises a non-connectable, **static**
identifier. The app registers a `PendingIntent` scan for it, which lives in the
Bluetooth stack rather than in the app process, so it survives the process being
killed and restarts the service when a door is seen.

This is a **safety net, not the fast path** — a low-power scan takes seconds. The
sub-second LED still comes from the door connecting to the phone's beacon.

Why static here but rotating on the phone: a fixed byte pattern can be matched by
the Bluetooth *controller* (offloaded filtering) so the phone's CPU stays asleep,
and a door bolted to a wall has no location privacy to lose. The phone — which
does — keeps its 15 s rotating pseudonym.

### Verifying beacon/scan coexistence

The beacon and the scanner share one radio. Scanning is the half that must stay
fast: every advertisement missed is an RSSI sample the proximity filter never
receives. **Measure this on your board before trusting it.**

```
# 1. Baseline, with the beacon still disabled.
idf.py build flash monitor
smartkey> scanstats 30
  window          : 30.0 s
  door beacon     : off
  from paired phone: 291  (9.7/s)  <- feeds the LED filter

# 2. Enable it and repeat.
idf.py menuconfig    # SmartKey door unit -> Presence and timing -> door beacon
idf.py build flash monitor
smartkey> scanstats 30
  door beacon     : ON
  from paired phone: 27?  (?.?/s)
```

Keep a paired phone in range and stationary for both runs.

**Interpreting it:** a phone advertises at ~10/s. If the "from paired phone" rate
stays above ~5/s the filter still fills its window well inside the 1 s budget and
the beacon is safe to keep on. A large drop means the radio is being starved —
either raise `SMARTKEY_DOOR_BEACON_INTERVAL_MS`, keep
`SMARTKEY_DOOR_BEACON_IDLE_ONLY=y`, or leave the beacon off.

Then confirm the actual behaviour end to end: force-stop the app from Android
settings, walk up to the door, and check that the service restarts on its own.

## Production hardening

Before shipping, enable in `menuconfig`:

* **Flash encryption** (release mode) and **NVS encryption** — otherwise the
  long term keys can be read out of flash (security-model.md, threat A6).
* **Secure boot v2**.
* Replace the `0xFFFF` test company id in the protocol with a registered one.
