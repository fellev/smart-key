# SmartKey

Walk up to your door with your phone in your pocket, an LED lights up to say you
are recognised, press the button, and Home Assistant opens the door over Zigbee.

```
          BLE 5 (LE 1M, legacy advertising)              Zigbee 3.0 (802.15.4)
 ┌────────────┐                             ┌──────────────┐   On/Off command   ┌───────────────┐
 │ Galaxy S26 │ ◄── adv: static lock id ─── │  ESP32-C5    │ ─────────────────► │ Home Assistant│
 │  (app)     │     (door beacon, §2.4)     │  door unit   │                    │  (ZHA coord.) │
 │            │                             │              │                    └───────────────┘
 │ peripheral │ ─── adv: rolling pseudonym ►│   central    │
 │ GATT server│                             │ GATT client  │
 │            │ ◄── GATT: presence ────────►│              │
 └────────────┘     handshake               └──────────────┘
                                              LED  +  button
```

Both sides advertise, for opposite reasons:

* **Phone → door** carries a **rotating** pseudonym (new every 15 s) so the phone
  cannot be tracked. This is what the door detects and connects to.
* **Door → phone** carries a **static** lock id. A door bolted to a wall has no
  location privacy to lose, and a fixed byte pattern is the only kind Android can
  match inside the Bluetooth controller — which is what lets the phone stay
  radio-silent until a door is actually nearby.

The session is always established **door → phone**: the mains-powered side does
the expensive continuous scanning.

| Folder | Contents |
|--------|----------|
| [`shared-protocols/`](shared-protocols/) | **Read this first.** Wire protocol, security model, machine readable schema and the golden test vectors both sides are tested against |
| [`esp32-firmware/`](esp32-firmware/) | ESP-IDF firmware for the ESP32-C5 door unit |
| [`android-app/`](android-app/) | Kotlin app for Android 16 (API 36) |

## How it meets the requirements

| Requirement | How |
|-------------|-----|
| Detect the user approaching | The phone advertises a rolling BLE beacon; the mains-powered door unit scans continuously and connects on a match |
| LED on in **under a second** | ≈ 210 ms typical / 610 ms worst case — but this is a *guarantee* only in `ALWAYS_ADVERTISE` mode. See the note below — §8, §8.5 |
| LED on **only when the phone is near the board** | Median-filtered RSSI with hysteresis; a single spike can never light it, and the button follows the same condition — §8.4 |
| Authentication between phone and door | **Mutual** HMAC-SHA256 challenge/response over a per-connection transcript, with a long term key established by X25519 + a pairing code |
| Button opens the door over Zigbee | The unit is a Zigbee 3.0 On/Off switch end device that HA binds to the door relay |
| Privacy | The phone's beacon identifier rotates every 15 s, and by default it transmits nothing at all until a door is heard |
| Door goes idle once opened | A successful unlock releases the session and turns the LED off; the same phone is refused until it is seen to leave — §9.1 |

### The one requirement trade-off worth knowing

The phone has two presence modes, and the default is **not** the one that
guarantees the sub-second LED:

| | `LISTEN_FIRST` (default) | `ALWAYS_ADVERTISE` |
|---|---|---|
| phone transmits | **nothing** until it hears a door | continuously, every 100 ms |
| LED latency | best-effort, ~2–6 s from first beacon | **< 1 s, guaranteed** |
| battery | lower, nothing at all away from doors | ~1 %/day |

`LISTEN_FIRST` was chosen as the default because "my phone broadcasts all day and
all night" is a real cost, and in practice the delay is usually much smaller than
the figures suggest: the door beacon carries far beyond LED range, so the phone
wakes while you are still walking up and the wake-up overlaps the approach.

If you need the hard sub-second guarantee, switch the mode in the app and accept
the continuous transmission. Nothing else changes — no re-pairing, no firmware
change. Details in `shared-protocols/protocol-spec.md` §8.5.

## What the LED means

Exactly one thing: **the button will work right now.** That is a deliberately
narrow promise, and it is why there are separate states either side of it.

```
  IDLE ──hears phone──► CONNECTING ──► HANDSHAKING ──authenticated──┐
    ▲                                                              │
    │                                     ┌── median ≥ −60 dBm ────┤
    │                                     ▼                        ▼
    │                                  GRANTED  ◄──────────►  LINGERING
    │                              (LED on, button      (authenticated but
    │                               armed)               too far: LED OFF,
    │                                     │               button refused)
    │                              button │
    │                                     ▼
    │                                 UNLOCKING ──zigbee ack──► release
    └──────────────────────────────────────────────────────────────┘
                     (LED off; this phone held until it leaves)
```

Three things fall out of this that are easy to get wrong:

**Authorisation and proximity are separate.** `LINGERING` means "I know who you
are, but you are not at the door" — LED off and the button *refused*. The link
is kept alive, so stepping closer re-lights in ~250 ms with no new handshake.
Authorisation is cryptographic and binary; proximity is a noisy physical
measurement. Keeping them apart is what lets the LED mean one unambiguous thing.

**Distance uses a median, not a single reading.** Raw BLE RSSI swings 15–20 dB
packet to packet. A median of 5 samples rejects outliers in *both* directions, so
one spike can't grant from across the room and one dropout can't cut you off
mid-use. Three deliberately different thresholds: connect at −70 dBm (early, to
hide the handshake), LED at −60 dBm (only at the door), disconnect at −85 dBm
(late, so re-entry is free).

**Opening the door ends the session.** Otherwise the LED keeps inviting presses
after the door is already open. Note that *releasing alone would do nothing* —
the phone that just unlocked is still in your hand 30 cm away, so the scanner
would reconnect and relight within a few hundred milliseconds. Re-arming is
therefore based on **departure, not a timer**: that phone is ignored until it is
seen further away (−75 dBm), stops being seen (3 s), or hits a 60 s cap. The cap
matters — a phone left on a desk beside the reader would otherwise lock that user
out forever.

## Getting started

### 1. Run the checks (no hardware needed)

```bash
./run_checks.sh
```

Five stages, all of which must pass:

| | Stage | Current |
|---|---|---|
| 1 | Python reference crypto self test | all reference vectors pass |
| 2 | Regenerate the shared golden vectors | in sync |
| 3 | C / Kotlin / JSON constants agree | 88 constants, 0 mismatches |
| 4 | Firmware protocol tests (native) | 163 checks, 0 failures |
| 5 | Android unit tests (JVM) | 67 tests, 0 failures |

Stage 3 also checks *invariants*, not just equality — e.g. that the LED-on
threshold sits between the connect and disconnect thresholds, and that the phone
and door beacon magic bytes cannot collide. Those catch a broken configuration
that is individually consistent but collectively nonsense.

Stage 5 needs a JDK. If one is not on `PATH` the script looks in
`~/tools/jdk-17`; otherwise it tells you how to get one.

### 2. Build and flash the firmware

**ESP-IDF 5.5.x is required** — the bound is pinned in
`esp32-firmware/main/idf_component.yml`. ESP-IDF 6.x ships mbedTLS 4.x, which
removes the crypto APIs this project uses; see the "ESP-IDF version" section of
[`esp32-firmware/README.md`](esp32-firmware/README.md) before attempting an
upgrade.

```bash
. ~/esp/v5.5.1/esp-idf/export.sh
cd esp32-firmware
idf.py set-target esp32c5
idf.py menuconfig          # "SmartKey door unit" -> GPIOs, RSSI thresholds, ...
idf.py build flash monitor
```

Default wiring: LED on `GPIO8`, button from `GPIO9` to ground (internal pull-up).

### 3. Build the app

Open `android-app/` in Android Studio and run it on the phone. It needs the
Bluetooth advertise/connect/scan and notification permissions.

### 4. Pair

1. Hold the button on the door unit for 5 s — the LED blinks at 2 Hz and the
   pairing code is printed on the serial console (or type `pair` there).
2. In the app, tap **Pair a door**, enter the 8 digit code and a name.
3. Turn presence on. The LED now lights whenever you approach.

The code is never transmitted: it is folded into the key derivation, so a wrong
code silently produces a *different* long term key and the confirmation fails.
Three attempts, then the window closes.

### 5. Calibrate the LED distance

**Do this once per installation.** The −60 dBm default is a reasonable starting
point, but walls, mounting height and phone model shift RSSI significantly.

```
smartkey> rssi 30
  time     raw        filtered   verdict
    0.0s   -78 dBm    -80 dBm    far  (led off)
   12.0s   -57 dBm    -58 dBm    NEAR (led on)
```

Stand where the LED *should* come on, read the **filtered** column, then set
`SMARTKEY_PROXIMITY_NEAR_DBM` a few dB below it and `..._FAR_DBM` about 12 dB
below that.

If you enable the door beacon, also run `scanstats 30` before and after to
confirm the beacon is not starving the scanner — the beacon and the scan share
one radio, and every advertisement missed is an RSSI sample the LED filter never
sees.

### 6. Connect Home Assistant

Put ZHA into "add device" mode; the unit joins as `SmartKey / SK-DOOR-C5`. Bind
its endpoint 1 On/Off **client** cluster to your door relay, or react to the
`zha_event` it emits.

## Serial console

Connect with `idf.py monitor` and type `help`:

| Command | Effect |
|---------|--------|
| `status` | Lock id, presence state, Zigbee state, active session, proximity, re-arm hold |
| `rssi [seconds]` | Live raw + filtered RSSI, for tuning the LED distance |
| `scanstats [seconds]` | Measured advertisement reception rate, for checking beacon/scan coexistence |
| `users` | List the paired phones |
| `pair` | Open a pairing window |
| `revoke <slot>` / `enable <slot>` | Disable or re-enable a phone |
| `forget <slot>` | Erase one credential |
| `reset` | Erase everything and reboot |

Holding the button for 10 s performs the same factory reset.

## Security in one paragraph

No secret ever travels over the air: only random nonces and HMAC tags. Both
sides authenticate each other, so a fake door unit cannot make the app reveal
anything and a fake phone cannot light the LED. The physical button is the
actual unlock trigger, which is what keeps a pure relay attack from opening the
door. Full analysis, including what is **not** covered, is in
[`shared-protocols/security-model.md`](shared-protocols/security-model.md).

**The honest limitation:** RSSI is a proximity *heuristic*, not a distance
measurement. The median filter genuinely stops the "LED lights from across the
room" problem, but an attacker with a high-gain antenna can still forge a strong
signal. That is precisely why the button remains the actual trigger — proximity
decides whether the button is *armed*, never whether the door opens. Real
distance bounding needs UWB or BLE channel sounding, which the C5 does not have.

## Changing the protocol

1. Edit `shared-protocols/protocol-spec.md` and `schema/smartkey-protocol.json`.
2. Update `tools/skp_crypto.py` if the crypto changed, then regenerate:
   `python3 shared-protocols/tools/gen_test_vectors.py`.
3. Update the C and Kotlin constants.
4. Run `./run_checks.sh` — it fails loudly if the three sides disagree.
5. Bump `shared-protocols/CHANGELOG.md`, and the version byte **only if the wire
   format actually changed**.

Point 5 matters: the protocol is at **1.4.0** but the version byte is still
`0x01`, because every release since 1.0.0 has been additive or door-local. The
door beacon added a *new* advertisement type rather than changing the existing
one, so old and new builds of either side interoperate in all four
combinations. Reserve a version bump for changes that genuinely break that.
