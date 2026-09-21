# SmartKey

Walk up to your door with your phone in your pocket, an LED lights up to say you
are recognised, press the button, and Home Assistant opens the door over Zigbee.

```
          BLE 5 (LE 1M, legacy advertising)              Zigbee 3.0 (802.15.4)
 ┌────────────┐   adv: rolling pseudonym    ┌──────────────┐   On/Off command   ┌───────────────┐
 │ Galaxy S26 │ ─────────────────────────►  │  ESP32-C5    │ ─────────────────► │ Home Assistant│
 │  (app)     │                             │  door unit   │                    │  (ZHA coord.) │
 │ peripheral │ ◄─── GATT: SmartKey ───────►│   central    │                    └───────────────┘
 │ GATT server│      presence handshake     │ GATT client  │
 └────────────┘                             └──────────────┘
                                              LED  +  button
```

| Folder | Contents |
|--------|----------|
| [`shared-protocols/`](shared-protocols/) | **Read this first.** Wire protocol, security model, machine readable schema and the golden test vectors both sides are tested against |
| [`esp32-firmware/`](esp32-firmware/) | ESP-IDF firmware for the ESP32-C5 door unit |
| [`android-app/`](android-app/) | Kotlin app for Android 16 (API 36) |

## How it meets the requirements

| Requirement | How |
|-------------|-----|
| Detect the user approaching | The phone advertises a rolling BLE beacon; the door unit scans continuously and connects on a match |
| LED on in **under a second** | Measured budget ≈ 210 ms typical / 610 ms worst case — see `shared-protocols/protocol-spec.md` §8 |
| LED on **only when the phone is near the board** | Median-filtered RSSI with hysteresis; a single spike can never light it, and the button follows the same condition — §8.4 |
| Authentication between phone and door | **Mutual** HMAC-SHA256 challenge/response over a per-connection transcript, with a long term key established by X25519 + a pairing code |
| Button opens the door over Zigbee | The unit is a Zigbee 3.0 On/Off switch end device that HA binds to the door relay |
| Privacy | The beacon identifier rotates every 15 s, so the user cannot be tracked |

## Getting started

### 1. Run the checks (no hardware needed)

```bash
./run_checks.sh
```

This runs the reference crypto self test, regenerates the shared vectors,
verifies that the C, Kotlin and JSON definitions agree, and builds + runs the
firmware protocol unit tests natively.

### 2. Build and flash the firmware

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

### 5. Connect Home Assistant

Put ZHA into "add device" mode; the unit joins as `SmartKey / SK-DOOR-C5`. Bind
its endpoint 1 On/Off **client** cluster to your door relay, or react to the
`zha_event` it emits.

## Serial console

Connect with `idf.py monitor` and type `help`:

| Command | Effect |
|---------|--------|
| `status` | Lock id, presence state, Zigbee state, active session, proximity |
| `rssi [seconds]` | Live raw + filtered RSSI, for tuning the LED distance |
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

## Changing the protocol

1. Edit `shared-protocols/protocol-spec.md` and `schema/smartkey-protocol.json`.
2. Update `tools/skp_crypto.py` if the crypto changed, then regenerate:
   `python3 shared-protocols/tools/gen_test_vectors.py`.
3. Update the C and Kotlin constants.
4. Run `./run_checks.sh` — it fails loudly if the three sides disagree.
5. Bump the version byte and `shared-protocols/CHANGELOG.md`.
