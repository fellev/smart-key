# SmartKey Shared Protocols

This folder is the **single source of truth** for everything that crosses the boundary
between the ESP32-C5 door unit (firmware) and the Android application.

| File | Contents |
|------|----------|
| `protocol-spec.md` | Runtime protocol: BLE roles, advertising beacon, GATT service, presence handshake frames, byte layouts |
| `pairing-spec.md` | Out-of-band provisioning of the long term key (X25519 + pairing code) |
| `security-model.md` | Threat model, what is / is not mitigated, key hierarchy |
| `schema/smartkey-protocol.json` | Machine readable constants (UUIDs, frame ids, sizes, timings) |
| `test-vectors/handshake.json` | Golden vectors for the presence handshake (used by both unit test suites) |
| `test-vectors/pairing.json` | Golden vectors for the pairing key derivation |
| `tools/gen_test_vectors.py` | Regenerates the vectors above (pure python, `pip install cryptography`) |
| `CHANGELOG.md` | Protocol version history |

## Roles at a glance

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

Why the phone is the **peripheral** (advertiser) and the ESP32 is the **central** (scanner):

* Android background BLE *scanning* is throttled by the OS (opportunistic / batched), which
  makes the "< 1 s LED" requirement impossible to hit reliably. Android background
  *advertising* from a foreground service is not throttled.
* The door unit is mains powered, so continuous `LOW_LATENCY` scanning costs nothing.
* The ESP32 therefore owns the timing budget end-to-end (see `protocol-spec.md` §8).

## Protocol version

`SKP1` — wire version byte `0x01`. Any incompatible change bumps the version byte and the
`CHANGELOG.md`.
