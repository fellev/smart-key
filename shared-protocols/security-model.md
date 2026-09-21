# SmartKey Security Model

## 1. Assets

| asset | why it matters |
|-------|----------------|
| `LTK` (per lock+user) | Holding it lets a phone light the LED — the prerequisite for unlocking |
| Physical button access | The button is the actual unlock trigger |
| Zigbee network key | Managed by Home Assistant / the Zigbee stack, out of scope here |
| User location privacy | A phone that advertises must not be trackable |

## 2. Adversaries

| # | adversary | capability |
|---|-----------|-----------|
| A1 | Passive radio eavesdropper | Records all BLE traffic near the door |
| A2 | Active radio attacker | Replays / injects BLE frames, spoofs advertisements |
| A3 | Relay attacker | Two radios relaying BLE frames between a distant phone and the door |
| A4 | Stalker | Follows advertising payloads to track a person |
| A5 | Thief with the phone | Has the unlocked/locked handset in hand |
| A6 | Attacker with physical access to the door unit | Can read flash, press the button |

## 3. Mitigations

| threat | mitigation |
|--------|-----------|
| A1 learning the key | Only HMAC tags and random nonces are ever transmitted; the `LTK` never leaves either device after pairing |
| A2 replay | Both `nonce_l` and `nonce_p` are fresh 128-bit random values per connection and both are in the transcript; a replayed `AUTH` never matches the lock's fresh `nonce_l` |
| A2 impersonating the lock | Mutual authentication: the phone verifies `tag_l` before treating the session as real |
| A2 tag reflection | Domain separation bytes `0x01`/`0x02`/`0x03`/`0x10` in every HMAC input |
| A3 relay | **Partially mitigated.** RSSI thresholds + the requirement that a *human presses the physical button at the door* means a relay alone cannot open anything. A relay plus an accomplice at the door is out of scope for v1 (would need UWB / BLE channel sounding, which the C5 does not provide) |
| A4 tracking | Rolling 6-byte pseudonym (15 s epochs) + Android's resolvable private address. No stable identifier is broadcast |
| A5 stolen phone | Keys live in the Android Keystore (StrongBox when present) and cannot be exported; the app can require a device credential before enabling presence, and `flags.UNLOCKED` lets the lock optionally require an unlocked phone (`CONFIG_SMARTKEY_REQUIRE_PHONE_UNLOCKED`) |
| A6 flash extraction | Flash encryption + NVS encryption in production builds; each lock has unique keys, so one compromised lock does not affect others |
| Timing side channels | All tag comparisons use constant-time compare (`mbedtls_ct_memcmp` / `MessageDigest.isEqual`) |
| Brute force on the pairing code | The code only enters the KDF; a wrong guess fails the confirmation. 3 attempts then pairing mode exits, and pairing mode itself needs a 5 s physical button hold |
| Unlock spam | Rate limit: at most 1 unlock per `CONFIG_SMARTKEY_UNLOCK_MIN_INTERVAL_MS` (default 2000 ms) and 10 per minute |

## 4. Why no BLE bonding / LE Secure Connections?

1. It would cost 300–800 ms extra on first contact, and Android's bonding cache is flaky
   across app reinstalls — both fatal for the < 1 s requirement.
2. LESC "Just Works" gives no MITM protection anyway, and numeric comparison needs a UI on
   both ends at every reconnect.
3. The application layer already provides mutual authentication and a session key.

Consequence: the BLE link itself is untrusted, so **no secret is ever sent over it**. Only
nonces and MAC tags travel on the wire.

## 5. Explicit non-goals for v1

* Resistance to a two-person relay attack at the door.
* Confidentiality of the fact that *a* SmartKey user is nearby (the beacon is unencrypted,
  though unlinkable).
* Protection against a malicious Home Assistant / Zigbee coordinator.
* Remote (off-site) unlocking.

## 6. Audit / logging

The lock keeps the last 32 events in RTC memory (survives reboot, not power loss):
timestamp (uptime), `user_id[0..3]`, event (`GRANTED`, `AUTH_FAILED`, `UNLOCK`, `PAIRED`,
`REVOKED`), result. They can be dumped over the serial console with `log`.
