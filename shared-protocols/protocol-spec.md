# SmartKey Runtime Protocol — `SKP1`

Wire version: `0x01`. All multi-byte integers are **little endian** unless stated otherwise.
All cryptographic primitives are from the SHA-256 family.

---

## 1. Identities and keys

| Name | Size | Lives on | Description |
|------|------|----------|-------------|
| `lock_id` | 16 B | both | Random UUID of the door unit, created at first boot, exported during pairing |
| `user_id` | 16 B | both | Random UUID of the phone credential, created by the app at first launch |
| `LTK` | 32 B | both | Long term shared secret for this (lock, user) pair. Established by `pairing-spec.md` |
| `K_beacon` | 32 B | both | `HKDF(LTK, info="SKP1-beacon")` — derives the rolling advertising pseudonym |
| `K_auth` | 32 B | both | `HKDF(LTK, info="SKP1-auth")` — handshake HMAC key |
| `K_sess` | 32 B | both (ephemeral) | Per-session key, derived during the handshake |

Sub-key derivation (both sides, done once after pairing and cached):

```
K_beacon = HKDF-SHA256(ikm = LTK, salt = lock_id || user_id, info = "SKP1-beacon", L = 32)
K_auth   = HKDF-SHA256(ikm = LTK, salt = lock_id || user_id, info = "SKP1-auth",   L = 32)
```

`HKDF-SHA256` is RFC 5869 (extract-then-expand).

---

## 2. BLE roles

| | Android phone | ESP32-C5 door unit |
|---|---|---|
| GAP role | Peripheral (connectable advertiser) | Central (active scanner, initiator) |
| GATT role | Server | Client |
| Duty cycle | Advertise from a foreground service | Scan continuously (mains powered) |

### 2.1 Advertising (phone → door unit)

Legacy connectable advertising (`ADV_IND`), PHY LE 1M, so that any ESP32 variant can see it.

* Advertising interval: **100 ms** (`ADVERTISE_MODE_LOW_LATENCY`).
* TX power: `ADVERTISE_TX_POWER_MEDIUM` (tuned per install, see §8.3).
* Payload: a single **Manufacturer Specific Data** AD structure.

```
AD type 0xFF, Company ID 0xFFFF   (0xFFFF = "for testing", replace before production)

 offset size  field
   0      2   company_id            = 0xFFFF            (LE, part of the AD structure)
   2      1   skp_magic             = 0x4B  ('K')
   3      1   skp_version           = 0x01
   4      1   flags                 (see below)
   5      6   pseudonym[6]          rolling, see §2.2
  11      1   battery_pct           0..100, 0xFF = unknown
                                                         total AD payload = 12 bytes
```

`flags` bit field:

| bit | meaning |
|-----|---------|
| 0 | `SCREEN_ON` — phone display is on (hint that the user is actively approaching) |
| 1 | `UNLOCKED` — device is user-authenticated (keyguard not locked) |
| 2 | `PAIRING_MODE` — the app is in pairing mode, see `pairing-spec.md` |
| 3..7 | reserved, must be 0 |

The whole structure fits in the 31-byte legacy advertising PDU together with the flags AD
structure and a short local name.

### 2.2 Rolling pseudonym

A static advertising payload would let anyone track the user, so the identifier rotates.

```
epoch     = floor(unix_time_seconds / 15)            # 15 s time slot, uint64 LE
pseudonym = HMAC-SHA256(K_beacon, "SKP1-pseudo" || epoch_le64)[0..5]      # first 6 bytes
```

* The phone recomputes the pseudonym and restarts advertising whenever the epoch changes.
* The door unit keeps, for every paired user, the pseudonyms of epochs `e-2 … e+2`
  (±30 s clock skew tolerance) in a lookup table refreshed once per epoch. Matching an
  incoming advertisement is an `O(users × 5)` memcmp — microseconds — which keeps us far
  inside the 1 s budget.
* Matching a pseudonym is a *hint*, never authentication: it only triggers the connection.

### 2.3 GATT service (hosted by the phone)

| | UUID |
|---|---|
| SmartKey service | `8e9a0001-6b5f-4b1e-9c9e-2f0a6f0c5a10` |
| `CONTROL` characteristic (Write Without Response) | `8e9a0002-6b5f-4b1e-9c9e-2f0a6f0c5a10` |
| `STATUS` characteristic (Notify) | `8e9a0003-6b5f-4b1e-9c9e-2f0a6f0c5a10` |
| `PAIRING` characteristic (Write + Notify) | `8e9a0004-6b5f-4b1e-9c9e-2f0a6f0c5a10` |

The door unit writes frames to `CONTROL` and receives frames as notifications on `STATUS`
(CCCD `0x2902` is enabled right after discovery). The connection is requested with an
interval of 7.5–15 ms during the handshake; the door unit then relaxes it to 100–200 ms
while the user is merely "present".

No BLE bonding / LE Secure Connections is used — the application layer provides
authentication and the link is not trusted (see `security-model.md` §4).

---

### 2.4 Door beacon (door unit → phone, recovery only)

> Added in 1.2.0. **Optional** (`CONFIG_SMARTKEY_DOOR_BEACON_ENABLE`, default off) and
> not part of the unlock path. A door that never emits it behaves exactly as in 1.1.0.

#### Why it exists

The normal flow depends on `PresenceService` staying alive. A foreground service is not an
absolute guarantee: vendor battery managers — Samsung's "Deep Sleeping" list in particular —
stop apps anyway. When that happens presence dies **silently**, and the user only discovers it
while standing at a door that will not light up.

This beacon lets the door announce itself so a phone in that state can repair itself.

#### Why the identifier is static

This is the opposite choice from §2.2, and deliberately so:

| | phone beacon (§2.1) | door beacon (§2.4) |
|---|---|---|
| identifier | rotates every 15 s | **static** |
| reason | a phone in a pocket must not be trackable | a door is bolted to a wall and already has a fixed, public location |
| consequence | cannot be matched by an offloaded filter | **can** be pushed into the Bluetooth controller |

Hardware-offloaded filtering is what makes the recovery scan affordable: the phone's
application processor stays asleep until the controller matches the pattern. A rotating
identifier would forfeit that, and the door has no privacy to protect by rotating.

#### Format

Non-connectable, non-scannable (`ADV_NONCONN_IND`), PHY LE 1M.

```
AD type 0xFF, Company ID 0xFFFF

 offset size  field
   0      2   company_id            = 0xFFFF            (LE, part of the AD structure)
   2      1   skp_magic             = 0x44  ('D')       ← 'D' for door, not 'K'
   3      1   skp_version           = 0x01
   4      1   flags                 (see below)
   5      6   lock_id[0..5]         first 6 bytes of the lock id, static
  11      1   reserved              = 0x00
                                                         total AD payload = 12 bytes
```

The magic byte is the only thing separating this from a phone beacon, so parsers on both
sides **must** reject the other type rather than mis-parsing it.

`flags` bit field:

| bit | meaning |
|-----|---------|
| 0 | `PAIRING` — a pairing window is currently open |
| 1 | `ENROLLED` — the door has at least one credential |
| 2..7 | reserved, must be 0 |

* Advertising interval: **1000 ms** default — deliberately slow, since the only consumer is
  a low-power background scan.
* Suspended while a pairing window is open (the pairing advertisement takes the radio) and,
  by default, while any phone is connected (there is then nobody to wake).

#### What it is not

* **Not a fast path.** Low-power scan plus broadcast dispatch takes seconds, far outside the
  §8 budget. Presence detection still runs door-connects-to-phone.
* **Not connectable.** Nothing may dial in on it.
* **Not authentication.** Seeing it only causes the phone to restart its own service; every
  security property still comes from the §5 handshake.

#### Radio cost

The beacon shares one radio with the scanner, and scanning is the latency-critical half —
each advertisement missed is an RSSI sample the §8.4 proximity filter never receives. The
`scanstats` console command reports the measured advertisement rate so this can be verified
on real hardware before the beacon is enabled, rather than assumed.

## 3. Frame format

Every frame on `CONTROL`, `STATUS` and `PAIRING` shares this header:

```
 offset size  field
   0      1   version   = 0x01
   1      1   type      = frame type (§4)
   2      2   length    = payload length in bytes (uint16 LE), 0..236
   4    len   payload
                                              frame size = 4 + length  (max 240)
```

Frames are never fragmented: the door unit negotiates an ATT MTU of 247 (payload 244) and
refuses to talk to a peer that grants less than 100 bytes of payload.

---

## 4. Frame types

| id | name | direction | payload |
|----|------|-----------|---------|
| `0x01` | `HELLO` | lock → phone | §5.1 |
| `0x02` | `AUTH` | phone → lock | §5.2 |
| `0x03` | `SESSION_OK` | lock → phone | §5.3 |
| `0x04` | `UNLOCK_EVENT` | lock → phone | §6 |
| `0x05` | `UNLOCK_ACK` | phone → lock | §6 |
| `0x06` | `PRESENCE_PING` | lock → phone | empty (keep-alive) |
| `0x07` | `PRESENCE_PONG` | phone → lock | empty |
| `0x10` | `PAIR_START` | phone → lock | `pairing-spec.md` |
| `0x11` | `PAIR_RESPONSE` | lock → phone | `pairing-spec.md` |
| `0x12` | `PAIR_CONFIRM` | phone → lock | `pairing-spec.md` |
| `0x13` | `PAIR_RESULT` | lock → phone | `pairing-spec.md` |
| `0x7F` | `ERROR` | both | §7 |

---

## 5. Presence handshake

Goal: the door unit must convince itself that a phone holding `K_auth` is in range, and the
phone must convince itself that it is talking to the real door unit — in well under a second.

```
   lock                                                         phone
    │  (advertisement pseudonym matched, connection established)  │
    │ ── HELLO      { lock_id, nonce_l, caps }  ─────────────────► │
    │ ◄── AUTH      { user_id, nonce_p, tag_p } ────────────────── │
    │ ── SESSION_OK { tag_l, session_id, grant, ttl } ───────────► │
```

### 5.1 `HELLO` (0x01), payload 34 bytes

```
   0   16  lock_id[16]
  16   16  nonce_l[16]        cryptographically random, fresh per connection
  32    1  caps               bit0 = supports UNLOCK_EVENT, bit1 = supports pairing
  33    1  reserved (0)
```

### 5.2 `AUTH` (0x02), payload 64 bytes

```
   0   16  user_id[16]
  16   16  nonce_p[16]        cryptographically random, fresh per connection
  32   32  tag_p[32]
```

```
transcript = "SKP1-auth-v1" || lock_id || user_id || nonce_l || nonce_p
tag_p      = HMAC-SHA256(K_auth, 0x01 || transcript)
```

The lock looks up `K_auth` by `user_id`, recomputes `tag_p` and compares it in **constant
time**. A mismatch ⇒ `ERROR{AUTH_FAILED}` and immediate disconnect.

### 5.3 `SESSION_OK` (0x03), payload 42 bytes

```
   0   32  tag_l[32]
  32    8  session_id[8]
  40    1  grant              0 = denied, 1 = granted (LED on)
  41    1  ttl_s              seconds this grant stays valid without a PRESENCE_PONG
```

```
tag_l      = HMAC-SHA256(K_auth, 0x02 || transcript)
session_id = HMAC-SHA256(K_auth, 0x03 || transcript)[0..7]
K_sess     = HKDF-SHA256(ikm = K_auth, salt = nonce_l || nonce_p,
                         info = "SKP1-session" || lock_id || user_id, L = 32)
```

The phone verifies `tag_l` in constant time; a mismatch means the door unit is an impostor,
the app disconnects and shows a warning.

The domain separation byte (`0x01`/`0x02`/`0x03`) prevents reflecting one tag as another.

### 5.4 Presence maintenance

`SESSION_OK{grant=1}` means **"you are authorised"**, not **"the LED is on"**. The
two are deliberately separate:

* Authorisation is cryptographic and binary.
* The LED additionally requires the phone to be measured **physically next to the
  board**, which is a noisy, continuous quantity (§8.4).

So after a successful handshake the lock is in one of two states:

| lock state | meaning | LED | button |
|------------|---------|-----|--------|
| `GRANTED` | authenticated **and** near | on | works |
| `LINGERING` | authenticated but too far | off | refused |

The connection is kept in `LINGERING`, so stepping closer re-lights the LED
within one proximity poll (~250 ms) with no new handshake.

* The lock sends `PRESENCE_PING` every `ttl_s / 2` seconds (default `ttl_s = 10`).
* Two consecutive missing `PRESENCE_PONG`s, a raw RSSI below the *disconnect*
  threshold for 3 consecutive samples, or a BLE disconnect ⇒ session destroyed.

---

## 6. Unlock reporting

The physical button is wired to the door unit, so the unlock command never travels over
BLE — a deliberate design decision (see `security-model.md` §3). BLE only tells the phone
what happened so the app can show feedback.

`UNLOCK_EVENT` (0x04), payload 46 bytes:

```
   0    8  session_id[8]
   8    4  counter (uint32 LE)   monotonic per session, starts at 1
  12    1  result                0 = ok, 1 = zigbee error, 2 = not permitted, 3 = rate limited
  13    1  reserved (0)
  14   32  tag[32] = HMAC-SHA256(K_sess, 0x10 || session_id || counter_le32 || result)
```

`UNLOCK_ACK` (0x05), payload 12 bytes:

```
   0    8  session_id[8]
   8    4  counter (uint32 LE)   echoes the acknowledged event
```

---

## 7. Errors

`ERROR` (0x7F), payload 2 bytes: `code (uint8)`, `detail (uint8)`.

| code | meaning |
|------|---------|
| `0x01` | `UNSUPPORTED_VERSION` |
| `0x02` | `MALFORMED_FRAME` |
| `0x03` | `UNKNOWN_USER` |
| `0x04` | `AUTH_FAILED` |
| `0x05` | `NOT_PAIRED` |
| `0x06` | `PAIRING_DISABLED` |
| `0x07` | `RATE_LIMITED` |
| `0x08` | `TIMEOUT` |
| `0x09` | `INTERNAL` |

---

## 8. Timing budget (requirement: LED < 1000 ms)

| step | typical | worst case |
|------|---------|-----------|
| Phone advertisement emitted (100 ms interval) | 50 ms | 100 ms |
| Door unit scan catches it (interval 60 ms / window 60 ms ⇒ ~100 % duty) | 10 ms | 60 ms |
| Pseudonym table lookup | < 1 ms | 1 ms |
| BLE connection establishment (conn interval 7.5 ms) | 60 ms | 150 ms |
| MTU exchange + service discovery (cached after first connection) | 30 ms | 180 ms |
| `HELLO` → `AUTH` → `SESSION_OK` (3 × ~15 ms round trip incl. HMAC) | 60 ms | 120 ms |
| LED GPIO | < 1 ms | 1 ms |
| **total** | **~210 ms** | **~610 ms** |

Rules that protect the budget:

1. The door unit **caches GATT handles** per known phone address so discovery is skipped on
   reconnect (`smartkey_ble` keeps an LRU of 8 peers).
2. HMAC-SHA256 runs on the C5 hardware SHA accelerator: tens of microseconds — negligible.
3. The scanner never stops, and the LED decision is taken in the BLE host task, not behind
   an application queue.
4. No BLE pairing/bonding round trips (they would add 300–800 ms).

### 8.4 Proximity gate — "only when the phone is near the board"

Raw BLE RSSI is a poor distance estimate: multipath, body shadowing and antenna
orientation swing it 15–20 dB between consecutive packets. Gating the LED on a
single sample would both light it from across a room (one lucky reflection) and
make it flicker. The door unit therefore applies a **median filter with
hysteresis** before deciding.

```
                       ┌──────────── raw RSSI samples ────────────┐
 advertisements ──────►│  sliding window of N (default 5) samples │
 connection polls ────►└──────────────────┬───────────────────────┘
      (every 250 ms)                      │ median
                                          ▼
                       median ≥ near_dbm ──► NEAR  (LED on,  button armed)
                       median <  far_dbm ──► FAR   (LED off, button refused)
                       in between         ──► keep the previous verdict
```

| parameter | default | meaning |
|-----------|---------|---------|
| `CONFIG_SMARTKEY_PROXIMITY_NEAR_DBM` | `-60` | Median at/above this ⇒ LED on (~1 m) |
| `CONFIG_SMARTKEY_PROXIMITY_FAR_DBM` | `-72` | Median below this ⇒ LED off (~2–3 m) |
| `CONFIG_SMARTKEY_PROXIMITY_WINDOW` | `5` | Samples in the median window |
| `CONFIG_SMARTKEY_PROXIMITY_MIN_SAMPLES` | `3` | Required before the LED may ever turn on |
| `CONFIG_SMARTKEY_PROXIMITY_POLL_MS` | `250` | Connection RSSI sampling period |
| `CONFIG_SMARTKEY_RSSI_ENTER_DBM` | `-70` | Advertisement level that triggers the *connection* |
| `CONFIG_SMARTKEY_RSSI_EXIT_DBM` | `-85` | Raw level at which the link is dropped entirely |

Why these are three separate distances:

* **Connect early (`-70`)** — the handshake costs ~200 ms, so it is started
  while the user is still walking up. Its cost is hidden.
* **Light the LED late (`-60`)** — the visible signal only appears when the user
  is actually at the door.
* **Disconnect very late (`-85`)** — staying connected through the whole
  approach means re-entry never pays the handshake cost again.

**The median filter does not delay the LED.** Advertisement RSSI is fed into the
same window while scanning, so by the time the handshake completes the window is
already full and the verdict is available immediately. The `min_samples`
requirement is satisfied by the approach itself, not by waiting at the door.

Properties worth stating explicitly, each covered by a unit test:

* A single strong sample can never light the LED (`min_samples`).
* A single spike among weak samples cannot light it (median, not mean).
* A single dropout among strong samples cannot extinguish it.
* Inside the 12 dB band the verdict is sticky, so the LED cannot chatter.

Calibrate per installation with the `rssi` console command, which prints the raw
and filtered values live: stand where the LED *should* turn on, then set
`NEAR_DBM` a few dB below the filtered reading and `FAR_DBM` ~12 dB below that.

---

### 8.5 Presence modes — what the phone transmits

The budget in §8 assumes the phone is already advertising when the user arrives. That
holds in `ALWAYS_ADVERTISE`. It does **not** hold in `LISTEN_FIRST`, and the difference
is deliberate.

| | `ALWAYS_ADVERTISE` | `LISTEN_FIRST` (default) |
|---|---|---|
| phone transmits | continuously, every 100 ms | **only after hearing a door** |
| LED latency | **< 1 s, guaranteed** (§8) | best-effort, typically 2–6 s from first beacon |
| phone battery | ~1 %/day | lower, and nothing at all when away from doors |
| RF privacy | pseudonymous but always broadcasting | silent unless a door is nearby |
| requires | nothing | door beacon (§2.4) enabled |

#### The listen-first wake-up path

```
door beacon (1 Hz, static)
      │        matched inside the Bluetooth controller — CPU asleep
      ▼
first-match broadcast to the phone            ~1-4 s   (LOW_POWER duty cycle)
      ▼
phone starts advertising                      ~100 ms
      ▼
door sees it, connects, handshake             ~210 ms  (§8, unchanged)
      ▼
LED                                           ≈ 2-6 s total
```

**Why this is usable despite being slower.** The door beacon is receivable far beyond the
LED range: the phone typically hears the door while the user is still approaching, so the
wake-up overlaps the walk rather than adding to it. The user-perceived delay is therefore
usually much smaller than the figures above — but unlike §8 it is **not guaranteed**,
because it depends on where the beacon is first heard and on the OS scan duty cycle.

Anyone who needs the hard sub-second guarantee should select `ALWAYS_ADVERTISE`, and
accept that the phone then transmits continuously.

#### Staying transmitting

Once woken, the phone keeps advertising for a **90 s linger window**, refreshed by every
new beacon sighting and by both edges of a connection. This means:

* it does not go silent while a session is live;
* it keeps advertising briefly as the user walks away, then stops on its own;
* a door heard only in passing does not leave the phone transmitting for long.

#### Failure mode to be aware of

`LISTEN_FIRST` against a door with **no beacon** is a dead configuration: the phone waits
for something that never arrives and never advertises. This is why
`CONFIG_SMARTKEY_DOOR_BEACON_ENABLE` defaults to `y` from 1.3.0 onwards.

## 9. State machine (door unit)

```
   IDLE ──pseudonym match && rssi ≥ enter──► CONNECTING ──connected──► HANDSHAKING
     ▲                                            │                          │
     │                                    fail / timeout            SESSION_OK(grant=1)
     │                                            │                          │
     │◄───────────────────────────────────────────┘                          │
     │                                                                       ▼
     │                                              ┌──────── median ≥ near ────────┐
     │                                              │                               │
     │                                        LINGERING ◄───median < far───►     GRANTED
     │                                    (authenticated,                    (authenticated
     │                                     LED off, button                    AND near:
     │                                     refused)                           LED on)
     │                                              │                               │
     │◄──raw rssi < disconnect ×3 | ping timeout | BLE disconnect ──────────────────┤
                                                                                    │ button
                                                                                    ▼
                                                                                UNLOCKING
                                                                      (zigbee On/Off cmd → HA)
                                                                                    │ done
                                                                                    ▼
                                                                                 GRANTED
```

The handshake lands in `GRANTED` directly when the phone is already measured to
be near (the normal walk-up case, because the filter is pre-seeded from
advertisements), otherwise in `LINGERING`. Movement between the two costs one
proximity poll and no cryptography.

`PAIRING` is a separate top-level state entered by holding the button for 5 s (see
`pairing-spec.md`).

### 9.1 Releasing after the door opens

> Added in 1.4.0. `CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK`, default on.

A **successful** unlock returns the unit to `IDLE`: the session is dropped, the link is
closed and the LED goes out. "One approach, one opening" — once the door is actually
open the LED stops inviting further presses.

```
GRANTED ──button──► UNLOCKING ──zigbee ack──► release ──► IDLE
                                                 │        (LED off, link closed,
                                                 │         phone held, see below)
                                     failure ────┘
                                        │
                                        ▼
                                     GRANTED   (still lit: the user must be able
                                                to retry a relay that did not fire)
```

Only success releases. If the Zigbee command fails the unit stays `GRANTED` so the user
can press again.

#### Why releasing is not enough on its own

The phone that just opened the door is still standing at the reader and still
advertising. A bare disconnect would be undone immediately: the scanner sees the same
phone, reconnects, re-handshakes and relights the LED within a few hundred milliseconds.
A fixed time cooldown has the same defect, only a few seconds later.

The re-arm condition is therefore **departure, not elapsed time**. After an unlock that
peer is ignored until one of:

| rule | default | meaning |
|---|---|---|
| departure | seen weaker than **−75 dBm** | the user has stepped away — the normal case |
| absence | not seen for **3 s** | walked through the door and out of range |
| cap | **60 s** absolute | safety valve, see below |

Matching is by **BLE address, not credential slot**, so a second paired phone arriving at
the same time is unaffected — only the phone that actually opened the door is held.

The cap matters: a phone left lying on a desk beside the reader is permanently close and
permanently visible, so neither departure nor absence would ever fire. Without the cap
that user would be locked out indefinitely.

The hold is also cleared whenever credentials change (pairing, revocation, factory
reset), so it can never outlive the credential it applies to.

#### Reporting order

`UNLOCK_EVENT` is written before the link is torn down and the unit waits ~250 ms for the
controller to transmit it, so the app still shows "Door opened" rather than losing the
notification to the disconnect.

---

## 10. Zigbee mapping (door unit → Home Assistant)

The door unit joins the HA Zigbee network (ZHA / Zigbee2MQTT coordinator) as a
**Zigbee 3.0 End Device** and exposes:

| endpoint | device id | clusters |
|----------|-----------|----------|
| `1` | `0x0103` On/Off Light Switch | **client**: On/Off (`0x0006`), Identify (`0x0003`) — **server**: Basic (`0x0000`), Identify (`0x0003`) |

Pressing the button while in `GRANTED` sends On/Off → `On (0x01)` (configurable to `Toggle`)
to the bound target. Home Assistant binds that endpoint to the door relay / lock entity, so
no custom HA integration is required. Without a binding the command goes to the coordinator
(`0x0000`, endpoint 1) and HA reacts to the resulting `zha_event`.

Basic cluster attributes: manufacturer `"SmartKey"`, model `"SK-DOOR-C5"`.
