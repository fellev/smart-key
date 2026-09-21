# Changelog

All notable changes to the SmartKey wire protocol.

## [1.4.0] - 2026-09-21 — the door goes idle once it has been opened

No wire format change; the version byte stays `0x01`. Door unit behaviour only,
and the app needs no changes.

* A **successful** unlock now releases the session: link closed, LED off, back
  to `IDLE` (`protocol-spec.md` §9.1). Previously the LED stayed lit and the
  button stayed live until the user physically walked away — it kept inviting
  presses after the door was already open.
* A failed unlock deliberately does **not** release: if the relay never fired
  the user still needs the LED and the button to retry.
* Re-arming is **departure based, not a timer**. Releasing alone would achieve
  nothing: the phone that just unlocked is still at the reader and still
  advertising, so the scanner would reconnect and relight the LED within a few
  hundred milliseconds. A fixed cooldown fails the same way, just later. The
  phone is therefore ignored until it is seen to leave (`-75` dBm), stops being
  seen at all (3 s), or hits a 60 s absolute cap.
* The cap is a safety valve: a phone left lying beside the reader is always
  close and always visible, so without it that user would be locked out forever.
* Holds are keyed on **BLE address, not credential slot**, so a second paired
  phone arriving alongside the first is unaffected.
* Holds are cleared on pairing, revocation and factory reset, so one can never
  outlive the credential it applies to.
* `UNLOCK_EVENT` is flushed (~250 ms) before the link drops, so the app still
  shows "Door opened".
* New `CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK` (default **on**) plus
  `REARM_DEPART_DBM` / `REARM_ABSENT_MS` / `REARM_MAX_HOLD_MS`. Disable for
  doors where repeated openings without walking away are normal.

## [1.3.0] - 2026-09-21 — listen-first: the phone stops transmitting continuously

No wire format change; the version byte stays `0x01`. Phone behaviour and one
firmware default.

* New **`LISTEN_FIRST` presence mode, now the default**: the phone transmits
  **nothing at all** until it has actually heard a door beacon (§2.4). Detection
  while idle happens entirely in the Bluetooth controller's offloaded scan
  filter, so "listening" costs far less than the advertising it replaces.
* Once woken the phone advertises for a **90 s linger window**, refreshed by new
  sightings and by both edges of a connection, so it never goes quiet mid-session
  and keeps transmitting briefly as the user walks away.
* `ALWAYS_ADVERTISE` preserves the old behaviour for anyone who needs the hard
  sub-second guarantee.
* New phone state `LISTENING` (radio silent, waiting) distinct from `ADVERTISING`.
* `CONFIG_SMARTKEY_DOOR_BEACON_ENABLE` now defaults to **`y`**: listen-first
  cannot work without it, and a beacon-less door plus a listen-first phone is a
  dead configuration.

> **Latency changes, and this is the real cost.** The §8 sub-second budget is a
> *guarantee* only in `ALWAYS_ADVERTISE`. In listen-first the LED is best-effort,
> typically 2–6 s measured from the first beacon sighting — usually far less in
> practice because the phone wakes while the user is still walking up, since the
> beacon carries much further than the LED proximity range. See §8.5.

## [1.2.0] - 2026-09-21 — door beacon recovery path

Additive only. The version byte stays `0x01`: this introduces a **new, separate**
advertisement type and leaves the phone beacon, the handshake frames and the GATT
layout untouched. All four old/new combinations of app and firmware interoperate,
and the feature is off by default.

* New optional **door beacon** (`protocol-spec.md` §2.4): the door unit emits a
  non-connectable advertisement with magic byte `0x44` (`'D'`) carrying a
  **static** truncated lock id.
* Purpose is **recovery, not detection**. A foreground service can still be killed
  by vendor battery managers, after which presence dies silently; a phone in that
  state is woken by this beacon and restarts its own service. The unlock path is
  unchanged — the door still connects to the phone.
* The identifier is static *specifically* so Android can push the scan filter into
  the Bluetooth controller (offloaded filtering), which is what makes the recovery
  scan nearly free. This costs no privacy because the identifier belongs to a door
  bolted to a wall; the **phone keeps its 15 s rotating pseudonym**.
* Guarded by `CONFIG_SMARTKEY_DOOR_BEACON_ENABLE` (default **off**), suspended
  during pairing and, by default, while a phone is connected.
* New `scanstats` console command reports the measured advertisement reception
  rate, so the radio cost of enabling the beacon can be verified on hardware
  instead of assumed.
* `check_consistency.py` now asserts the phone and door magic bytes cannot
  collide and that the door beacon stays slower than the phone beacon.

> **Not** included: this release does not reduce how often the *phone* transmits.
> The phone still advertises continuously at 100 ms while presence is running.
> Motion-gated advertising is tracked separately.

## [1.1.0] - 2026-09-21 — proximity gated LED

No wire format change, so the version byte stays `0x01` and old and new builds
interoperate. Door unit behaviour only.

* The permission LED now requires the phone to be **measured next to the board**,
  not merely authenticated. The gate is a median filter over the last 5 RSSI
  samples with 12 dB of hysteresis (`protocol-spec.md` §8.4).
* New door unit state `LINGERING`: authenticated but too far — LED off and the
  button is refused, while the connection is kept so that stepping closer
  re-lights the LED in ~250 ms without another handshake.
* Connection RSSI is polled every 250 ms instead of every 5 s, so the LED now
  follows the user instead of lagging by up to 15 s.
* Retuned defaults: connect at `-70` dBm, light the LED at `-60` dBm, disconnect
  at `-85` dBm — three deliberately different distances.
* New `rssi` console command for calibrating the thresholds on site.

## [1.0.0] - 2026-09-21 - `SKP1` (wire version `0x01`)

Initial protocol.

* Presence beacon: manufacturer specific advertising data, 6 byte rolling pseudonym.
* Presence handshake: `HELLO` / `AUTH` / `SESSION_OK`, mutual HMAC-SHA256 authentication.
* Session key derivation (HKDF-SHA256) + authenticated `UNLOCK_EVENT` reporting.
* Pairing: X25519 ECDH authenticated by an 8 digit pairing code, HKDF-SHA256 long term key.
