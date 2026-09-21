# SmartKey Pairing — establishing the long term key (`LTK`)

Pairing is a rare, deliberate, physically-present operation. It gives a phone a
`(lock_id, user_id, LTK)` credential that the runtime protocol then uses forever.

## 1. Entering pairing mode

* **Door unit**: hold the button for 5 s. The LED blinks at 2 Hz and the unit switches its
  BLE role: it starts **advertising** a connectable pairing beacon and acts as GATT server
  for the `PAIRING` characteristic. Pairing mode lasts 120 s or until one successful pairing.
* The unit prints/serves an **8 digit pairing code** (`00000000`–`99999999`).
  Source order: `CONFIG_SMARTKEY_PAIRING_CODE` if non-empty, otherwise a random code logged
  on the serial console and blinked out as a QR-less fallback. Production units should carry
  a printed label with the code and `lock_id`.
* **Phone**: the user enters pairing mode in the app, scans for the pairing beacon, and types
  the 8 digit code.

Pairing beacon (from the door unit):

```
AD 0xFF manufacturer data, company 0xFFFF
  0  2  company_id 0xFFFF
  2  1  magic   = 0x4B ('K')
  3  1  version = 0x01
  4  1  flags   = 0x80   (bit7 = PAIRING_BEACON, distinguishes it from a phone beacon)
  5  6  lock_id[0..5]    first 6 bytes of the lock id, for display/selection
```

## 2. Key agreement

X25519 ECDH, authenticated by the pairing code (the code is mixed into the transcript, so an
attacker who does not know it cannot complete the confirmation step).

```
phone                                                     lock
  │  PAIR_START   { user_id, pubkey_p[32], nonce_p[16] } ──►│
  │◄─ PAIR_RESPONSE { lock_id, pubkey_l[32], nonce_l[16], confirm_l[32] }
  │  PAIR_CONFIRM { confirm_p[32] } ────────────────────────►│
  │◄─ PAIR_RESULT { status, ttl_hint }
```

Shared computation on both sides:

```
Z          = X25519(own_private, peer_public)                 # 32 bytes
pc         = ASCII bytes of the 8 digit pairing code          # 8 bytes
transcript = "SKP1-pair-v1" || lock_id || user_id || pubkey_p || pubkey_l
                             || nonce_p || nonce_l
LTK        = HKDF-SHA256(ikm = Z, salt = nonce_p || nonce_l,
                         info = transcript || pc, L = 32)
confirm_l  = HMAC-SHA256(LTK, 0x01 || transcript)
confirm_p  = HMAC-SHA256(LTK, 0x02 || transcript)
```

* The phone verifies `confirm_l` (constant time). If it fails, the code was wrong or a MITM
  is present → abort, no key stored.
* The lock verifies `confirm_p` before storing anything.
* Because the code only enters the KDF, a wrong code produces a different `LTK` and the
  confirmation simply fails; no offline dictionary attack material is exposed beyond a single
  online guess. The lock allows **3 failed attempts**, then leaves pairing mode.

`Z` must be rejected if it is all-zero (low-order point contribution).

## 3. Frame payloads

`PAIR_START` (0x10), 64 bytes:

```
  0  16  user_id[16]
 16  32  pubkey_p[32]
 48  16  nonce_p[16]
```

`PAIR_RESPONSE` (0x11), 96 bytes:

```
  0  16  lock_id[16]
 16  32  pubkey_l[32]
 48  16  nonce_l[16]
 64  32  confirm_l[32]
```

`PAIR_CONFIRM` (0x12), 32 bytes:

```
  0  32  confirm_p[32]
```

`PAIR_RESULT` (0x13), 4 bytes:

```
  0   1  status   0 = ok, 1 = bad confirm, 2 = store full, 3 = pairing disabled
  1   1  slot     index of the credential slot used (0..CONFIG_SMARTKEY_MAX_USERS-1)
  2   2  reserved (0)
```

## 4. Storage

**Door unit** — NVS namespace `smartkey`, encrypted with NVS encryption (flash encryption
enabled in production):

| key | value |
|-----|-------|
| `lock_id` | 16 B |
| `u<slot>.uid` | 16 B user id |
| `u<slot>.ltk` | 32 B long term key |
| `u<slot>.name` | up to 31 chars, label shown in logs |
| `u<slot>.en` | 1 B enabled flag (revocation without deletion) |

Default capacity: `CONFIG_SMARTKEY_MAX_USERS = 8`.

**Phone** — `EncryptedSharedPreferences` for the credential record, with the `LTK` imported
into the Android Keystore as a non-exportable `HmacSHA256` key
(alias `smartkey_ltk_<lock_id_hex>`, `setUserAuthenticationRequired(false)` so the
presence handshake works with the screen off, `StrongBox` when available).

`K_auth` / `K_beacon` cannot be derived inside the Keystore (no HKDF support), so the app
derives them once at pairing time and stores **those** as separate non-exportable Keystore
HMAC keys; the raw `LTK` is wiped from memory and never persisted in plaintext.

## 5. Revocation

* On the lock: `u<slot>.en = 0` (via the serial console command `revoke <slot>`, or by a
  factory reset with a 10 s button hold: LED fast-blinks and all slots are erased).
* On the phone: deleting the credential in the app removes the Keystore aliases.
