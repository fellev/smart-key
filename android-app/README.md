# SmartKey Android app

Kotlin app for Android 16 (API 36, Galaxy S26). It makes the phone a BLE
peripheral that the door unit recognises, and runs the pairing exchange.

## Why the phone advertises instead of scanning

Android throttles background BLE scanning (opportunistic and batched), which
makes a sub-second reaction impossible. Background *advertising* from a
foreground service is not throttled, so the roles are inverted relative to the
obvious design: the phone advertises, the mains-powered door unit scans. See
[`../shared-protocols/protocol-spec.md`](../shared-protocols/protocol-spec.md) §2.

## Layout

```
app/src/main/java/com/example/smart_key/
  protocol/     SKP1 constants, frame codec, crypto, X25519 (no Android deps)
  data/         Credential model + EncryptedSharedPreferences store
  ble/          Advertiser, GATT server, HandshakeEngine, PresenceService
  pairing/      PairingSession (pure logic) + PairingClient (BLE transport)
  StatusFragment.kt / PairingFragment.kt / MainActivity.kt
app/src/test/   JUnit tests against ../shared-protocols/test-vectors/
```

`HandshakeEngine` and `PairingSession` hold all the security logic and are pure
functions of the frames they receive, which is what makes them unit testable
without a device.

## Build and test

Open the folder in Android Studio and run, or from the command line:

```bash
./gradlew testDebugUnitTest      # protocol, crypto, handshake and pairing tests
./gradlew assembleDebug
```

The unit tests read the golden vectors straight from `../shared-protocols/`
(the path is passed in by `app/build.gradle.kts`), so the app and the firmware
are verified against exactly the same bytes.

> A JDK is required. If `java` is missing:
> `sudo apt install openjdk-17-jdk`, or just run the tests from Android Studio,
> which bundles its own JBR.

## Permissions

| Permission | Why |
|------------|-----|
| `BLUETOOTH_ADVERTISE` | Broadcast the presence beacon |
| `BLUETOOTH_CONNECT` | Host the GATT server and talk to the door unit |
| `BLUETOOTH_SCAN` (`neverForLocation`) | Find a door unit while pairing only |
| `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Keep advertising with the screen off |
| `POST_NOTIFICATIONS` | The mandatory foreground service notification |

No location permission is needed: the scan filter is declared `neverForLocation`.

## Key handling

Pairing derives the long term key, immediately derives `K_auth` and `K_beacon`
from it, wipes the raw key, and stores only the sub keys in
`EncryptedSharedPreferences` (AES-256-GCM under an Android Keystore master key).
See [`../shared-protocols/pairing-spec.md`](../shared-protocols/pairing-spec.md) §4.

## Known next steps

* Move the sub keys into Keystore-held `HmacSHA256` keys so they are
  non-exportable even with root (needs an HMAC-over-Keystore refactor of
  `SmartKeyCrypto`).
* Optional biometric gate before presence is enabled.
* Instrumented tests for the BLE transport classes, which currently have no
  device-free coverage.
