package com.example.smart_key.protocol

import java.util.UUID

/**
 * Constants of the SmartKey wire protocol (SKP1).
 *
 * Mirror of `esp32-firmware/components/smartkey_proto/include/smartkey_proto.h`.
 * The authoritative definition is `shared-protocols/protocol-spec.md` and the
 * machine readable `shared-protocols/schema/smartkey-protocol.json`.
 */
object SmartKeyProtocol {

    const val VERSION: Byte = 0x01

    // --- sizes (protocol-spec.md §1, §3) ------------------------------------
    const val ID_SIZE = 16
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 16
    const val TAG_SIZE = 32
    const val SESSION_ID_SIZE = 8
    const val PSEUDONYM_SIZE = 6
    const val PUBKEY_SIZE = 32
    const val PAIRING_CODE_LEN = 8

    const val HEADER_SIZE = 4
    const val MAX_PAYLOAD = 236
    const val MAX_FRAME = HEADER_SIZE + MAX_PAYLOAD

    // --- advertising (protocol-spec.md §2.1) --------------------------------
    /** 0xFFFF is the "for testing" company id; replace before production. */
    const val MANUFACTURER_ID = 0xFFFF
    const val ADV_MAGIC: Byte = 0x4B
    /** Payload size *excluding* the company id, which Android prepends itself. */
    const val ADV_DATA_SIZE = 10
    const val ADV_INTERVAL_MS = 100L

    const val FLAG_SCREEN_ON = 0x01
    const val FLAG_UNLOCKED = 0x02
    const val FLAG_PAIRING_MODE = 0x04
    const val FLAG_PAIRING_BEACON = 0x80

    const val BATTERY_UNKNOWN = 0xFF

    // --- door beacon (protocol-spec.md §2.4) --------------------------------
    /**
     * Beacon emitted by the *door*, used only to recover a killed presence
     * service.
     *
     * Unlike the phone beacon, this identifier is deliberately STATIC. A fixed
     * byte pattern is what allows Android to push the scan filter down into
     * the Bluetooth controller (offloaded filtering), so the recovery scan
     * costs almost no battery. The privacy cost is nil because the identifier
     * belongs to a door bolted to a wall, not to a phone in a pocket — the
     * phone's own beacon keeps its 15 s rotating pseudonym.
     */
    const val DOOR_MAGIC: Byte = 0x44
    /** Payload size *excluding* the company id, which Android prepends. */
    const val DOOR_DATA_SIZE = 10
    const val DOOR_ID_SIZE = 6

    const val DOOR_FLAG_PAIRING = 0x01
    const val DOOR_FLAG_ENROLLED = 0x02

    // --- GATT (protocol-spec.md §2.3) ---------------------------------------
    val SERVICE_UUID: UUID = UUID.fromString("8e9a0001-6b5f-4b1e-9c9e-2f0a6f0c5a10")
    val CONTROL_UUID: UUID = UUID.fromString("8e9a0002-6b5f-4b1e-9c9e-2f0a6f0c5a10")
    val STATUS_UUID: UUID = UUID.fromString("8e9a0003-6b5f-4b1e-9c9e-2f0a6f0c5a10")
    val PAIRING_UUID: UUID = UUID.fromString("8e9a0004-6b5f-4b1e-9c9e-2f0a6f0c5a10")
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    // --- frame types (protocol-spec.md §4) ----------------------------------
    object FrameType {
        const val HELLO: Byte = 0x01
        const val AUTH: Byte = 0x02
        const val SESSION_OK: Byte = 0x03
        const val UNLOCK_EVENT: Byte = 0x04
        const val UNLOCK_ACK: Byte = 0x05
        const val PRESENCE_PING: Byte = 0x06
        const val PRESENCE_PONG: Byte = 0x07
        const val PAIR_START: Byte = 0x10
        const val PAIR_RESPONSE: Byte = 0x11
        const val PAIR_CONFIRM: Byte = 0x12
        const val PAIR_RESULT: Byte = 0x13
        const val ERROR: Byte = 0x7F
    }

    // --- payload sizes ------------------------------------------------------
    const val HELLO_SIZE = 34
    const val AUTH_SIZE = 64
    const val SESSION_OK_SIZE = 42
    const val UNLOCK_EVENT_SIZE = 46
    const val UNLOCK_ACK_SIZE = 12
    const val PAIR_START_SIZE = 64
    const val PAIR_RESPONSE_SIZE = 96
    const val PAIR_CONFIRM_SIZE = 32
    const val PAIR_RESULT_SIZE = 4
    const val ERROR_SIZE = 2

    // --- error codes (protocol-spec.md §7) ----------------------------------
    object ErrorCode {
        const val UNSUPPORTED_VERSION = 0x01
        const val MALFORMED_FRAME = 0x02
        const val UNKNOWN_USER = 0x03
        const val AUTH_FAILED = 0x04
        const val NOT_PAIRED = 0x05
        const val PAIRING_DISABLED = 0x06
        const val RATE_LIMITED = 0x07
        const val TIMEOUT = 0x08
        const val INTERNAL = 0x09
    }

    /** Result codes carried in UNLOCK_EVENT. */
    object UnlockResult {
        const val OK = 0
        const val ZIGBEE_ERROR = 1
        const val NOT_PERMITTED = 2
        const val RATE_LIMITED = 3
    }

    /** Result codes carried in PAIR_RESULT. */
    object PairResult {
        const val OK = 0
        const val BAD_CONFIRM = 1
        const val STORE_FULL = 2
        const val DISABLED = 3
    }
}
