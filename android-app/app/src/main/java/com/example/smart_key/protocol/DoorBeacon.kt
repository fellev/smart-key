package com.example.smart_key.protocol

/**
 * Beacon broadcast by a door unit (protocol-spec.md §2.4).
 *
 * This is **not** part of the normal unlock path. The door always initiates
 * the session by connecting to the phone; this beacon exists purely so a phone
 * whose presence service was killed by the OS can notice a door nearby and
 * restart itself.
 *
 * Its identifier is deliberately **static**, which is the opposite of the
 * phone's 15 s rotating pseudonym. That is a considered asymmetry:
 *
 *  - A static pattern can be matched by a [android.bluetooth.le.ScanFilter]
 *    that Android pushes into the Bluetooth controller, so the recovery scan
 *    wakes the CPU only on a real match.
 *  - A door is a fixed object in a known location, so it has no location
 *    privacy to lose. The phone — which does — keeps its rotating pseudonym.
 */
class DoorBeacon(
    val flags: Int,
    val lockId: ByteArray
) {
    init {
        require(lockId.size == SmartKeyProtocol.DOOR_ID_SIZE) {
            "lockId must be ${SmartKeyProtocol.DOOR_ID_SIZE} bytes"
        }
    }

    /** True when the door has at least one credential enrolled. */
    val isEnrolled: Boolean
        get() = (flags and SmartKeyProtocol.DOOR_FLAG_ENROLLED) != 0

    /** True while the door has a pairing window open. */
    val isPairing: Boolean
        get() = (flags and SmartKeyProtocol.DOOR_FLAG_PAIRING) != 0

    /** Lowercase hex of the truncated lock id, for logs and matching. */
    val shortId: String
        get() = lockId.joinToString("") { "%02x".format(it) }

    /** Bytes after the company id: magic, version, flags, lock id, reserved. */
    fun toManufacturerData(): ByteArray = byteArrayOf(
        SmartKeyProtocol.DOOR_MAGIC,
        SmartKeyProtocol.VERSION,
        flags.toByte()
    ) + lockId + byteArrayOf(0)

    /** Full payload including the little endian company id. */
    fun toFullPayload(): ByteArray = byteArrayOf(
        (SmartKeyProtocol.MANUFACTURER_ID and 0xFF).toByte(),
        ((SmartKeyProtocol.MANUFACTURER_ID shr 8) and 0xFF).toByte()
    ) + toManufacturerData()

    companion object {
        /**
         * Parse the 12 byte form (company id included).
         *
         * Returns null for anything that is not a door beacon — including a
         * SmartKey *phone* beacon, which shares the company id but uses a
         * different magic byte.
         */
        fun parse(data: ByteArray): DoorBeacon? {
            if (data.size < SmartKeyProtocol.DOOR_DATA_SIZE + 2) return null
            val companyId = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
            if (companyId != SmartKeyProtocol.MANUFACTURER_ID) return null
            if (data[2] != SmartKeyProtocol.DOOR_MAGIC) return null
            if (data[3] != SmartKeyProtocol.VERSION) return null
            return DoorBeacon(
                flags = data[4].toInt() and 0xFF,
                lockId = data.copyOfRange(5, 11)
            )
        }

        /**
         * Parse the 10 byte form Android hands back from
         * `ScanRecord.getManufacturerSpecificData(id)`, which strips the
         * company id.
         */
        fun parseWithoutCompanyId(data: ByteArray): DoorBeacon? {
            if (data.size < SmartKeyProtocol.DOOR_DATA_SIZE) return null
            if (data[0] != SmartKeyProtocol.DOOR_MAGIC) return null
            if (data[1] != SmartKeyProtocol.VERSION) return null
            return DoorBeacon(
                flags = data[2].toInt() and 0xFF,
                lockId = data.copyOfRange(3, 9)
            )
        }

        /**
         * Bytes and mask for a hardware-offloadable [ScanFilter].
         *
         * Only the magic and version bytes are matched; the lock id is left
         * masked out so one filter covers every door the user has paired.
         */
        val FILTER_DATA: ByteArray = byteArrayOf(
            SmartKeyProtocol.DOOR_MAGIC,
            SmartKeyProtocol.VERSION
        ) + ByteArray(SmartKeyProtocol.DOOR_DATA_SIZE - 2)

        val FILTER_MASK: ByteArray = byteArrayOf(0xFF.toByte(), 0xFF.toByte()) +
            ByteArray(SmartKeyProtocol.DOOR_DATA_SIZE - 2)
    }
}
