package com.example.smart_key.protocol

/**
 * SmartKey presence beacon payload (protocol-spec.md §2.1).
 *
 * Android's `AdvertiseData.addManufacturerData()` adds the 2 byte company id
 * itself, so [toManufacturerData] returns the 10 bytes that follow it, while
 * [toFullPayload] produces the 12 byte form used in the golden vectors and by
 * the firmware parser.
 */
class SmartKeyAdvertisement(
    val flags: Int,
    val pseudonym: ByteArray,
    val batteryPercent: Int = SmartKeyProtocol.BATTERY_UNKNOWN
) {
    init {
        require(pseudonym.size == SmartKeyProtocol.PSEUDONYM_SIZE) {
            "pseudonym must be ${SmartKeyProtocol.PSEUDONYM_SIZE} bytes"
        }
    }

    /** Bytes after the company id: magic, version, flags, pseudonym, battery. */
    fun toManufacturerData(): ByteArray = byteArrayOf(
        SmartKeyProtocol.ADV_MAGIC,
        SmartKeyProtocol.VERSION,
        flags.toByte()
    ) + pseudonym + byteArrayOf(batteryPercent.toByte())

    /** Full payload including the little endian company id. */
    fun toFullPayload(): ByteArray = byteArrayOf(
        (SmartKeyProtocol.MANUFACTURER_ID and 0xFF).toByte(),
        ((SmartKeyProtocol.MANUFACTURER_ID shr 8) and 0xFF).toByte()
    ) + toManufacturerData()

    companion object {
        /** Parse the 12 byte form (company id included). Returns null if foreign. */
        fun parse(data: ByteArray): SmartKeyAdvertisement? {
            if (data.size < SmartKeyProtocol.ADV_DATA_SIZE + 2) return null
            val companyId = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
            if (companyId != SmartKeyProtocol.MANUFACTURER_ID) return null
            if (data[2] != SmartKeyProtocol.ADV_MAGIC) return null
            if (data[3] != SmartKeyProtocol.VERSION) return null
            return SmartKeyAdvertisement(
                flags = data[4].toInt() and 0xFF,
                pseudonym = data.copyOfRange(5, 11),
                batteryPercent = data[11].toInt() and 0xFF
            )
        }

        /** Build the beacon the app advertises for the given epoch. */
        fun forEpoch(
            kBeacon: ByteArray,
            epoch: Long,
            screenOn: Boolean,
            deviceUnlocked: Boolean,
            pairingMode: Boolean = false,
            batteryPercent: Int = SmartKeyProtocol.BATTERY_UNKNOWN
        ): SmartKeyAdvertisement {
            var flags = 0
            if (screenOn) flags = flags or SmartKeyProtocol.FLAG_SCREEN_ON
            if (deviceUnlocked) flags = flags or SmartKeyProtocol.FLAG_UNLOCKED
            if (pairingMode) flags = flags or SmartKeyProtocol.FLAG_PAIRING_MODE
            return SmartKeyAdvertisement(
                flags = flags,
                pseudonym = SmartKeyCrypto.pseudonym(kBeacon, epoch),
                batteryPercent = batteryPercent
            )
        }
    }
}
