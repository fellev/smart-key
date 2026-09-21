package com.example.smart_key.data

import com.example.smart_key.protocol.SmartKeyCrypto

/**
 * One paired door: the identity plus the derived sub keys used at runtime.
 *
 * The raw long term key is never kept here — only `K_auth` and `K_beacon`, in
 * line with pairing-spec.md §4.
 */
class Credential(
    val lockId: ByteArray,
    val userId: ByteArray,
    val kAuth: ByteArray,
    val kBeacon: ByteArray,
    val label: String,
    val pairedAtEpochSeconds: Long
) {
    /** Short hexadecimal form of the lock id, used in the UI and as a key. */
    val lockIdHex: String get() = lockId.toHex()

    val shortId: String get() = lockIdHex.take(8)

    /** The pseudonym this credential should advertise right now. */
    fun currentPseudonym(): ByteArray =
        SmartKeyCrypto.pseudonym(kBeacon, SmartKeyCrypto.currentEpoch())
}

/** Lowercase hexadecimal, matching the shared test vectors. */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/** Parse lowercase or uppercase hexadecimal into bytes. */
fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex string must have an even length" }
    return ByteArray(length / 2) {
        ((Character.digit(this[it * 2], 16) shl 4) or Character.digit(this[it * 2 + 1], 16))
            .toByte()
    }
}
