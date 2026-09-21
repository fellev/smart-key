package com.example.smart_key.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SKP1 key derivation and authentication tags.
 *
 * Kotlin twin of `esp32-firmware/components/smartkey_proto/smartkey_crypto.c`
 * and `shared-protocols/tools/skp_crypto.py`; all three are verified against
 * the same golden vectors.
 */
object SmartKeyCrypto {

    private const val HMAC_SHA256 = "HmacSHA256"

    // Info strings and domain separation bytes (protocol-spec.md §1, §5).
    private val INFO_BEACON = "SKP1-beacon".toByteArray(Charsets.US_ASCII)
    private val INFO_AUTH = "SKP1-auth".toByteArray(Charsets.US_ASCII)
    private val INFO_SESSION = "SKP1-session".toByteArray(Charsets.US_ASCII)
    private val INFO_PSEUDO = "SKP1-pseudo".toByteArray(Charsets.US_ASCII)
    private val TRANSCRIPT_AUTH = "SKP1-auth-v1".toByteArray(Charsets.US_ASCII)
    private val TRANSCRIPT_PAIR = "SKP1-pair-v1".toByteArray(Charsets.US_ASCII)

    private const val DOMAIN_AUTH_PHONE: Byte = 0x01
    private const val DOMAIN_AUTH_LOCK: Byte = 0x02
    private const val DOMAIN_SESSION_ID: Byte = 0x03
    private const val DOMAIN_UNLOCK_EVENT: Byte = 0x10
    private const val DOMAIN_PAIR_CONFIRM_LOCK: Byte = 0x01
    private const val DOMAIN_PAIR_CONFIRM_PHONE: Byte = 0x02

    /** Rolling pseudonym epoch length, protocol-spec.md §2.2. */
    const val BEACON_EPOCH_SECONDS = 15L

    private val random = SecureRandom()

    // ------------------------------------------------------------ primitives

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance(HMAC_SHA256).apply { init(SecretKeySpec(key, HMAC_SHA256)) }.doFinal(data)

    /** RFC 5869 HKDF-SHA256 (extract-then-expand). */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "invalid HKDF output length: $length" }
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmacSha256(effectiveSalt, ikm)

        val mac = Mac.getInstance(HMAC_SHA256).apply { init(SecretKeySpec(prk, HMAC_SHA256)) }
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.reset()
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val chunk = minOf(previous.size, length - offset)
            previous.copyInto(output, offset, 0, chunk)
            offset += chunk
            counter++
        }
        return output
    }

    /** Constant time comparison; [MessageDigest.isEqual] is time-constant on Android. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /** Overwrite key material that is no longer needed. */
    fun wipe(vararg buffers: ByteArray) = buffers.forEach { it.fill(0) }

    // --------------------------------------------------------------- subkeys

    /** K_beacon and K_auth derived from the long term key (protocol-spec.md §1). */
    class SubKeys(val kBeacon: ByteArray, val kAuth: ByteArray)

    fun deriveSubKeys(ltk: ByteArray, lockId: ByteArray, userId: ByteArray): SubKeys {
        val salt = lockId + userId
        return SubKeys(
            kBeacon = hkdfSha256(ltk, salt, INFO_BEACON, SmartKeyProtocol.KEY_SIZE),
            kAuth = hkdfSha256(ltk, salt, INFO_AUTH, SmartKeyProtocol.KEY_SIZE)
        )
    }

    /** Current 15 second beacon epoch. */
    fun epochFor(unixSeconds: Long): Long = unixSeconds / BEACON_EPOCH_SECONDS

    fun currentEpoch(): Long = epochFor(System.currentTimeMillis() / 1000)

    /** Rolling advertising pseudonym for [epoch] (protocol-spec.md §2.2). */
    fun pseudonym(kBeacon: ByteArray, epoch: Long): ByteArray {
        val data = ByteBuffer.allocate(INFO_PSEUDO.size + 8).order(ByteOrder.LITTLE_ENDIAN)
            .put(INFO_PSEUDO).putLong(epoch).array()
        return hmacSha256(kBeacon, data).copyOf(SmartKeyProtocol.PSEUDONYM_SIZE)
    }

    // ------------------------------------------------------------- handshake

    fun authTranscript(
        lockId: ByteArray,
        userId: ByteArray,
        nonceL: ByteArray,
        nonceP: ByteArray
    ): ByteArray = TRANSCRIPT_AUTH + lockId + userId + nonceL + nonceP

    private fun tagWithDomain(key: ByteArray, domain: Byte, data: ByteArray): ByteArray =
        hmacSha256(key, byteArrayOf(domain) + data)

    fun tagPhone(kAuth: ByteArray, transcript: ByteArray): ByteArray =
        tagWithDomain(kAuth, DOMAIN_AUTH_PHONE, transcript)

    fun tagLock(kAuth: ByteArray, transcript: ByteArray): ByteArray =
        tagWithDomain(kAuth, DOMAIN_AUTH_LOCK, transcript)

    fun sessionId(kAuth: ByteArray, transcript: ByteArray): ByteArray =
        tagWithDomain(kAuth, DOMAIN_SESSION_ID, transcript)
            .copyOf(SmartKeyProtocol.SESSION_ID_SIZE)

    fun sessionKey(
        kAuth: ByteArray,
        lockId: ByteArray,
        userId: ByteArray,
        nonceL: ByteArray,
        nonceP: ByteArray
    ): ByteArray = hkdfSha256(
        ikm = kAuth,
        salt = nonceL + nonceP,
        info = INFO_SESSION + lockId + userId,
        length = SmartKeyProtocol.KEY_SIZE
    )

    /** Authentication tag of an UNLOCK_EVENT (protocol-spec.md §6). */
    fun unlockTag(kSess: ByteArray, sessionId: ByteArray, counter: Int, result: Int): ByteArray {
        val data = ByteBuffer.allocate(SmartKeyProtocol.SESSION_ID_SIZE + 5)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(sessionId).putInt(counter).put(result.toByte())
            .array()
        return tagWithDomain(kSess, DOMAIN_UNLOCK_EVENT, data)
    }

    // --------------------------------------------------------------- pairing

    fun pairTranscript(
        lockId: ByteArray,
        userId: ByteArray,
        publicKeyP: ByteArray,
        publicKeyL: ByteArray,
        nonceP: ByteArray,
        nonceL: ByteArray
    ): ByteArray = TRANSCRIPT_PAIR + lockId + userId + publicKeyP + publicKeyL + nonceP + nonceL

    /**
     * Derive the long term key. The pairing code enters the KDF, so a wrong
     * code yields a different key and the confirmation fails (pairing-spec.md §2).
     */
    fun pairLtk(
        sharedZ: ByteArray,
        nonceP: ByteArray,
        nonceL: ByteArray,
        transcript: ByteArray,
        pairingCode: String
    ): ByteArray {
        require(pairingCode.length == SmartKeyProtocol.PAIRING_CODE_LEN) {
            "pairing code must be ${SmartKeyProtocol.PAIRING_CODE_LEN} digits"
        }
        return hkdfSha256(
            ikm = sharedZ,
            salt = nonceP + nonceL,
            info = transcript + pairingCode.toByteArray(Charsets.US_ASCII),
            length = SmartKeyProtocol.KEY_SIZE
        )
    }

    fun pairConfirmLock(ltk: ByteArray, transcript: ByteArray): ByteArray =
        tagWithDomain(ltk, DOMAIN_PAIR_CONFIRM_LOCK, transcript)

    fun pairConfirmPhone(ltk: ByteArray, transcript: ByteArray): ByteArray =
        tagWithDomain(ltk, DOMAIN_PAIR_CONFIRM_PHONE, transcript)
}
