package com.example.smart_key.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Verifies the Kotlin crypto against the golden vectors shared with the
 * firmware (shared-protocols/test-vectors/handshake.json).
 */
class SmartKeyCryptoTest {

    private val vectors = SharedVectors.handshake
    private val inputs = vectors.getJSONObject("inputs")

    private val lockId = inputs.getString("lock_id").decodeHex()
    private val userId = inputs.getString("user_id").decodeHex()
    private val ltk = inputs.getString("ltk").decodeHex()
    private val nonceL = inputs.getString("nonce_l").decodeHex()
    private val nonceP = inputs.getString("nonce_p").decodeHex()

    private val kAuth = vectors.getJSONObject("subkeys").getString("k_auth").decodeHex()
    private val kBeacon = vectors.getJSONObject("subkeys").getString("k_beacon").decodeHex()

    @Test
    fun `hkdf matches rfc 5869 test case 1`() {
        val hkdf = vectors.getJSONArray("hkdf").getJSONObject(0)
        val okm = SmartKeyCrypto.hkdfSha256(
            ikm = hkdf.getString("ikm").decodeHex(),
            salt = hkdf.getString("salt").decodeHex(),
            info = hkdf.getString("info").decodeHex(),
            length = hkdf.getInt("length")
        )
        assertEquals(hkdf.getString("okm"), okm.encodeHex())
    }

    @Test
    fun `sub keys match the shared vectors`() {
        val subKeys = SmartKeyCrypto.deriveSubKeys(ltk, lockId, userId)
        assertEquals(
            vectors.getJSONObject("subkeys").getString("k_beacon"),
            subKeys.kBeacon.encodeHex()
        )
        assertEquals(
            vectors.getJSONObject("subkeys").getString("k_auth"),
            subKeys.kAuth.encodeHex()
        )
    }

    @Test
    fun `rolling pseudonyms match the shared vectors`() {
        val entries = vectors.getJSONArray("pseudonyms")
        for (i in 0 until entries.length()) {
            val entry = entries.getJSONObject(i)
            val epoch = entry.getLong("epoch")
            assertEquals(
                "pseudonym for epoch $epoch",
                entry.getString("pseudonym"),
                SmartKeyCrypto.pseudonym(kBeacon, epoch).encodeHex()
            )
        }
    }

    @Test
    fun `epoch boundaries are 15 seconds apart`() {
        assertEquals(0L, SmartKeyCrypto.epochFor(0))
        assertEquals(0L, SmartKeyCrypto.epochFor(14))
        assertEquals(1L, SmartKeyCrypto.epochFor(15))
        assertEquals(117227520L, SmartKeyCrypto.epochFor(1758412800L))
    }

    @Test
    fun `handshake transcript and tags match the shared vectors`() {
        val handshake = vectors.getJSONObject("handshake")
        val transcript = SmartKeyCrypto.authTranscript(lockId, userId, nonceL, nonceP)

        assertEquals(handshake.getString("transcript"), transcript.encodeHex())
        assertEquals(
            handshake.getString("tag_p"),
            SmartKeyCrypto.tagPhone(kAuth, transcript).encodeHex()
        )
        assertEquals(
            handshake.getString("tag_l"),
            SmartKeyCrypto.tagLock(kAuth, transcript).encodeHex()
        )
        assertEquals(
            handshake.getString("session_id"),
            SmartKeyCrypto.sessionId(kAuth, transcript).encodeHex()
        )
        assertEquals(
            handshake.getString("k_sess"),
            SmartKeyCrypto.sessionKey(kAuth, lockId, userId, nonceL, nonceP).encodeHex()
        )
    }

    @Test
    fun `unlock tag matches the shared vectors`() {
        val event = vectors.getJSONObject("frames").getJSONObject("unlock_event")
        val handshake = vectors.getJSONObject("handshake")
        val tag = SmartKeyCrypto.unlockTag(
            kSess = handshake.getString("k_sess").decodeHex(),
            sessionId = handshake.getString("session_id").decodeHex(),
            counter = event.getInt("counter"),
            result = event.getInt("result")
        )
        assertEquals(event.getString("tag"), tag.encodeHex())
    }

    @Test
    fun `domain separation makes the phone and lock tags differ`() {
        val transcript = SmartKeyCrypto.authTranscript(lockId, userId, nonceL, nonceP)
        assertFalse(
            "a lock tag must never be reusable as a phone tag",
            SmartKeyCrypto.constantTimeEquals(
                SmartKeyCrypto.tagPhone(kAuth, transcript),
                SmartKeyCrypto.tagLock(kAuth, transcript)
            )
        )
    }

    @Test
    fun `a different nonce produces a different tag`() {
        val transcript = SmartKeyCrypto.authTranscript(lockId, userId, nonceL, nonceP)
        val replayed = SmartKeyCrypto.authTranscript(
            lockId, userId, ByteArray(SmartKeyProtocol.NONCE_SIZE) { 0x42 }, nonceP
        )
        assertFalse(
            SmartKeyCrypto.constantTimeEquals(
                SmartKeyCrypto.tagPhone(kAuth, transcript),
                SmartKeyCrypto.tagPhone(kAuth, replayed)
            )
        )
    }

    @Test
    fun `random bytes are the requested length and vary`() {
        val a = SmartKeyCrypto.randomBytes(SmartKeyProtocol.NONCE_SIZE)
        val b = SmartKeyCrypto.randomBytes(SmartKeyProtocol.NONCE_SIZE)
        assertEquals(SmartKeyProtocol.NONCE_SIZE, a.size)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `wipe clears key material`() {
        val secret = SmartKeyCrypto.randomBytes(32)
        SmartKeyCrypto.wipe(secret)
        assertArrayEquals(ByteArray(32), secret)
    }

    @Test
    fun `constant time compare works both ways`() {
        val a = byteArrayOf(1, 2, 3, 4)
        assertTrue(SmartKeyCrypto.constantTimeEquals(a, byteArrayOf(1, 2, 3, 4)))
        assertFalse(SmartKeyCrypto.constantTimeEquals(a, byteArrayOf(1, 2, 3, 5)))
    }
}
