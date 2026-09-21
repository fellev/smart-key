package com.example.smart_key.protocol

import com.example.smart_key.pairing.PairingSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pairing key agreement against shared-protocols/test-vectors/pairing.json.
 *
 * X25519 runs through the JDK provider, which the plain JVM unit test runtime
 * supplies, so no device is needed.
 */
class PairingTest {

    private val vectors = SharedVectors.pairing
    private val inputs = vectors.getJSONObject("inputs")
    private val ecdh = vectors.getJSONObject("x25519")

    private val lockId = inputs.getString("lock_id").decodeHex()
    private val userId = inputs.getString("user_id").decodeHex()
    private val privP = inputs.getString("private_phone").decodeHex()
    private val privL = inputs.getString("private_lock").decodeHex()
    private val nonceP = inputs.getString("nonce_p").decodeHex()
    private val nonceL = inputs.getString("nonce_l").decodeHex()
    private val code = inputs.getString("pairing_code")

    private val pubP = ecdh.getString("public_phone").decodeHex()
    private val pubL = ecdh.getString("public_lock").decodeHex()

    @Test
    fun `x25519 public keys match the shared vectors`() {
        assertEquals(ecdh.getString("public_phone"), X25519.publicKeyFromPrivate(privP).encodeHex())
        assertEquals(ecdh.getString("public_lock"), X25519.publicKeyFromPrivate(privL).encodeHex())
    }

    @Test
    fun `both sides derive the same shared secret`() {
        val fromPhone = X25519.computeShared(X25519.privateKeyFromBytes(privP), pubL)
        val fromLock = X25519.computeShared(X25519.privateKeyFromBytes(privL), pubP)
        assertEquals(ecdh.getString("shared"), fromPhone.encodeHex())
        assertEquals(ecdh.getString("shared"), fromLock.encodeHex())
    }

    @Test
    fun `pair transcript and long term key match the shared vectors`() {
        val transcript = SmartKeyCrypto.pairTranscript(
            lockId = lockId,
            userId = userId,
            publicKeyP = pubP,
            publicKeyL = pubL,
            nonceP = nonceP,
            nonceL = nonceL
        )
        assertEquals(vectors.getString("transcript"), transcript.encodeHex())

        val shared = ecdh.getString("shared").decodeHex()
        val ltk = SmartKeyCrypto.pairLtk(shared, nonceP, nonceL, transcript, code)
        assertEquals(vectors.getString("ltk"), ltk.encodeHex())

        assertEquals(
            vectors.getString("confirm_l"),
            SmartKeyCrypto.pairConfirmLock(ltk, transcript).encodeHex()
        )
        assertEquals(
            vectors.getString("confirm_p"),
            SmartKeyCrypto.pairConfirmPhone(ltk, transcript).encodeHex()
        )
    }

    @Test
    fun `a wrong pairing code yields a different key`() {
        val transcript =
            SmartKeyCrypto.pairTranscript(lockId, userId, pubP, pubL, nonceP, nonceL)
        val shared = ecdh.getString("shared").decodeHex()
        val wrong = SmartKeyCrypto.pairLtk(shared, nonceP, nonceL, transcript, "00000000")

        assertEquals(vectors.getString("wrong_code_ltk"), wrong.encodeHex())
        assertFalse(
            "a wrong code must never produce the right key",
            wrong.encodeHex() == vectors.getString("ltk")
        )
    }

    @Test
    fun `sub keys derived after pairing match the shared vectors`() {
        val derived = vectors.getJSONObject("derived_subkeys")
        val subKeys = SmartKeyCrypto.deriveSubKeys(
            vectors.getString("ltk").decodeHex(), lockId, userId
        )
        assertEquals(derived.getString("k_auth"), subKeys.kAuth.encodeHex())
        assertEquals(derived.getString("k_beacon"), subKeys.kBeacon.encodeHex())
    }

    @Test
    fun `pairing frames match the shared encodings`() {
        val frames = vectors.getJSONObject("frames")

        assertEquals(
            frames.getString("pair_start"),
            PairStart(userId, pubP, nonceP).toFrame().encode().encodeHex()
        )
        assertEquals(
            frames.getString("pair_response"),
            PairResponse(
                lockId, pubL, nonceL, vectors.getString("confirm_l").decodeHex()
            ).toFrame().encode().encodeHex()
        )
        assertEquals(
            frames.getString("pair_confirm"),
            pairConfirmFrame(vectors.getString("confirm_p").decodeHex()).encode().encodeHex()
        )
        assertEquals(
            frames.getString("pair_result_ok"),
            PairResult(SmartKeyProtocol.PairResult.OK, 0).toFrame().encode().encodeHex()
        )
    }

    /**
     * Full session run with the lock played back from the golden vectors: the
     * session must accept the genuine confirmation and derive the right key.
     */
    @Test
    fun `pairing session completes against the golden lock responses`() {
        val session = newSession()
        assertEquals(
            vectors.getJSONObject("frames").getString("pair_start"),
            session.start().encode().encodeHex()
        )

        val response = PairResponse(
            lockId, pubL, nonceL, vectors.getString("confirm_l").decodeHex()
        ).toFrame().encode()

        val step = session.onFrame(response)
        assertTrue("expected a confirmation frame", step is PairingSession.Step.Send)
        assertEquals(
            vectors.getJSONObject("frames").getString("pair_confirm"),
            (step as PairingSession.Step.Send).frame.encode().encodeHex()
        )

        val result = session.onFrame(
            PairResult(SmartKeyProtocol.PairResult.OK, 3).toFrame().encode()
        )
        assertTrue(result is PairingSession.Step.Success)
        result as PairingSession.Step.Success
        assertEquals(vectors.getString("ltk"), result.ltk.encodeHex())
        assertEquals(3, result.slot)
    }

    /** A lock that cannot produce the right confirmation must be rejected. */
    @Test
    fun `pairing session rejects a bad confirmation`() {
        val session = newSession()
        session.start()

        val tampered = vectors.getString("confirm_l").decodeHex().also { it[0]++ }
        val step = session.onFrame(PairResponse(lockId, pubL, nonceL, tampered).toFrame().encode())
        assertTrue(step is PairingSession.Step.Failure)
    }

    /** Entering the wrong code must fail, not silently store a useless key. */
    @Test
    fun `pairing session rejects a wrong pairing code`() {
        val session = PairingSession(
            userId = userId,
            pairingCode = "00000000",
            keyPair = X25519.KeyPair(X25519.privateKeyFromBytes(privP), pubP),
            nonceP = nonceP
        )
        session.start()

        val genuine = PairResponse(
            lockId, pubL, nonceL, vectors.getString("confirm_l").decodeHex()
        ).toFrame().encode()
        assertTrue(session.onFrame(genuine) is PairingSession.Step.Failure)
    }

    /** Deterministic session that replays the fixed vectors. */
    private fun newSession() = PairingSession(
        userId = userId,
        pairingCode = code,
        keyPair = X25519.KeyPair(X25519.privateKeyFromBytes(privP), pubP),
        nonceP = nonceP
    )
}
