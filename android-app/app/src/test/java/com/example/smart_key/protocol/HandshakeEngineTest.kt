package com.example.smart_key.protocol

import com.example.smart_key.ble.HandshakeEngine
import com.example.smart_key.data.Credential
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Exercises the phone's handshake state machine by playing the role of the
 * door unit with the keys from shared-protocols/test-vectors/handshake.json.
 *
 * These tests are the security regression net: they prove the app refuses an
 * impostor lock, rejects replays and ignores forged unlock reports.
 */
class HandshakeEngineTest {

    private val vectors = SharedVectors.handshake
    private val inputs = vectors.getJSONObject("inputs")

    private val lockId = inputs.getString("lock_id").decodeHex()
    private val userId = inputs.getString("user_id").decodeHex()
    private val kAuth = vectors.getJSONObject("subkeys").getString("k_auth").decodeHex()
    private val kBeacon = vectors.getJSONObject("subkeys").getString("k_beacon").decodeHex()

    private val credential = Credential(
        lockId = lockId,
        userId = userId,
        kAuth = kAuth,
        kBeacon = kBeacon,
        label = "Front door",
        pairedAtEpochSeconds = 0
    )

    private fun engine() = HandshakeEngine(listOf(credential))

    private fun helloFrame(nonceL: ByteArray) =
        Hello(lockId, nonceL, caps = 0x03).toFrame().encode()

    /** Replay the lock's side of the handshake; returns the session and nonce_p. */
    private fun completeHandshake(
        engine: HandshakeEngine,
        nonceL: ByteArray = inputs.getString("nonce_l").decodeHex()
    ): Pair<HandshakeEngine.Session, ByteArray> {
        val authOutcome = engine.onFrame(helloFrame(nonceL))
        assertTrue(authOutcome is HandshakeEngine.Outcome.Reply)
        val auth = Auth.parse((authOutcome as HandshakeEngine.Outcome.Reply).frame)

        // The lock recomputes the transcript from the phone's fresh nonce.
        val transcript = SmartKeyCrypto.authTranscript(lockId, userId, nonceL, auth.nonceP)
        assertArrayEquals(
            "the phone must prove knowledge of K_auth",
            SmartKeyCrypto.tagPhone(kAuth, transcript),
            auth.tagP
        )

        val sessionOk = SessionOk(
            tagL = SmartKeyCrypto.tagLock(kAuth, transcript),
            sessionId = SmartKeyCrypto.sessionId(kAuth, transcript),
            grant = true,
            ttlSeconds = 10
        ).toFrame().encode()

        val outcome = engine.onFrame(sessionOk)
        assertTrue("handshake should succeed", outcome is HandshakeEngine.Outcome.Authenticated)
        return (outcome as HandshakeEngine.Outcome.Authenticated).session to auth.nonceP
    }

    @Test
    fun `a genuine lock is authenticated`() {
        val engine = engine()
        val (session, nonceP) = completeHandshake(engine)

        val expectedKey = SmartKeyCrypto.sessionKey(
            kAuth, lockId, userId, inputs.getString("nonce_l").decodeHex(), nonceP
        )
        assertArrayEquals(expectedKey, session.sessionKey)
        assertEquals(10, session.ttlSeconds)
    }

    @Test
    fun `an unknown lock gets NOT_PAIRED`() {
        val stranger = Hello(ByteArray(16) { 0x55 }, ByteArray(16), 0x03).toFrame().encode()
        val outcome = engine().onFrame(stranger)

        assertTrue(outcome is HandshakeEngine.Outcome.Reply)
        val frame = (outcome as HandshakeEngine.Outcome.Reply).frame
        assertEquals(SmartKeyProtocol.FrameType.ERROR, frame.type)
        assertEquals(SmartKeyProtocol.ErrorCode.NOT_PAIRED, frame.payload[0].toInt())
    }

    @Test
    fun `an impostor lock is rejected and raises an alarm`() {
        val engine = engine()
        engine.onFrame(helloFrame(inputs.getString("nonce_l").decodeHex()))

        // An attacker without K_auth can only guess the tag.
        val forged = SessionOk(
            tagL = ByteArray(32) { 0x11 },
            sessionId = ByteArray(8) { 0x22 },
            grant = true,
            ttlSeconds = 10
        ).toFrame().encode()

        val outcome = engine.onFrame(forged)
        assertTrue(outcome is HandshakeEngine.Outcome.Abort)
        assertTrue(
            "an impostor must be surfaced to the user",
            (outcome as HandshakeEngine.Outcome.Abort).alarming
        )
    }

    @Test
    fun `a replayed SESSION_OK from an earlier session is rejected`() {
        // Capture a genuine SESSION_OK produced for one phone nonce...
        val first = engine()
        val nonceL = inputs.getString("nonce_l").decodeHex()
        val reply = first.onFrame(helloFrame(nonceL)) as HandshakeEngine.Outcome.Reply
        val oldAuth = Auth.parse(reply.frame)
        val oldTranscript = SmartKeyCrypto.authTranscript(lockId, userId, nonceL, oldAuth.nonceP)
        val captured = SessionOk(
            tagL = SmartKeyCrypto.tagLock(kAuth, oldTranscript),
            sessionId = SmartKeyCrypto.sessionId(kAuth, oldTranscript),
            grant = true,
            ttlSeconds = 10
        ).toFrame().encode()

        // ...and replay it into a fresh session, which uses a fresh nonce_p.
        val second = engine()
        second.onFrame(helloFrame(nonceL))
        assertTrue(
            "a replayed SESSION_OK must not authenticate",
            second.onFrame(captured) is HandshakeEngine.Outcome.Abort
        )
    }

    @Test
    fun `a denied grant does not create a session`() {
        val engine = engine()
        val nonceL = inputs.getString("nonce_l").decodeHex()
        val reply = engine.onFrame(helloFrame(nonceL)) as HandshakeEngine.Outcome.Reply
        val auth = Auth.parse(reply.frame)
        val transcript = SmartKeyCrypto.authTranscript(lockId, userId, nonceL, auth.nonceP)

        val denied = SessionOk(
            tagL = SmartKeyCrypto.tagLock(kAuth, transcript),
            sessionId = SmartKeyCrypto.sessionId(kAuth, transcript),
            grant = false,
            ttlSeconds = 10
        ).toFrame().encode()

        assertTrue(engine.onFrame(denied) is HandshakeEngine.Outcome.Abort)
    }

    @Test
    fun `presence pings are answered with pongs`() {
        val outcome = engine().onFrame(
            emptyFrame(SmartKeyProtocol.FrameType.PRESENCE_PING).encode()
        )
        assertTrue(outcome is HandshakeEngine.Outcome.Reply)
        assertEquals(
            SmartKeyProtocol.FrameType.PRESENCE_PONG,
            (outcome as HandshakeEngine.Outcome.Reply).frame.type
        )
    }

    @Test
    fun `a valid unlock event is acknowledged`() {
        val engine = engine()
        val (session, _) = completeHandshake(engine)

        val event = UnlockEvent(
            sessionId = session.sessionId,
            counter = 1,
            result = SmartKeyProtocol.UnlockResult.OK,
            tag = SmartKeyCrypto.unlockTag(
                session.sessionKey, session.sessionId, 1, SmartKeyProtocol.UnlockResult.OK
            )
        ).toFrame().encode()

        val outcome = engine.onFrame(event)
        assertTrue(outcome is HandshakeEngine.Outcome.Unlock)
        outcome as HandshakeEngine.Outcome.Unlock
        assertEquals(SmartKeyProtocol.UnlockResult.OK, outcome.result)

        val ack = UnlockAck.parse(outcome.reply)
        assertEquals(1, ack.counter)
        assertArrayEquals(session.sessionId, ack.sessionId)
    }

    @Test
    fun `a forged unlock event is ignored`() {
        val engine = engine()
        val (session, _) = completeHandshake(engine)

        val forged = UnlockEvent(
            sessionId = session.sessionId,
            counter = 99,
            result = SmartKeyProtocol.UnlockResult.OK,
            tag = ByteArray(32) { 0x7E }
        ).toFrame().encode()

        assertTrue(engine.onFrame(forged) === HandshakeEngine.Outcome.Ignore)
    }

    @Test
    fun `an unlock event before authentication is ignored`() {
        val event = UnlockEvent(ByteArray(8), 1, 0, ByteArray(32)).toFrame().encode()
        assertTrue(engine().onFrame(event) === HandshakeEngine.Outcome.Ignore)
    }

    @Test
    fun `malformed input never crashes the engine`() {
        // Header claims 0x40 payload bytes but only one follows.
        val outcome = engine().onFrame(byteArrayOf(0x01, 0x01, 0x40, 0x00, 0x00))
        assertTrue(outcome is HandshakeEngine.Outcome.Reply)
        assertEquals(
            SmartKeyProtocol.FrameType.ERROR,
            (outcome as HandshakeEngine.Outcome.Reply).frame.type
        )
    }
}
