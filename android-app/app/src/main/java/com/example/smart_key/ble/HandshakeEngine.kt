package com.example.smart_key.ble

import android.util.Log
import com.example.smart_key.data.Credential
import com.example.smart_key.protocol.Auth
import com.example.smart_key.protocol.Frame
import com.example.smart_key.protocol.Hello
import com.example.smart_key.protocol.SessionOk
import com.example.smart_key.protocol.SmartKeyCrypto
import com.example.smart_key.protocol.SmartKeyProtocol
import com.example.smart_key.protocol.UnlockAck
import com.example.smart_key.protocol.UnlockEvent
import com.example.smart_key.protocol.emptyFrame
import com.example.smart_key.protocol.errorFrame

/**
 * Phone side of the presence handshake (protocol-spec.md §5).
 *
 * Pure logic with no Android dependency: frames in, outcomes out. That keeps
 * it unit testable against the shared golden vectors and keeps all the crypto
 * in one small, reviewable place.
 */
class HandshakeEngine(private val credentials: List<Credential>) {

    /** What the transport should do with the engine's answer. */
    sealed class Outcome {
        /** Send this frame back to the lock. */
        class Reply(val frame: Frame) : Outcome()

        /** Handshake completed; the lock proved it is authentic. */
        class Authenticated(val credential: Credential, val session: Session) : Outcome()

        /** The lock reported an unlock attempt; [reply] acknowledges it. */
        class Unlock(val result: Int, val reply: Frame) : Outcome()

        /** Something went wrong; disconnect (and warn the user if [alarming]). */
        class Abort(val reason: String, val alarming: Boolean = false) : Outcome()

        /** Nothing to do. */
        object Ignore : Outcome()
    }

    /** Session material established by a successful handshake. */
    class Session(val sessionId: ByteArray, val sessionKey: ByteArray, val ttlSeconds: Int)

    private var session: Session? = null
    private var credential: Credential? = null
    private var pendingTranscript: ByteArray? = null
    private var pendingNonceL: ByteArray? = null
    private var pendingNonceP: ByteArray? = null

    /** The verified session, or null while unauthenticated. */
    val activeSession: Session? get() = session

    /** Process one frame received from the lock. */
    fun onFrame(data: ByteArray): Outcome = try {
        dispatch(Frame.decode(data))
    } catch (e: Exception) {
        Log.w(TAG, "rejected frame: ${e.message}")
        Outcome.Reply(errorFrame(SmartKeyProtocol.ErrorCode.MALFORMED_FRAME))
    }

    private fun dispatch(frame: Frame): Outcome = when (frame.type) {
        SmartKeyProtocol.FrameType.HELLO -> onHello(frame)
        SmartKeyProtocol.FrameType.SESSION_OK -> onSessionOk(frame)
        SmartKeyProtocol.FrameType.UNLOCK_EVENT -> onUnlockEvent(frame)
        SmartKeyProtocol.FrameType.PRESENCE_PING ->
            Outcome.Reply(emptyFrame(SmartKeyProtocol.FrameType.PRESENCE_PONG))
        SmartKeyProtocol.FrameType.ERROR -> {
            val code = frame.payload.firstOrNull()?.toInt() ?: 0
            Outcome.Abort("the lock reported error 0x%02x".format(code))
        }
        else -> Outcome.Ignore
    }

    /** HELLO -> look up the credential and answer with AUTH (spec §5.2). */
    private fun onHello(frame: Frame): Outcome {
        val hello = Hello.parse(frame)
        val match = credentials.firstOrNull { it.lockId.contentEquals(hello.lockId) }
            ?: return Outcome.Reply(errorFrame(SmartKeyProtocol.ErrorCode.NOT_PAIRED))

        val nonceP = SmartKeyCrypto.randomBytes(SmartKeyProtocol.NONCE_SIZE)
        val transcript = SmartKeyCrypto.authTranscript(
            lockId = match.lockId,
            userId = match.userId,
            nonceL = hello.nonceL,
            nonceP = nonceP
        )

        // Remember what we need in order to verify the lock's answer.
        credential = match
        pendingTranscript = transcript
        pendingNonceL = hello.nonceL
        pendingNonceP = nonceP

        val auth = Auth(
            userId = match.userId,
            nonceP = nonceP,
            tagP = SmartKeyCrypto.tagPhone(match.kAuth, transcript)
        )
        return Outcome.Reply(auth.toFrame())
    }

    /**
     * SESSION_OK -> verify the lock's tag before trusting it (spec §5.3).
     *
     * A mismatch means we are talking to an impostor, which is worth telling
     * the user about (security-model.md, threat A2).
     */
    private fun onSessionOk(frame: Frame): Outcome {
        val cred = credential ?: return Outcome.Abort("SESSION_OK before HELLO")
        val transcript = pendingTranscript ?: return Outcome.Abort("SESSION_OK out of order")
        val sessionOk = SessionOk.parse(frame)

        val expectedTag = SmartKeyCrypto.tagLock(cred.kAuth, transcript)
        if (!SmartKeyCrypto.constantTimeEquals(expectedTag, sessionOk.tagL)) {
            return Outcome.Abort("the door unit failed authentication", alarming = true)
        }
        val expectedId = SmartKeyCrypto.sessionId(cred.kAuth, transcript)
        if (!SmartKeyCrypto.constantTimeEquals(expectedId, sessionOk.sessionId)) {
            return Outcome.Abort("session id mismatch", alarming = true)
        }
        if (!sessionOk.grant) {
            return Outcome.Abort("the door unit denied access")
        }

        val newSession = Session(
            sessionId = sessionOk.sessionId,
            sessionKey = SmartKeyCrypto.sessionKey(
                kAuth = cred.kAuth,
                lockId = cred.lockId,
                userId = cred.userId,
                nonceL = pendingNonceL!!,
                nonceP = pendingNonceP!!
            ),
            ttlSeconds = sessionOk.ttlSeconds
        )
        session = newSession
        Log.i(TAG, "authenticated with lock ${cred.shortId}")
        return Outcome.Authenticated(cred, newSession)
    }

    /** UNLOCK_EVENT -> verify the tag, then acknowledge (spec §6). */
    private fun onUnlockEvent(frame: Frame): Outcome {
        val current = session ?: return Outcome.Ignore
        val event = UnlockEvent.parse(frame)

        if (!SmartKeyCrypto.constantTimeEquals(event.sessionId, current.sessionId)) {
            return Outcome.Ignore
        }
        val expected = SmartKeyCrypto.unlockTag(
            current.sessionKey, event.sessionId, event.counter, event.result
        )
        if (!SmartKeyCrypto.constantTimeEquals(expected, event.tag)) {
            Log.w(TAG, "unlock event with a bad tag, ignoring")
            return Outcome.Ignore
        }
        return Outcome.Unlock(
            result = event.result,
            reply = UnlockAck(event.sessionId, event.counter).toFrame()
        )
    }

    /** Forget the session, e.g. after a disconnect. */
    fun reset() {
        session?.let { SmartKeyCrypto.wipe(it.sessionKey) }
        session = null
        credential = null
        pendingTranscript = null
        pendingNonceL = null
        pendingNonceP = null
    }

    companion object {
        private const val TAG = "HandshakeEngine"
    }
}
