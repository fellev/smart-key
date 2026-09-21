package com.example.smart_key.pairing

import com.example.smart_key.protocol.Frame
import com.example.smart_key.protocol.PairResponse
import com.example.smart_key.protocol.PairResult
import com.example.smart_key.protocol.PairStart
import com.example.smart_key.protocol.SmartKeyCrypto
import com.example.smart_key.protocol.SmartKeyProtocol
import com.example.smart_key.protocol.X25519
import com.example.smart_key.protocol.pairConfirmFrame
import java.security.PrivateKey

/**
 * Phone side of the pairing exchange (pairing-spec.md §2).
 *
 * Transport independent so it can be unit tested against the shared golden
 * vectors: feed it frames, take the frames it produces.
 */
class PairingSession(
    private val userId: ByteArray,
    private val pairingCode: String,
    keyPair: X25519.KeyPair = X25519.generateKeyPair(),
    private val nonceP: ByteArray = SmartKeyCrypto.randomBytes(SmartKeyProtocol.NONCE_SIZE)
) {
    /** Outcome of feeding a frame to the session. */
    sealed class Step {
        /** Write this frame to the lock's PAIRING characteristic. */
        class Send(val frame: Frame) : Step()

        /** Pairing succeeded; store [ltk] for [lockId], then wipe it. */
        class Success(val lockId: ByteArray, val ltk: ByteArray, val slot: Int) : Step()

        /** Pairing failed; [message] is safe to show to the user. */
        class Failure(val message: String) : Step()

        /** Nothing to do yet. */
        object Waiting : Step()
    }

    private val privateKey: PrivateKey = keyPair.privateKey
    private val publicKeyP: ByteArray = keyPair.publicKeyBytes

    private var ltk: ByteArray? = null
    private var lockId: ByteArray? = null

    init {
        require(pairingCode.length == SmartKeyProtocol.PAIRING_CODE_LEN) {
            "the pairing code must be ${SmartKeyProtocol.PAIRING_CODE_LEN} digits"
        }
    }

    /** First frame to send once connected to the lock. */
    fun start(): Frame = PairStart(userId, publicKeyP, nonceP).toFrame()

    /** Feed a frame received from the lock. */
    fun onFrame(data: ByteArray): Step = try {
        val frame = Frame.decode(data)
        when (frame.type) {
            SmartKeyProtocol.FrameType.PAIR_RESPONSE -> onPairResponse(frame)
            SmartKeyProtocol.FrameType.PAIR_RESULT -> onPairResult(frame)
            else -> Step.Waiting
        }
    } catch (e: Exception) {
        Step.Failure("Malformed response from the door unit")
    }

    /**
     * Verify the lock's confirmation, which simultaneously proves that it knew
     * the pairing code, then answer with our own confirmation.
     */
    private fun onPairResponse(frame: Frame): Step {
        val response = PairResponse.parse(frame)

        val shared = try {
            X25519.computeShared(privateKey, response.publicKeyL)
        } catch (e: IllegalStateException) {
            return Step.Failure("The door unit sent an invalid key")
        }

        val transcript = SmartKeyCrypto.pairTranscript(
            lockId = response.lockId,
            userId = userId,
            publicKeyP = publicKeyP,
            publicKeyL = response.publicKeyL,
            nonceP = nonceP,
            nonceL = response.nonceL
        )
        val candidate = SmartKeyCrypto.pairLtk(
            sharedZ = shared,
            nonceP = nonceP,
            nonceL = response.nonceL,
            transcript = transcript,
            pairingCode = pairingCode
        )
        SmartKeyCrypto.wipe(shared)

        // A wrong code produces a different key, so this check fails first.
        val expected = SmartKeyCrypto.pairConfirmLock(candidate, transcript)
        if (!SmartKeyCrypto.constantTimeEquals(expected, response.confirmL)) {
            SmartKeyCrypto.wipe(candidate)
            return Step.Failure("Wrong pairing code, or the door unit is not genuine")
        }

        ltk = candidate
        lockId = response.lockId
        return Step.Send(pairConfirmFrame(SmartKeyCrypto.pairConfirmPhone(candidate, transcript)))
    }

    private fun onPairResult(frame: Frame): Step {
        val result = PairResult.parse(frame)
        val key = ltk
        val id = lockId
        if (!result.isSuccess) {
            key?.let { SmartKeyCrypto.wipe(it) }
            ltk = null
            return Step.Failure(result.message)
        }
        if (key == null || id == null) {
            return Step.Failure("The door unit confirmed pairing too early")
        }
        return Step.Success(id, key, result.slot)
    }

    /** Drop any key material still held by the session. */
    fun cancel() {
        ltk?.let { SmartKeyCrypto.wipe(it) }
        ltk = null
        lockId = null
    }
}
