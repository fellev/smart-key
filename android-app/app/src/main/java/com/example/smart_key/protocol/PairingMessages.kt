package com.example.smart_key.protocol

import java.nio.ByteBuffer

/** Pairing frame payloads (pairing-spec.md §3). */

/** PAIR_START (0x10), sent by the phone. */
class PairStart(val userId: ByteArray, val publicKeyP: ByteArray, val nonceP: ByteArray) {

    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.PAIR_START,
        ByteBuffer.allocate(SmartKeyProtocol.PAIR_START_SIZE)
            .put(userId).put(publicKeyP).put(nonceP)
            .array()
    )

    companion object {
        fun parse(frame: Frame): PairStart {
            frame.expect(SmartKeyProtocol.FrameType.PAIR_START, SmartKeyProtocol.PAIR_START_SIZE)
            return PairStart(
                userId = frame.payload.copyOfRange(0, 16),
                publicKeyP = frame.payload.copyOfRange(16, 48),
                nonceP = frame.payload.copyOfRange(48, 64)
            )
        }
    }
}

/** PAIR_RESPONSE (0x11), sent by the lock. */
class PairResponse(
    val lockId: ByteArray,
    val publicKeyL: ByteArray,
    val nonceL: ByteArray,
    val confirmL: ByteArray
) {
    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.PAIR_RESPONSE,
        ByteBuffer.allocate(SmartKeyProtocol.PAIR_RESPONSE_SIZE)
            .put(lockId).put(publicKeyL).put(nonceL).put(confirmL)
            .array()
    )

    companion object {
        fun parse(frame: Frame): PairResponse {
            frame.expect(
                SmartKeyProtocol.FrameType.PAIR_RESPONSE,
                SmartKeyProtocol.PAIR_RESPONSE_SIZE
            )
            return PairResponse(
                lockId = frame.payload.copyOfRange(0, 16),
                publicKeyL = frame.payload.copyOfRange(16, 48),
                nonceL = frame.payload.copyOfRange(48, 64),
                confirmL = frame.payload.copyOfRange(64, 96)
            )
        }
    }
}

/** PAIR_CONFIRM (0x12), sent by the phone. */
fun pairConfirmFrame(confirmP: ByteArray): Frame =
    Frame(SmartKeyProtocol.FrameType.PAIR_CONFIRM, confirmP.copyOf())

/** PAIR_RESULT (0x13), sent by the lock. */
class PairResult(val status: Int, val slot: Int) {

    val isSuccess: Boolean get() = status == SmartKeyProtocol.PairResult.OK

    /** Human readable reason, for the pairing UI. */
    val message: String
        get() = when (status) {
            SmartKeyProtocol.PairResult.OK -> "Paired successfully"
            SmartKeyProtocol.PairResult.BAD_CONFIRM -> "Wrong pairing code"
            SmartKeyProtocol.PairResult.STORE_FULL -> "The lock has no free slots"
            SmartKeyProtocol.PairResult.DISABLED -> "The lock is not in pairing mode"
            else -> "Unknown pairing error ($status)"
        }

    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.PAIR_RESULT,
        byteArrayOf(status.toByte(), slot.toByte(), 0, 0)
    )

    companion object {
        fun parse(frame: Frame): PairResult {
            frame.expect(SmartKeyProtocol.FrameType.PAIR_RESULT, SmartKeyProtocol.PAIR_RESULT_SIZE)
            return PairResult(
                status = frame.payload[0].toInt() and 0xFF,
                slot = frame.payload[1].toInt() and 0xFF
            )
        }
    }
}
