package com.example.smart_key.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Typed payloads of the SKP1 frames (protocol-spec.md §5, §6 and
 * pairing-spec.md §3). Byte offsets match the firmware structs exactly.
 */

/** HELLO (0x01), sent by the lock. */
class Hello(val lockId: ByteArray, val nonceL: ByteArray, val caps: Byte) {

    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.HELLO,
        ByteBuffer.allocate(SmartKeyProtocol.HELLO_SIZE)
            .put(lockId).put(nonceL).put(caps).put(0)
            .array()
    )

    companion object {
        fun parse(frame: Frame): Hello {
            frame.expect(SmartKeyProtocol.FrameType.HELLO, SmartKeyProtocol.HELLO_SIZE)
            return Hello(
                lockId = frame.payload.copyOfRange(0, 16),
                nonceL = frame.payload.copyOfRange(16, 32),
                caps = frame.payload[32]
            )
        }
    }
}

/** AUTH (0x02), sent by the phone. */
class Auth(val userId: ByteArray, val nonceP: ByteArray, val tagP: ByteArray) {

    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.AUTH,
        ByteBuffer.allocate(SmartKeyProtocol.AUTH_SIZE)
            .put(userId).put(nonceP).put(tagP)
            .array()
    )

    companion object {
        fun parse(frame: Frame): Auth {
            frame.expect(SmartKeyProtocol.FrameType.AUTH, SmartKeyProtocol.AUTH_SIZE)
            return Auth(
                userId = frame.payload.copyOfRange(0, 16),
                nonceP = frame.payload.copyOfRange(16, 32),
                tagP = frame.payload.copyOfRange(32, 64)
            )
        }
    }
}

/** SESSION_OK (0x03), sent by the lock. */
class SessionOk(
    val tagL: ByteArray,
    val sessionId: ByteArray,
    val grant: Boolean,
    val ttlSeconds: Int
) {
    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.SESSION_OK,
        ByteBuffer.allocate(SmartKeyProtocol.SESSION_OK_SIZE)
            .put(tagL).put(sessionId)
            .put(if (grant) 1 else 0).put(ttlSeconds.toByte())
            .array()
    )

    companion object {
        fun parse(frame: Frame): SessionOk {
            frame.expect(SmartKeyProtocol.FrameType.SESSION_OK, SmartKeyProtocol.SESSION_OK_SIZE)
            return SessionOk(
                tagL = frame.payload.copyOfRange(0, 32),
                sessionId = frame.payload.copyOfRange(32, 40),
                grant = frame.payload[40].toInt() != 0,
                ttlSeconds = frame.payload[41].toInt() and 0xFF
            )
        }
    }
}

/** UNLOCK_EVENT (0x04), sent by the lock. */
class UnlockEvent(
    val sessionId: ByteArray,
    val counter: Int,
    val result: Int,
    val tag: ByteArray
) {
    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.UNLOCK_EVENT,
        ByteBuffer.allocate(SmartKeyProtocol.UNLOCK_EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .put(sessionId).putInt(counter).put(result.toByte()).put(0).put(tag)
            .array()
    )

    companion object {
        fun parse(frame: Frame): UnlockEvent {
            frame.expect(
                SmartKeyProtocol.FrameType.UNLOCK_EVENT,
                SmartKeyProtocol.UNLOCK_EVENT_SIZE
            )
            val buffer = ByteBuffer.wrap(frame.payload).order(ByteOrder.LITTLE_ENDIAN)
            return UnlockEvent(
                sessionId = frame.payload.copyOfRange(0, 8),
                counter = buffer.getInt(8),
                result = frame.payload[12].toInt() and 0xFF,
                tag = frame.payload.copyOfRange(14, 46)
            )
        }
    }
}

/** UNLOCK_ACK (0x05), sent by the phone. */
class UnlockAck(val sessionId: ByteArray, val counter: Int) {

    fun toFrame(): Frame = Frame(
        SmartKeyProtocol.FrameType.UNLOCK_ACK,
        ByteBuffer.allocate(SmartKeyProtocol.UNLOCK_ACK_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .put(sessionId).putInt(counter)
            .array()
    )

    companion object {
        fun parse(frame: Frame): UnlockAck {
            frame.expect(SmartKeyProtocol.FrameType.UNLOCK_ACK, SmartKeyProtocol.UNLOCK_ACK_SIZE)
            val buffer = ByteBuffer.wrap(frame.payload).order(ByteOrder.LITTLE_ENDIAN)
            return UnlockAck(frame.payload.copyOfRange(0, 8), buffer.getInt(8))
        }
    }
}
