package com.example.smart_key.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Frame codec for SKP1 (protocol-spec.md §3-§7).
 *
 * Pure Kotlin with no Android dependency, so it runs in plain JVM unit tests
 * against the same golden vectors as the firmware.
 */

/** Thrown when a received frame cannot be decoded. */
class ProtocolException(message: String) : Exception(message)

/** A decoded frame header plus its payload. */
class Frame(val type: Byte, val payload: ByteArray) {

    fun encode(): ByteArray {
        require(payload.size <= SmartKeyProtocol.MAX_PAYLOAD) {
            "payload too large: ${payload.size}"
        }
        return ByteBuffer.allocate(SmartKeyProtocol.HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(SmartKeyProtocol.VERSION)
            .put(type)
            .putShort(payload.size.toShort())
            .put(payload)
            .array()
    }

    override fun equals(other: Any?): Boolean =
        other is Frame && type == other.type && payload.contentEquals(other.payload)

    override fun hashCode(): Int = 31 * type.toInt() + payload.contentHashCode()

    override fun toString(): String = "Frame(type=0x%02x, ${payload.size} bytes)".format(type)

    companion object {
        /** Decode a frame; throws [ProtocolException] on any malformed input. */
        fun decode(data: ByteArray): Frame {
            if (data.size < SmartKeyProtocol.HEADER_SIZE) {
                throw ProtocolException("frame truncated: ${data.size} bytes")
            }
            if (data[0] != SmartKeyProtocol.VERSION) {
                throw ProtocolException("unsupported protocol version ${data[0]}")
            }
            val length = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                .getShort(2).toInt() and 0xFFFF
            if (length > SmartKeyProtocol.MAX_PAYLOAD) {
                throw ProtocolException("payload length $length exceeds the maximum")
            }
            if (data.size < SmartKeyProtocol.HEADER_SIZE + length) {
                throw ProtocolException("frame truncated: need ${length + 4}, got ${data.size}")
            }
            return Frame(
                data[1],
                data.copyOfRange(
                    SmartKeyProtocol.HEADER_SIZE,
                    SmartKeyProtocol.HEADER_SIZE + length
                )
            )
        }
    }
}

/** Validate the type and payload size of a decoded frame. */
internal fun Frame.expect(expectedType: Byte, size: Int) {
    if (type != expectedType) {
        throw ProtocolException(
            "expected frame type 0x%02x but got 0x%02x".format(expectedType, type)
        )
    }
    if (payload.size != size) {
        throw ProtocolException(
            "frame 0x%02x has ${payload.size} payload bytes, expected $size".format(expectedType)
        )
    }
}

/** Empty frames: PRESENCE_PING / PRESENCE_PONG. */
fun emptyFrame(type: Byte): Frame = Frame(type, ByteArray(0))

/** ERROR (0x7F). */
fun errorFrame(code: Int, detail: Int = 0): Frame =
    Frame(SmartKeyProtocol.FrameType.ERROR, byteArrayOf(code.toByte(), detail.toByte()))
