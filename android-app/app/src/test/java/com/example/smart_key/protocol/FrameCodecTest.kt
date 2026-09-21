package com.example.smart_key.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Byte-exact checks of the frame codec against the shared golden vectors, so
 * the Kotlin encoder and the C encoder can never disagree on the wire format.
 */
class FrameCodecTest {

    private val vectors = SharedVectors.handshake
    private val frames = vectors.getJSONObject("frames")
    private val inputs = vectors.getJSONObject("inputs")
    private val handshake = vectors.getJSONObject("handshake")

    private fun expected(name: String): String =
        frames.getJSONObject(name).getString("encoded")

    private fun assertThrowsProtocol(block: () -> Unit) {
        try {
            block()
            fail("expected a ProtocolException")
        } catch (expected: ProtocolException) {
            // success
        }
    }

    @Test
    fun `hello encodes and decodes byte for byte`() {
        val hello = Hello(
            lockId = inputs.getString("lock_id").decodeHex(),
            nonceL = inputs.getString("nonce_l").decodeHex(),
            caps = 0x03
        )
        val encoded = hello.toFrame().encode()
        assertEquals(expected("hello"), encoded.encodeHex())

        val decoded = Hello.parse(Frame.decode(encoded))
        assertArrayEquals(hello.lockId, decoded.lockId)
        assertArrayEquals(hello.nonceL, decoded.nonceL)
        assertEquals(hello.caps, decoded.caps)
    }

    @Test
    fun `auth encodes and decodes byte for byte`() {
        val auth = Auth(
            userId = inputs.getString("user_id").decodeHex(),
            nonceP = inputs.getString("nonce_p").decodeHex(),
            tagP = handshake.getString("tag_p").decodeHex()
        )
        val encoded = auth.toFrame().encode()
        assertEquals(expected("auth"), encoded.encodeHex())
        assertArrayEquals(auth.tagP, Auth.parse(Frame.decode(encoded)).tagP)
    }

    @Test
    fun `session ok encodes and decodes byte for byte`() {
        val sessionOk = SessionOk(
            tagL = handshake.getString("tag_l").decodeHex(),
            sessionId = handshake.getString("session_id").decodeHex(),
            grant = true,
            ttlSeconds = 10
        )
        val encoded = sessionOk.toFrame().encode()
        assertEquals(expected("session_ok"), encoded.encodeHex())

        val decoded = SessionOk.parse(Frame.decode(encoded))
        assertTrue(decoded.grant)
        assertEquals(10, decoded.ttlSeconds)
        assertArrayEquals(sessionOk.tagL, decoded.tagL)
    }

    @Test
    fun `unlock event encodes and decodes byte for byte`() {
        val source = frames.getJSONObject("unlock_event")
        val event = UnlockEvent(
            sessionId = handshake.getString("session_id").decodeHex(),
            counter = source.getInt("counter"),
            result = source.getInt("result"),
            tag = source.getString("tag").decodeHex()
        )
        val encoded = event.toFrame().encode()
        assertEquals(expected("unlock_event"), encoded.encodeHex())

        val decoded = UnlockEvent.parse(Frame.decode(encoded))
        assertEquals(event.counter, decoded.counter)
        assertEquals(event.result, decoded.result)
        assertArrayEquals(event.tag, decoded.tag)
    }

    @Test
    fun `unlock ack round trips`() {
        val ack = UnlockAck(handshake.getString("session_id").decodeHex(), 0x01020304)
        val decoded = UnlockAck.parse(Frame.decode(ack.toFrame().encode()))
        assertEquals(ack.counter, decoded.counter)
        assertArrayEquals(ack.sessionId, decoded.sessionId)
    }

    @Test
    fun `empty and error frames match the shared vectors`() {
        assertEquals(
            expected("presence_ping"),
            emptyFrame(SmartKeyProtocol.FrameType.PRESENCE_PING).encode().encodeHex()
        )
        assertEquals(
            expected("error_auth_failed"),
            errorFrame(SmartKeyProtocol.ErrorCode.AUTH_FAILED).encode().encodeHex()
        )
    }

    @Test
    fun `truncated frames are rejected`() {
        assertThrowsProtocol { Frame.decode(byteArrayOf(0x01, 0x01, 0x00)) }
        // header announces 10 payload bytes but only 2 follow
        assertThrowsProtocol {
            Frame.decode(byteArrayOf(0x01, 0x01, 0x0A, 0x00, 0xAA.toByte(), 0xBB.toByte()))
        }
    }

    @Test
    fun `unsupported versions are rejected`() {
        assertThrowsProtocol { Frame.decode(byteArrayOf(0x02, 0x01, 0x00, 0x00)) }
    }

    @Test
    fun `oversized payload lengths are rejected`() {
        assertThrowsProtocol { Frame.decode(byteArrayOf(0x01, 0x01, 0xFF.toByte(), 0x00)) }
    }

    @Test
    fun `a wrong frame type is rejected by the typed parser`() {
        assertThrowsProtocol {
            Hello.parse(emptyFrame(SmartKeyProtocol.FrameType.PRESENCE_PONG))
        }
    }

    @Test
    fun `advertisement payload matches the shared vector`() {
        val adv = vectors.getJSONObject("advertisement")
        val beacon = SmartKeyAdvertisement(
            flags = adv.getInt("flags"),
            pseudonym = SmartKeyCrypto.pseudonym(
                vectors.getJSONObject("subkeys").getString("k_beacon").decodeHex(),
                adv.getLong("epoch")
            ),
            batteryPercent = adv.getInt("battery_pct")
        )
        assertEquals(adv.getString("bytes"), beacon.toFullPayload().encodeHex())

        val parsed = SmartKeyAdvertisement.parse(beacon.toFullPayload())!!
        assertEquals(beacon.flags, parsed.flags)
        assertEquals(beacon.batteryPercent, parsed.batteryPercent)
        assertArrayEquals(beacon.pseudonym, parsed.pseudonym)
    }

    @Test
    fun `the manufacturer data excludes the company id`() {
        val adv = vectors.getJSONObject("advertisement")
        val full = adv.getString("bytes").decodeHex()
        val beacon = SmartKeyAdvertisement.parse(full)!!
        // Android prepends the company id itself, so we must emit 10 bytes.
        assertEquals(SmartKeyProtocol.ADV_DATA_SIZE, beacon.toManufacturerData().size)
        assertArrayEquals(full.copyOfRange(2, full.size), beacon.toManufacturerData())
    }

    @Test
    fun `foreign advertisements are ignored`() {
        val bytes = vectors.getJSONObject("advertisement").getString("bytes").decodeHex()
        bytes[2] = 0x00 // wrong magic
        assertNull(SmartKeyAdvertisement.parse(bytes))
        assertNull(SmartKeyAdvertisement.parse(ByteArray(4)))
    }
}
