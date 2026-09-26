package com.example.smart_key.protocol

import com.example.smart_key.pairing.PairingSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A PAIR_RESPONSE truncated by a too-small ATT MTU is the most likely real
 * pairing failure in the field: the frame is 100 bytes, but the default MTU of
 * 23 leaves only 20 usable.
 *
 * These tests pin down that the resulting message actually says something
 * useful. The original wording ("Malformed response from the door unit")
 * pointed at a protocol bug and hid the real cause.
 */
class TruncatedFrameTest {

    private fun session() = PairingSession(
        userId = ByteArray(SmartKeyProtocol.ID_SIZE) { 1 },
        pairingCode = "12345678"
    )

    @Test
    fun `a frame cut off by the default MTU reports the truncation`() {
        // What a 23 byte MTU actually delivers: 20 bytes of a 100 byte frame.
        val full = ByteArray(SmartKeyProtocol.HEADER_SIZE + SmartKeyProtocol.PAIR_RESPONSE_SIZE)
        full[0] = SmartKeyProtocol.VERSION
        full[1] = SmartKeyProtocol.FrameType.PAIR_RESPONSE
        full[2] = SmartKeyProtocol.PAIR_RESPONSE_SIZE.toByte()
        full[3] = 0

        val truncated = full.copyOfRange(0, 20)

        val step = session().onFrame(truncated)
        assertTrue("expected a failure", step is PairingSession.Step.Failure)

        val message = (step as PairingSession.Step.Failure).message
        // The message must name the real problem, not just "malformed".
        assertTrue(
            "message should mention truncation, was: $message",
            message.contains("truncated", ignoreCase = true)
        )
        // And it should carry the numbers needed to diagnose it.
        assertTrue("message should say how many bytes arrived: $message",
            message.contains("20"))
    }

    @Test
    fun `a frame shorter than the header is rejected`() {
        val step = session().onFrame(byteArrayOf(0x01, 0x11))
        assertTrue(step is PairingSession.Step.Failure)
        val message = (step as PairingSession.Step.Failure).message
        assertTrue("was: $message", message.contains("truncated", ignoreCase = true))
    }

    @Test
    fun `a wrong protocol version is reported as such`() {
        val frame = ByteArray(SmartKeyProtocol.HEADER_SIZE + 4)
        frame[0] = 0x99.toByte() // not SKP1
        frame[1] = SmartKeyProtocol.FrameType.PAIR_RESULT

        val step = session().onFrame(frame)
        assertTrue(step is PairingSession.Step.Failure)
        val message = (step as PairingSession.Step.Failure).message
        assertTrue(
            "should mention the version, was: $message",
            message.contains("version", ignoreCase = true)
        )
    }

    @Test
    fun `an unknown frame type is ignored rather than failing`() {
        // Forward compatibility: a future frame type must not abort pairing.
        val frame = ByteArray(SmartKeyProtocol.HEADER_SIZE)
        frame[0] = SmartKeyProtocol.VERSION
        frame[1] = 0x42 // unassigned

        assertEquals(PairingSession.Step.Waiting, session().onFrame(frame))
    }

    @Test
    fun `the minimum MTU covers the largest pairing frame`() {
        // Mirrors PairingClient.MIN_REQUIRED_MTU. If PAIR_RESPONSE ever grows,
        // this is the check that should fail first.
        val largestFrame = SmartKeyProtocol.HEADER_SIZE + SmartKeyProtocol.PAIR_RESPONSE_SIZE
        val required = largestFrame + 3 // ATT notification header

        assertEquals(103, required)
        assertTrue(
            "the default 23 byte MTU must be recognised as insufficient",
            23 < required
        )
        // The firmware asks for 247, which must be comfortably above it.
        assertTrue("247 should satisfy the requirement", 247 >= required)
    }
}
