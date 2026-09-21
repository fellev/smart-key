package com.example.smart_key.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The gate decides whether the phone's radio is transmitting at all, so the
 * headline requirement — "no continuous transmit" — is enforced here.
 */
class PresenceGateTest {

    private val linger = 90_000L

    private fun listenFirst() =
        PresenceGate(PresenceMode.LISTEN_FIRST, lingerMs = linger)

    private fun always() =
        PresenceGate(PresenceMode.ALWAYS_ADVERTISE, lingerMs = linger)

    // ------------------------------------------------- the core requirement

    @Test
    fun `listen-first transmits nothing until a door is heard`() {
        val gate = listenFirst()
        gate.start()

        assertFalse("must be silent at startup", gate.shouldTransmit(0))
        assertEquals(PresenceGate.Reason.SILENT, gate.reason(0))

        // Still silent an entire day later, with no door ever heard.
        val oneDay = 24 * 60 * 60 * 1000L
        assertFalse("must still be silent a day later", gate.shouldTransmit(oneDay))
    }

    @Test
    fun `hearing a door breaks radio silence`() {
        val gate = listenFirst()
        gate.start()
        gate.onDoorSeen(1_000)

        assertTrue(gate.shouldTransmit(1_000))
        assertEquals(PresenceGate.Reason.DOOR_NEARBY, gate.reason(1_000))
    }

    @Test
    fun `transmission stops again once the linger window expires`() {
        val gate = listenFirst()
        gate.start()
        gate.onDoorSeen(1_000)

        assertTrue("just inside", gate.shouldTransmit(1_000 + linger - 1))
        assertFalse("exactly at expiry", gate.shouldTransmit(1_000 + linger))
        assertFalse("well past", gate.shouldTransmit(1_000 + linger * 10))
    }

    @Test
    fun `a fresh sighting extends the window`() {
        val gate = listenFirst()
        gate.start()
        gate.onDoorSeen(1_000)
        gate.onDoorSeen(60_000) // still walking around near the door

        assertTrue(gate.shouldTransmit(60_000 + linger - 1))
        assertFalse(gate.shouldTransmit(60_000 + linger))
    }

    // ------------------------------------------------------ session pinning

    @Test
    fun `stays transmitting while connected no matter how old the sighting`() {
        val gate = listenFirst()
        gate.start()
        gate.onDoorSeen(1_000)
        gate.onConnectedChanged(true, 2_000)

        // Far beyond the linger window, but a session is live.
        val muchLater = 2_000 + linger * 100
        assertTrue("must not go silent mid-session", gate.shouldTransmit(muchLater))
        assertEquals(PresenceGate.Reason.CONNECTED, gate.reason(muchLater))
        assertNull("no silence timer while connected", gate.msUntilSilent(muchLater))
    }

    @Test
    fun `disconnecting restarts the linger countdown rather than cutting off`() {
        val gate = listenFirst()
        gate.start()
        gate.onDoorSeen(1_000)
        gate.onConnectedChanged(true, 2_000)
        gate.onConnectedChanged(false, 500_000)

        // Keeps advertising briefly while the user walks away...
        assertTrue(gate.shouldTransmit(500_000))
        assertTrue(gate.shouldTransmit(500_000 + linger - 1))
        // ...then goes quiet on its own.
        assertFalse(gate.shouldTransmit(500_000 + linger))
    }

    // -------------------------------------------------------- continuous mode

    @Test
    fun `always-advertise transmits from the start without hearing anything`() {
        val gate = always()
        gate.start()

        assertTrue(gate.shouldTransmit(0))
        assertEquals(PresenceGate.Reason.ALWAYS, gate.reason(0))
        assertTrue(gate.shouldTransmit(24 * 60 * 60 * 1000L))
        assertNull("never schedules silence", gate.msUntilSilent(0))
    }

    // ------------------------------------------------------------- lifecycle

    @Test
    fun `never transmits before start or after stop`() {
        val gate = listenFirst()

        assertFalse("before start", gate.shouldTransmit(0))

        gate.start()
        gate.onDoorSeen(1_000)
        assertTrue(gate.shouldTransmit(1_000))

        gate.stop()
        assertFalse("after stop", gate.shouldTransmit(1_000))
        assertEquals(PresenceGate.Reason.SILENT, gate.reason(1_000))
    }

    @Test
    fun `an always-advertise gate is also silent before start`() {
        val gate = always()
        assertFalse(gate.shouldTransmit(0))
    }

    @Test
    fun `stop clears a live session so a restart does not inherit it`() {
        val gate = listenFirst()
        gate.start()
        gate.onConnectedChanged(true, 1_000)
        gate.stop()
        gate.start()

        assertFalse("must not resume transmitting", gate.shouldTransmit(1_000))
    }

    // --------------------------------------------------------- silence timer

    @Test
    fun `reports when it will next go silent`() {
        val gate = listenFirst()
        gate.start()
        gate.onDoorSeen(1_000)

        assertEquals(linger, gate.msUntilSilent(1_000))
        assertEquals(linger - 5_000, gate.msUntilSilent(6_000))
        assertNull("already silent", gate.msUntilSilent(1_000 + linger))
    }

    @Test
    fun `reports no timer when nothing has ever been heard`() {
        val gate = listenFirst()
        gate.start()
        assertNull(gate.msUntilSilent(0))
    }
}
