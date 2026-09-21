package com.example.smart_key.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The door beacon is the recovery path for a presence service killed by the
 * OS. Two properties carry the whole design and are asserted here:
 *
 *  1. the payload is **static**, which is what lets Android offload the scan
 *     filter into the Bluetooth controller;
 *  2. it can never be confused with a *phone* beacon, even though the two
 *     share a manufacturer id.
 */
class DoorBeaconTest {

    private val lockId = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(),
        0xEF.toByte(), 0x01, 0x02)

    @Test
    fun `round trips through the full payload`() {
        val beacon = DoorBeacon(SmartKeyProtocol.DOOR_FLAG_ENROLLED, lockId)
        val parsed = DoorBeacon.parse(beacon.toFullPayload())

        assertNotNull(parsed)
        assertEquals(SmartKeyProtocol.DOOR_FLAG_ENROLLED, parsed!!.flags)
        assertArrayEquals(lockId, parsed.lockId)
        assertTrue(parsed.isEnrolled)
        assertFalse(parsed.isPairing)
    }

    @Test
    fun `round trips through the form Android returns from a scan`() {
        val beacon = DoorBeacon(SmartKeyProtocol.DOOR_FLAG_ENROLLED, lockId)
        // getManufacturerSpecificData() strips the company id.
        val parsed = DoorBeacon.parseWithoutCompanyId(beacon.toManufacturerData())

        assertNotNull(parsed)
        assertArrayEquals(lockId, parsed!!.lockId)
        assertTrue(parsed.isEnrolled)
    }

    @Test
    fun `payload is byte-identical every time so the filter can be offloaded`() {
        val a = DoorBeacon(SmartKeyProtocol.DOOR_FLAG_ENROLLED, lockId).toFullPayload()
        val b = DoorBeacon(SmartKeyProtocol.DOOR_FLAG_ENROLLED, lockId).toFullPayload()
        assertArrayEquals(a, b)
    }

    @Test
    fun `matches the firmware layout`() {
        val payload = DoorBeacon(0, lockId).toFullPayload()

        assertEquals(12, payload.size)
        assertEquals(
            (SmartKeyProtocol.MANUFACTURER_ID and 0xFF).toByte(), payload[0]
        )
        assertEquals(SmartKeyProtocol.DOOR_MAGIC, payload[2])
        assertEquals(SmartKeyProtocol.VERSION, payload[3])
        assertEquals(0.toByte(), payload[11]) // reserved
    }

    @Test
    fun `a phone beacon is never parsed as a door beacon`() {
        val phone = SmartKeyAdvertisement(
            flags = 0,
            pseudonym = ByteArray(SmartKeyProtocol.PSEUDONYM_SIZE) { 0xAB.toByte() },
            batteryPercent = 50
        )
        assertNull(DoorBeacon.parse(phone.toFullPayload()))
    }

    @Test
    fun `a door beacon is never parsed as a phone beacon`() {
        val door = DoorBeacon(SmartKeyProtocol.DOOR_FLAG_ENROLLED, lockId)
        assertNull(SmartKeyAdvertisement.parse(door.toFullPayload()))
    }

    @Test
    fun `rejects truncated, foreign and future payloads`() {
        val valid = DoorBeacon(0, lockId).toFullPayload()

        assertNull("truncated", DoorBeacon.parse(valid.copyOfRange(0, 6)))

        val foreignCompany = valid.copyOf()
        foreignCompany[0] = 0x11
        foreignCompany[1] = 0x22
        assertNull("foreign company id", DoorBeacon.parse(foreignCompany))

        val futureVersion = valid.copyOf()
        futureVersion[3] = 0x02
        assertNull("future version", DoorBeacon.parse(futureVersion))
    }

    @Test
    fun `the scan filter mask matches only the magic and version`() {
        assertEquals(SmartKeyProtocol.DOOR_DATA_SIZE, DoorBeacon.FILTER_DATA.size)
        assertEquals(SmartKeyProtocol.DOOR_DATA_SIZE, DoorBeacon.FILTER_MASK.size)

        assertEquals(SmartKeyProtocol.DOOR_MAGIC, DoorBeacon.FILTER_DATA[0])
        assertEquals(SmartKeyProtocol.VERSION, DoorBeacon.FILTER_DATA[1])

        assertEquals(0xFF.toByte(), DoorBeacon.FILTER_MASK[0])
        assertEquals(0xFF.toByte(), DoorBeacon.FILTER_MASK[1])

        // The lock id must stay masked out, so a single registered filter
        // covers every door the user has paired.
        for (i in 2 until DoorBeacon.FILTER_MASK.size) {
            assertEquals("mask byte $i must be zero", 0.toByte(), DoorBeacon.FILTER_MASK[i])
        }
    }

    @Test
    fun `a real beacon satisfies the offloaded filter`() {
        val payload = DoorBeacon(SmartKeyProtocol.DOOR_FLAG_ENROLLED, lockId)
            .toManufacturerData()

        // Reproduces what the Bluetooth controller does with data + mask.
        for (i in DoorBeacon.FILTER_MASK.indices) {
            val masked = payload[i].toInt() and DoorBeacon.FILTER_MASK[i].toInt()
            val expected = DoorBeacon.FILTER_DATA[i].toInt() and
                DoorBeacon.FILTER_MASK[i].toInt()
            assertEquals("filter byte $i", expected, masked)
        }
    }

    @Test
    fun `an unenrolled door is distinguishable from an enrolled one`() {
        val fresh = DoorBeacon.parse(DoorBeacon(0, lockId).toFullPayload())
        assertNotNull(fresh)
        assertFalse(fresh!!.isEnrolled)
    }

    @Test
    fun `rejects a wrong sized lock id`() {
        try {
            DoorBeacon(0, ByteArray(4))
            org.junit.Assert.fail("expected IllegalArgumentException")
        } catch (expected: IllegalArgumentException) {
            // success
        }
    }

    @Test
    fun `shortId is stable lowercase hex`() {
        assertEquals("deadbeef0102", DoorBeacon(0, lockId).shortId)
    }
}
