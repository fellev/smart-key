package com.example.smart_key.ble

/**
 * Decides whether the phone should be transmitting right now.
 *
 * ## The problem this solves
 *
 * In the original design the phone advertises continuously for as long as
 * presence is enabled. That is cheap (~1 %/day) but it means the phone is
 * broadcasting all day and all night, including while it sits on a desk with
 * no door within a hundred metres.
 *
 * [PresenceMode.LISTEN_FIRST] removes that entirely: the phone transmits
 * **nothing** until it has actually heard a door beacon, then advertises only
 * for as long as a door is plausibly nearby.
 *
 * ## Why listening can be free when transmitting is not
 *
 * The door beacon carries a *static* identifier, so the scan filter runs
 * inside the Bluetooth controller (offloaded filtering). The application
 * processor is not involved until the controller reports a match, so
 * "listening" here does not mean an app holding the radio in RX — that would
 * cost far more than advertising ever did.
 *
 * ## The trade
 *
 * Detection is no longer instant. The wake-up path (controller match →
 * broadcast dispatch → start advertising → door connects → handshake) takes
 * seconds, not milliseconds. It works only because the door beacon is
 * receivable far beyond the LED range, so the phone wakes while the user is
 * still walking up. See protocol-spec.md §8.5.
 *
 * Deliberately free of Android dependencies so the state machine can be unit
 * tested on the JVM.
 */
class PresenceGate(
    val mode: PresenceMode,
    /** How long to keep transmitting after the last door sighting. */
    private val lingerMs: Long = DEFAULT_LINGER_MS
) {

    /** Why the phone is (or is not) currently transmitting. */
    enum class Reason {
        /** Continuous mode: always on while presence is enabled. */
        ALWAYS,
        /** Listen-first: a door was heard recently. */
        DOOR_NEARBY,
        /** Listen-first: a session is live, so transmission must continue. */
        CONNECTED,
        /** Listen-first: nothing heard, radio silent. */
        SILENT,
    }

    private var lastDoorSeenAt: Long? = null
    private var connected = false
    private var started = false

    /** True once [start] has been called and [stop] has not. */
    val isRunning: Boolean get() = started

    fun start() {
        started = true
    }

    fun stop() {
        started = false
        lastDoorSeenAt = null
        connected = false
    }

    /** A door beacon was received. Only meaningful in listen-first mode. */
    fun onDoorSeen(nowMs: Long) {
        lastDoorSeenAt = nowMs
    }

    /**
     * A door has authenticated, or the session ended.
     *
     * While connected the phone must keep advertising: dropping the
     * advertisement mid-session would let the door lose track of the peer it
     * is already talking to.
     */
    fun onConnectedChanged(value: Boolean, nowMs: Long) {
        connected = value
        // Refresh on *both* edges. On connect it marks the door as present; on
        // disconnect it restarts the linger countdown from the moment contact
        // was lost. Without the disconnect case the window would still be
        // measured from the start of the session, so any session longer than
        // the linger period would cut transmission off the instant it ended —
        // precisely when the user is turning away from the door.
        lastDoorSeenAt = nowMs
    }

    /** Why the phone should be transmitting at [nowMs], if at all. */
    fun reason(nowMs: Long): Reason {
        if (!started) return Reason.SILENT
        if (mode == PresenceMode.ALWAYS_ADVERTISE) return Reason.ALWAYS
        if (connected) return Reason.CONNECTED
        val seen = lastDoorSeenAt ?: return Reason.SILENT
        return if (nowMs - seen < lingerMs) Reason.DOOR_NEARBY else Reason.SILENT
    }

    /** Whether the advertiser should be running at [nowMs]. */
    fun shouldTransmit(nowMs: Long): Boolean = reason(nowMs) != Reason.SILENT

    /**
     * Milliseconds until the linger window expires, or null when there is
     * nothing to expire (continuous mode, connected, or already silent).
     *
     * The service uses this to schedule the moment it goes quiet again rather
     * than polling.
     */
    fun msUntilSilent(nowMs: Long): Long? {
        if (!started || mode == PresenceMode.ALWAYS_ADVERTISE || connected) return null
        val seen = lastDoorSeenAt ?: return null
        val remaining = lingerMs - (nowMs - seen)
        return if (remaining > 0) remaining else null
    }

    companion object {
        /**
         * 90 s. Long enough to cover fumbling for the door, short enough that
         * a passing sighting does not leave the phone transmitting for ages.
         */
        const val DEFAULT_LINGER_MS = 90_000L
    }
}

/** How aggressively the phone announces itself. */
enum class PresenceMode {
    /**
     * Advertise continuously while presence is enabled (the 1.0 behaviour).
     * Sub-second LED, ~1 %/day battery, phone is transmitting at all times.
     */
    ALWAYS_ADVERTISE,

    /**
     * Transmit nothing until a door beacon is heard.
     *
     * Requires the door unit to have `CONFIG_SMARTKEY_DOOR_BEACON_ENABLE`
     * turned on — with no door beacon there is nothing to wake the phone and
     * it will never advertise.
     */
    LISTEN_FIRST,
}
