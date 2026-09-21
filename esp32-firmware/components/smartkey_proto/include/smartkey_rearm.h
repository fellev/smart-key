/**
 * @file smartkey_rearm.h
 * @brief "One approach, one opening": when may a phone re-engage the door?
 *
 * After the door has actually been opened the unit releases the session and
 * goes idle. Releasing alone is not enough, though: the phone that just
 * unlocked is still standing right next to the reader, still advertising, so
 * the scanner would reconnect within a few hundred milliseconds and light the
 * LED straight back up. A fixed time cooldown fails for the same reason — it
 * simply relights a few seconds later while the user is still there.
 *
 * The re-arm condition therefore has to be **departure**, not elapsed time:
 * the phone must be seen to leave (or stop being seen at all) before the door
 * will engage it again. That gives the intuitive behaviour — open the door,
 * walk through, the LED stays off — while a genuine second approach still
 * works normally.
 *
 * Two escape hatches stop the hold becoming permanent:
 *
 *  - @c absent_ms: the phone is not seen at all for a while (it went through
 *    the door and out of range), which is the common case;
 *  - @c max_hold_ms: an absolute cap, so a phone left lying on a table beside
 *    the reader cannot disable the door forever.
 *
 * Deliberately free of ESP-IDF dependencies so it can be unit tested on the
 * host alongside the rest of smartkey_proto.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Tuning, supplied by the application from Kconfig. */
typedef struct {
    /** Seen weaker than this ⇒ the phone has moved away ⇒ re-arm. */
    int8_t depart_dbm;
    /** Not seen at all for this long ⇒ re-arm. 0 disables this rule. */
    uint32_t absent_ms;
    /** Absolute cap on the hold, 0 = no cap. Safety valve only. */
    uint32_t max_hold_ms;
} skra_config_t;

/** Re-arm state for the peer that most recently opened the door. */
typedef struct {
    skra_config_t cfg;
    bool holding;         /**< true while that peer is being refused */
    int64_t held_since_ms;
    int64_t last_seen_ms; /**< last advertisement observed from the peer */
} skra_t;

/** @brief Initialise (or re-tune) and clear any hold. */
void skra_init(skra_t *ra, const skra_config_t *cfg);

/**
 * @brief Begin refusing this peer — call right after a successful unlock.
 */
void skra_hold(skra_t *ra, int64_t now_ms);

/**
 * @brief Feed an advertisement seen from the held peer.
 *
 * A sighting weaker than @c depart_dbm releases the hold immediately: the
 * user has stepped away from the door.
 */
void skra_observe(skra_t *ra, int64_t now_ms, int8_t rssi);

/**
 * @brief Should this peer still be refused?
 *
 * Also applies the absence and cap rules, so calling it drives the state
 * machine forward even when no advertisement has arrived.
 */
bool skra_blocked(skra_t *ra, int64_t now_ms);

/** @brief Drop any hold (e.g. on factory reset or revocation). */
void skra_clear(skra_t *ra);

#ifdef __cplusplus
}
#endif
