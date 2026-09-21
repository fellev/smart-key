/**
 * @file smartkey_rearm.c
 * @brief Departure based re-arm after an unlock. See smartkey_rearm.h.
 */

#include "smartkey_rearm.h"

#include <string.h>

/** Clamp nonsense configuration rather than refusing to work. */
static void sanitise(skra_config_t *cfg)
{
    if (cfg->depart_dbm > 0) {
        cfg->depart_dbm = -70;
    }
    /* An unreasonably long cap would leave the door dead after one unlock, so
     * bound it; 0 legitimately means "no cap". */
    if (cfg->max_hold_ms != 0 && cfg->max_hold_ms > 600000u) {
        cfg->max_hold_ms = 600000u;
    }
}

void skra_init(skra_t *ra, const skra_config_t *cfg)
{
    if (ra == NULL) {
        return;
    }
    memset(ra, 0, sizeof(*ra));
    if (cfg != NULL) {
        ra->cfg = *cfg;
    }
    sanitise(&ra->cfg);
}

void skra_hold(skra_t *ra, int64_t now_ms)
{
    if (ra == NULL) {
        return;
    }
    ra->holding = true;
    ra->held_since_ms = now_ms;
    /* The peer is by definition present at this instant. */
    ra->last_seen_ms = now_ms;
}

void skra_observe(skra_t *ra, int64_t now_ms, int8_t rssi)
{
    if (ra == NULL || !ra->holding) {
        return;
    }
    ra->last_seen_ms = now_ms;

    /* Seen, but far away: the user has walked off, so re-arm at once. This is
     * the normal path — it is what makes a second approach work immediately
     * rather than after some arbitrary timeout. */
    if (rssi < ra->cfg.depart_dbm) {
        ra->holding = false;
    }
}

bool skra_blocked(skra_t *ra, int64_t now_ms)
{
    if (ra == NULL || !ra->holding) {
        return false;
    }

    /* Not seen for a while: the phone went through the door and out of range.
     * Note this is driven by absence of advertisements, so it works even
     * though we are no longer connected to it. */
    if (ra->cfg.absent_ms != 0 &&
        (now_ms - ra->last_seen_ms) >= (int64_t)ra->cfg.absent_ms) {
        ra->holding = false;
        return false;
    }

    /* Safety valve: never refuse a credential indefinitely. A phone parked
     * next to the reader must not be able to disable the door. */
    if (ra->cfg.max_hold_ms != 0 &&
        (now_ms - ra->held_since_ms) >= (int64_t)ra->cfg.max_hold_ms) {
        ra->holding = false;
        return false;
    }

    return true;
}

void skra_clear(skra_t *ra)
{
    if (ra == NULL) {
        return;
    }
    ra->holding = false;
    ra->held_since_ms = 0;
    ra->last_seen_ms = 0;
}
