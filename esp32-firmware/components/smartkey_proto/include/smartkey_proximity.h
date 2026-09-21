/**
 * @file smartkey_proximity.h
 * @brief Filtered RSSI proximity gate: "is the phone actually next to the board?"
 *
 * Raw BLE RSSI is extremely noisy — multipath, body shadowing and antenna
 * orientation routinely swing it by 15-20 dB between consecutive packets. A
 * single sample is therefore useless as a distance gate: it produces both false
 * grants (a spike from across the room) and flicker.
 *
 * This module keeps a short sliding window and uses its **median**, which
 * rejects isolated outliers in both directions, combined with separate
 * enter/exit thresholds so the decision cannot chatter.
 *
 * Deliberately free of ESP-IDF dependencies so it can be unit tested on the
 * host together with the rest of smartkey_proto.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum supported window; keeps the struct allocation free. */
#define SKPX_MAX_WINDOW 9

/** Sentinel for "no usable estimate yet". */
#define SKPX_RSSI_UNKNOWN 0

/** Tuning, supplied by the application from Kconfig. */
typedef struct {
    int8_t near_dbm;     /**< median at or above this ⇒ near (LED may turn on) */
    int8_t far_dbm;      /**< median below this ⇒ no longer near (LED off) */
    uint8_t window;      /**< number of samples in the sliding window, 1..SKPX_MAX_WINDOW */
    uint8_t min_samples; /**< samples required before any decision is taken */
} skpx_config_t;

/** Proximity filter state for one peer. */
typedef struct {
    skpx_config_t cfg;
    int8_t samples[SKPX_MAX_WINDOW];
    uint8_t count; /**< how many slots are populated (saturates at window) */
    uint8_t next;  /**< write cursor */
    bool near;     /**< current hysteresis output */
} skpx_filter_t;

/**
 * @brief Initialise (or re-tune) a filter and clear its history.
 *
 * Invalid configuration is clamped to something sane rather than rejected, so a
 * bad Kconfig value can never leave the door unit unable to grant access.
 */
void skpx_init(skpx_filter_t *filter, const skpx_config_t *cfg);

/** @brief Drop all samples and the near state, keeping the tuning. */
void skpx_reset(skpx_filter_t *filter);

/**
 * @brief Feed one RSSI sample and re-evaluate proximity.
 * @return the current near state (also available via skpx_is_near()).
 */
bool skpx_add_sample(skpx_filter_t *filter, int8_t rssi);

/** @brief Current filtered proximity decision. */
bool skpx_is_near(const skpx_filter_t *filter);

/** @brief True once at least min_samples have been collected. */
bool skpx_ready(const skpx_filter_t *filter);

/**
 * @brief Median of the current window.
 * @return SKPX_RSSI_UNKNOWN when no samples have been collected yet.
 */
int8_t skpx_median(const skpx_filter_t *filter);

/** @brief Number of samples currently held. */
static inline uint8_t skpx_count(const skpx_filter_t *filter)
{
    return filter->count;
}

#ifdef __cplusplus
}
#endif
