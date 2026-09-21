/**
 * @file smartkey_proximity.c
 * @brief Median filtered RSSI proximity gate with hysteresis.
 */

#include "smartkey_proximity.h"

#include <string.h>

/** Sort a small array with insertion sort (n <= 9, so this is optimal here). */
static void sort_samples(int8_t *values, uint8_t count)
{
    for (uint8_t i = 1; i < count; i++) {
        int8_t key = values[i];
        int j = (int)i - 1;
        while (j >= 0 && values[j] > key) {
            values[j + 1] = values[j];
            j--;
        }
        values[j + 1] = key;
    }
}

void skpx_init(skpx_filter_t *filter, const skpx_config_t *cfg)
{
    if (filter == NULL) {
        return;
    }
    memset(filter, 0, sizeof(*filter));

    skpx_config_t safe = {
        .near_dbm = -60,
        .far_dbm = -72,
        .window = 5,
        .min_samples = 3,
    };
    if (cfg != NULL) {
        safe = *cfg;
    }

    /* Clamp rather than reject: a bad config must never brick the door. */
    if (safe.window == 0) {
        safe.window = 1;
    } else if (safe.window > SKPX_MAX_WINDOW) {
        safe.window = SKPX_MAX_WINDOW;
    }
    if (safe.min_samples == 0) {
        safe.min_samples = 1;
    } else if (safe.min_samples > safe.window) {
        safe.min_samples = safe.window;
    }
    /* far must be at or below near, otherwise the hysteresis inverts. */
    if (safe.far_dbm > safe.near_dbm) {
        safe.far_dbm = safe.near_dbm;
    }

    filter->cfg = safe;
}

void skpx_reset(skpx_filter_t *filter)
{
    if (filter == NULL) {
        return;
    }
    filter->count = 0;
    filter->next = 0;
    filter->near = false;
    memset(filter->samples, 0, sizeof(filter->samples));
}

int8_t skpx_median(const skpx_filter_t *filter)
{
    if (filter == NULL || filter->count == 0) {
        return SKPX_RSSI_UNKNOWN;
    }
    int8_t sorted[SKPX_MAX_WINDOW];
    memcpy(sorted, filter->samples, filter->count);
    sort_samples(sorted, filter->count);

    /* For an even count take the lower of the two middles: that biases the
     * estimate pessimistically, which is the safe direction for a door. */
    return sorted[(filter->count - 1) / 2];
}

bool skpx_ready(const skpx_filter_t *filter)
{
    return filter != NULL && filter->count >= filter->cfg.min_samples;
}

bool skpx_is_near(const skpx_filter_t *filter)
{
    return filter != NULL && filter->near;
}

bool skpx_add_sample(skpx_filter_t *filter, int8_t rssi)
{
    if (filter == NULL) {
        return false;
    }

    filter->samples[filter->next] = rssi;
    filter->next = (uint8_t)((filter->next + 1) % filter->cfg.window);
    if (filter->count < filter->cfg.window) {
        filter->count++;
    }

    /* Stay pessimistic until there is enough evidence to judge. */
    if (!skpx_ready(filter)) {
        filter->near = false;
        return false;
    }

    const int8_t median = skpx_median(filter);
    if (filter->near) {
        /* Only give up proximity once the median drops below the far edge. */
        if (median < filter->cfg.far_dbm) {
            filter->near = false;
        }
    } else {
        if (median >= filter->cfg.near_dbm) {
            filter->near = true;
        }
    }
    return filter->near;
}
